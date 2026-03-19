/*
 * akesoedr-hook/pipe_client.c
 * Named pipe client — ring buffer + background worker thread.
 *
 * Hook detours push events into a lock-free ring buffer (loader-lock safe).
 * A background worker thread drains the buffer, wraps events in
 * AKESOEDR_EVENT envelopes, serializes them, and sends over the named pipe
 * to the agent (\\.\pipe\AkesoEDRTelemetry).
 *
 * The worker thread is created lazily on the first push after DllMain
 * completes — CreateThread is NOT safe inside DllMain.
 *
 * LOADER-LOCK SAFETY (push path):
 *   InterlockedIncrement — interlocked intrinsic
 *   GetSystemTimePreciseAsFileTime — thin ntdll wrapper
 *   SetEvent — kernel call, no user-mode locks
 *   memcpy — CRT, no locks
 */

#include <windows.h>
#include <stdio.h>
#include "pipe_client.h"
#include "hooks_common.h"
#include "ipc.h"
#include "ipc_serialize.h"
#include "constants.h"

/* ── Ring buffer ──────────────────────────────────────────────────────────── */

typedef struct _AKESOEDR_RING_ENTRY {
    AKESOEDR_HOOK_EVENT     Event;
    LARGE_INTEGER           Timestamp;
    volatile LONG           Ready;      /* 0=empty, 1=written and readable */
} AKESOEDR_RING_ENTRY;

static AKESOEDR_RING_ENTRY  g_RingBuffer[AKESOEDR_HOOK_RING_BUFFER_SIZE];
static volatile LONG        g_RingHead = 0;     /* Next write slot (producer) */
static volatile LONG        g_RingTail = 0;     /* Next read slot (consumer) */

/* ── Worker thread state ──────────────────────────────────────────────────── */

static HANDLE   g_hWorkerThread     = NULL;
static HANDLE   g_hDrainEvent       = NULL;     /* Signaled when new events available */
static HANDLE   g_hShutdownEvent    = NULL;     /* Signaled for graceful shutdown */
static volatile LONG g_WorkerCreated = 0;       /* 0=not yet, 1=created */

/* ── Process context cache (populated once by worker thread) ──────────────── */

static AKESOEDR_PROCESS_CTX g_ProcessCtx;
static BOOL                 g_ProcessCtxReady = FALSE;

/* ── Forward declarations ─────────────────────────────────────────────────── */

static DWORD WINAPI PipeWorkerThread(LPVOID lpParam);
static void  CacheProcessContext(void);
static HANDLE ConnectToPipe(void);
static BOOL  PerformHandshake(HANDLE hPipe, UINT32 *pSequenceNum);
static void  DrainRingBuffer(HANDLE hPipe, UINT32 *pSequenceNum);

/* ── AkesoEDRPipeClientInit ───────────────────────────────────────────────── */

void
AkesoEDRPipeClientInit(void)
{
    /* Zero the ring buffer */
    ZeroMemory(g_RingBuffer, sizeof(g_RingBuffer));
    g_RingHead = 0;
    g_RingTail = 0;

    /* Create synchronization events (auto-reset for drain, manual-reset for shutdown) */
    g_hDrainEvent    = CreateEventW(NULL, FALSE, FALSE, NULL);
    g_hShutdownEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
}

/* ── AkesoEDRPipeClientShutdown ───────────────────────────────────────────── */

void
AkesoEDRPipeClientShutdown(void)
{
    /* Signal the worker to exit */
    if (g_hShutdownEvent != NULL) {
        SetEvent(g_hShutdownEvent);
    }

    /* Wait for worker thread to finish (2 second timeout) */
    if (g_hWorkerThread != NULL) {
        WaitForSingleObject(g_hWorkerThread, 2000);
        CloseHandle(g_hWorkerThread);
        g_hWorkerThread = NULL;
    }

    /* Clean up events */
    if (g_hDrainEvent != NULL) {
        CloseHandle(g_hDrainEvent);
        g_hDrainEvent = NULL;
    }
    if (g_hShutdownEvent != NULL) {
        CloseHandle(g_hShutdownEvent);
        g_hShutdownEvent = NULL;
    }
}

/* ── AkesoEDRPipeClientPush ───────────────────────────────────────────────── */

/*
 * Push a hook event into the ring buffer. Entirely loader-lock safe.
 *
 * Lazily creates the worker thread on the first call after hooks are ready.
 * Uses InterlockedCompareExchange to ensure single creation.
 */
void
AkesoEDRPipeClientPush(AKESOEDR_HOOK_EVENT *evt)
{
    LONG slot;
    AKESOEDR_RING_ENTRY *entry;
    FILETIME ft;

    if (evt == NULL) {
        return;
    }

    /* Lazily create worker thread (once, after DllMain completes) */
    if (AkesoEDRHooksAreReady() &&
        InterlockedCompareExchange(&g_WorkerCreated, 1, 0) == 0) {
        g_hWorkerThread = CreateThread(
            NULL, 0, PipeWorkerThread, NULL, 0, NULL);
    }

    /* Claim a ring buffer slot */
    slot = InterlockedIncrement(&g_RingHead) - 1;
    slot = slot % AKESOEDR_HOOK_RING_BUFFER_SIZE;

    entry = &g_RingBuffer[slot];

    /* If slot is still marked ready (consumer hasn't read it), we're
       overwriting an old event. Acceptable for POC — silently drop. */

    /* Copy event data */
    entry->Event = *evt;

    /* Capture timestamp (loader-lock safe) */
    GetSystemTimePreciseAsFileTime(&ft);
    entry->Timestamp.LowPart  = ft.dwLowDateTime;
    entry->Timestamp.HighPart = (LONG)ft.dwHighDateTime;

    /* Mark slot as readable */
    InterlockedExchange(&entry->Ready, 1);

    /* Wake the worker thread */
    if (g_hDrainEvent != NULL) {
        SetEvent(g_hDrainEvent);
    }
}

/* ── Process context cache ────────────────────────────────────────────────── */

/*
 * Populate g_ProcessCtx once. Called from the worker thread (NOT under
 * loader lock, so all these APIs are safe).
 */
static void
CacheProcessContext(void)
{
    HANDLE hToken = NULL;
    DWORD sessionId = 0;
    DWORD sessionSize = sizeof(sessionId);

    ZeroMemory(&g_ProcessCtx, sizeof(g_ProcessCtx));

    g_ProcessCtx.ProcessId = GetCurrentProcessId();
    g_ProcessCtx.ThreadId  = GetCurrentThreadId();

    /* Session ID */
    ProcessIdToSessionId(g_ProcessCtx.ProcessId, &sessionId);
    g_ProcessCtx.SessionId = sessionId;

    /* Image path */
    GetModuleFileNameW(NULL, g_ProcessCtx.ImagePath, AKESOEDR_MAX_PATH);

    /* Command line — GetCommandLineW returns a pointer to static buffer */
    {
        LPCWSTR cmdLine = GetCommandLineW();
        if (cmdLine != NULL) {
            _snwprintf_s(g_ProcessCtx.CommandLine,
                         AKESOEDR_MAX_CMDLINE, _TRUNCATE,
                         L"%s", cmdLine);
        }
    }

    /* Integrity level and elevation from process token */
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        /* Elevation */
        TOKEN_ELEVATION elevation;
        DWORD cbSize = sizeof(elevation);
        if (GetTokenInformation(hToken, TokenElevation,
                                &elevation, sizeof(elevation), &cbSize)) {
            g_ProcessCtx.IsElevated = (BOOLEAN)elevation.TokenIsElevated;
        }

        /* Integrity level */
        {
            BYTE buf[256];
            TOKEN_MANDATORY_LABEL *pLabel = (TOKEN_MANDATORY_LABEL *)buf;
            DWORD needed = 0;
            if (GetTokenInformation(hToken, TokenIntegrityLevel,
                                    pLabel, sizeof(buf), &needed)) {
                DWORD *pRid = GetSidSubAuthority(
                    pLabel->Label.Sid,
                    (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pLabel->Label.Sid) - 1));
                g_ProcessCtx.IntegrityLevel = *pRid;
            }
        }

        /* User SID */
        {
            BYTE buf[256];
            TOKEN_USER *pUser = (TOKEN_USER *)buf;
            DWORD needed = 0;
            if (GetTokenInformation(hToken, TokenUser,
                                    pUser, sizeof(buf), &needed)) {
                WCHAR name[128], domain[128];
                DWORD nameLen = 128, domainLen = 128;
                SID_NAME_USE sidUse;
                /* Convert SID to string for display */
                LPWSTR sidStr = NULL;
                if (ConvertSidToStringSidW(pUser->User.Sid, &sidStr)) {
                    _snwprintf_s(g_ProcessCtx.UserSid,
                                 AKESOEDR_MAX_SID_STRING, _TRUNCATE,
                                 L"%s", sidStr);
                    LocalFree(sidStr);
                }
            }
        }

        CloseHandle(hToken);
    }

    g_ProcessCtxReady = TRUE;
}

/* ── Pipe connection ──────────────────────────────────────────────────────── */

/*
 * Attempt to connect to the agent's telemetry pipe.
 * Returns pipe handle on success, INVALID_HANDLE_VALUE on failure.
 */
static HANDLE
ConnectToPipe(void)
{
    return CreateFileW(
        AKESOEDR_PIPE_TELEMETRY,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);
}

/* ── Handshake ────────────────────────────────────────────────────────────── */

/*
 * Send handshake and validate reply. Returns TRUE on success.
 */
static BOOL
PerformHandshake(HANDLE hPipe, UINT32 *pSequenceNum)
{
    AKESOEDR_IPC_HANDSHAKE      handshake;
    AKESOEDR_IPC_HANDSHAKE_REPLY reply;
    BYTE frameBuf[256];
    UINT32 bytesWritten = 0;
    DWORD dwWritten = 0, dwRead = 0;
    AKESOEDR_SERIALIZE_STATUS serStatus;

    /* Build handshake message */
    AkesoEDRIpcBuildHandshake(
        &handshake,
        AkesoEDRClientHookDll,
        GetCurrentProcessId(),
        (*pSequenceNum)++);

    /* Frame it */
    serStatus = AkesoEDRIpcWriteFrame(
        frameBuf, sizeof(frameBuf),
        &handshake, sizeof(handshake),
        &bytesWritten);
    if (serStatus != AkesoEDRSerializeOk) {
        return FALSE;
    }

    /* Send */
    if (!WriteFile(hPipe, frameBuf, bytesWritten, &dwWritten, NULL)
        || dwWritten != bytesWritten) {
        return FALSE;
    }

    /* Read reply frame: [4-byte length][AKESOEDR_IPC_HANDSHAKE_REPLY] */
    {
        BYTE replyBuf[256];
        UINT32 frameLen = 0;

        if (!ReadFile(hPipe, replyBuf, sizeof(replyBuf), &dwRead, NULL)
            || dwRead < sizeof(UINT32) + sizeof(AKESOEDR_IPC_HANDSHAKE_REPLY)) {
            return FALSE;
        }

        frameLen = *(UINT32 *)replyBuf;
        if (frameLen < sizeof(AKESOEDR_IPC_HANDSHAKE_REPLY)) {
            return FALSE;
        }

        memcpy(&reply, replyBuf + sizeof(UINT32), sizeof(reply));

        if (AkesoEDRIpcHeaderValidate(&reply.Header) != AkesoEDRSerializeOk) {
            return FALSE;
        }

        if (reply.Header.Type != AkesoEDRMsgHandshakeReply) {
            return FALSE;
        }

        if (reply.Status != (UINT32)AkesoEDRHandshakeOk) {
            return FALSE;
        }
    }

    return TRUE;
}

/* ── Ring buffer drain ────────────────────────────────────────────────────── */

/*
 * Drain all ready entries from the ring buffer, wrap in AKESOEDR_EVENT,
 * serialize, and send over the pipe.
 */
static void
DrainRingBuffer(HANDLE hPipe, UINT32 *pSequenceNum)
{
    LONG tail;
    int  drained = 0;

    for (drained = 0; drained < AKESOEDR_HOOK_RING_BUFFER_SIZE; drained++) {
        AKESOEDR_RING_ENTRY *entry;
        AKESOEDR_EVENT       envelope;
        BYTE                 sendBuf[sizeof(UINT32) + sizeof(AKESOEDR_IPC_EVENT_MSG) + sizeof(AKESOEDR_EVENT)];
        UINT32               bytesWritten = 0;
        DWORD                dwWritten = 0;

        tail = g_RingTail % AKESOEDR_HOOK_RING_BUFFER_SIZE;
        entry = &g_RingBuffer[tail];

        /* Check if this slot has data */
        if (!InterlockedCompareExchange(&entry->Ready, 1, 1)) {
            break;  /* No more ready entries */
        }

        /* Build AKESOEDR_EVENT envelope */
        AkesoEDREventInit(&envelope, AkesoEDRSourceHookDll,
                          AkesoEDRSeverityInformational);

        /* Use the timestamp captured at push time instead of now */
        envelope.Timestamp = entry->Timestamp;

        /* Copy process context */
        if (g_ProcessCtxReady) {
            envelope.ProcessCtx = g_ProcessCtx;
        }

        /* Copy hook event into payload */
        envelope.Payload.Hook = entry->Event;

        /* Mark slot as consumed */
        InterlockedExchange(&entry->Ready, 0);
        InterlockedIncrement(&g_RingTail);

        /* Serialize and send */
        if (AkesoEDRIpcSerializeEvent(sendBuf, sizeof(sendBuf),
                                       &envelope, (*pSequenceNum)++,
                                       &bytesWritten) == AkesoEDRSerializeOk) {
            if (!WriteFile(hPipe, sendBuf, bytesWritten, &dwWritten, NULL)
                || dwWritten != bytesWritten) {
                /* Pipe error — caller will reconnect */
                return;
            }
        }
    }
}

/* ── Worker thread ────────────────────────────────────────────────────────── */

/*
 * Background worker thread. Connects to the agent pipe, performs handshake,
 * then drains the ring buffer in a loop. Reconnects on pipe failure.
 */
static DWORD WINAPI
PipeWorkerThread(LPVOID lpParam)
{
    HANDLE  hPipe = INVALID_HANDLE_VALUE;
    UINT32  sequenceNum = 0;
    HANDLE  waitHandles[2];
    DWORD   backoffMs = 500;

    (void)lpParam;

    /* Cache process context once (safe — we're not under loader lock) */
    CacheProcessContext();

    waitHandles[0] = g_hShutdownEvent;
    waitHandles[1] = g_hDrainEvent;

    for (;;) {
        /* ── Connect phase ──────────────────────────────────────────── */
        while (hPipe == INVALID_HANDLE_VALUE) {
            /* Check for shutdown before each connect attempt */
            if (WaitForSingleObject(g_hShutdownEvent, 0) == WAIT_OBJECT_0) {
                goto shutdown;
            }

            hPipe = ConnectToPipe();
            if (hPipe == INVALID_HANDLE_VALUE) {
                /* Backoff: 500ms → 1s → 2s → 5s (cap) */
                WaitForSingleObject(g_hShutdownEvent, backoffMs);
                if (WaitForSingleObject(g_hShutdownEvent, 0) == WAIT_OBJECT_0) {
                    goto shutdown;
                }
                if (backoffMs < 5000) {
                    backoffMs = min(backoffMs * 2, 5000);
                }
                continue;
            }

            /* Connected — perform handshake */
            if (!PerformHandshake(hPipe, &sequenceNum)) {
                CloseHandle(hPipe);
                hPipe = INVALID_HANDLE_VALUE;
                continue;
            }

            /* Reset backoff on successful connect */
            backoffMs = 500;
        }

        /* ── Drain loop ─────────────────────────────────────────────── */
        {
            DWORD waitResult = WaitForMultipleObjects(
                2, waitHandles, FALSE, 100);

            if (waitResult == WAIT_OBJECT_0) {
                /* Shutdown signaled — drain remaining and exit */
                DrainRingBuffer(hPipe, &sequenceNum);
                goto shutdown;
            }

            /* WAIT_OBJECT_0 + 1 (drain event) or WAIT_TIMEOUT — drain */
            DrainRingBuffer(hPipe, &sequenceNum);

            /* Check if pipe is still valid by peeking */
            {
                DWORD avail = 0;
                if (!PeekNamedPipe(hPipe, NULL, 0, NULL, &avail, NULL)) {
                    DWORD err = GetLastError();
                    if (err == ERROR_BROKEN_PIPE || err == ERROR_PIPE_NOT_CONNECTED) {
                        CloseHandle(hPipe);
                        hPipe = INVALID_HANDLE_VALUE;
                        /* Will reconnect on next iteration */
                    }
                }
            }
        }
    }

shutdown:
    /* Send disconnect message if pipe is connected */
    if (hPipe != INVALID_HANDLE_VALUE) {
        AKESOEDR_IPC_DISCONNECT disc;
        BYTE discBuf[64];
        UINT32 bytesWritten = 0;
        DWORD dwWritten = 0;

        ZeroMemory(&disc, sizeof(disc));
        AkesoEDRIpcHeaderInit(
            &disc.Header,
            AkesoEDRMsgDisconnect,
            sizeof(AKESOEDR_IPC_DISCONNECT) - sizeof(AKESOEDR_IPC_HEADER),
            sequenceNum++);
        disc.Reason = 0;  /* Normal disconnect */

        if (AkesoEDRIpcWriteFrame(discBuf, sizeof(discBuf),
                                   &disc, sizeof(disc),
                                   &bytesWritten) == AkesoEDRSerializeOk) {
            WriteFile(hPipe, discBuf, bytesWritten, &dwWritten, NULL);
        }

        CloseHandle(hPipe);
    }

    return 0;
}
