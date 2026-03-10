/*
 * tests/test_consumer.c
 * P1-T4: Test consumer — connects to the driver's filter communication port
 * and prints received telemetry events to the console.
 *
 * Usage:
 *   test_consumer.exe [--count N]
 *
 * The consumer connects to \SentinelPort via FilterConnectCommunicationPort,
 * then loops calling FilterGetMessage to receive SENTINEL_FILTER_MSG structs
 * sent by the driver via FltSendMessage.
 *
 * Press Ctrl+C to stop.
 *
 * Build requirements:
 *   - Link: fltLib.lib, ole32.lib
 *   - Include: common/ (telemetry.h, ipc.h, constants.h)
 */

#include <windows.h>
#include <fltUser.h>
#include <stdio.h>
#include <stdlib.h>

#include "telemetry.h"
#include "ipc.h"

/* ── Constants ──────────────────────────────────────────────────────────── */

#define DEFAULT_MAX_EVENTS  0   /* 0 = unlimited */

/* ── Receive buffer ─────────────────────────────────────────────────────── */

/*
 * FilterGetMessage prepends FILTER_MESSAGE_HEADER to the message body.
 * The driver sends SENTINEL_FILTER_MSG as the body.
 */
typedef struct _CONSUMER_MESSAGE {
    FILTER_MESSAGE_HEADER   Header;
    SENTINEL_FILTER_MSG     Body;
} CONSUMER_MESSAGE;

/* ── Globals ────────────────────────────────────────────────────────────── */

static volatile BOOL g_Running = TRUE;
static HANDLE        g_Port    = INVALID_HANDLE_VALUE;

/* Statistics */
static ULONG g_TotalEvents      = 0;
static ULONG g_ProcessCreates   = 0;
static ULONG g_ProcessExits     = 0;
static ULONG g_ThreadCreates    = 0;
static ULONG g_ThreadExits      = 0;
static ULONG g_RemoteThreads    = 0;
static ULONG g_Errors           = 0;

/* ── Helpers ────────────────────────────────────────────────────────────── */

static const char*
SourceToString(SENTINEL_EVENT_SOURCE src)
{
    switch (src) {
    case SentinelSourceDriverProcess:   return "PROCESS";
    case SentinelSourceDriverThread:    return "THREAD";
    case SentinelSourceDriverObject:    return "OBJECT";
    case SentinelSourceDriverImageLoad: return "IMAGELOAD";
    case SentinelSourceDriverRegistry:  return "REGISTRY";
    case SentinelSourceDriverMinifilter:return "FILE";
    case SentinelSourceDriverNetwork:   return "NETWORK";
    case SentinelSourceHookDll:         return "HOOK";
    case SentinelSourceEtw:             return "ETW";
    case SentinelSourceAmsi:            return "AMSI";
    case SentinelSourceScanner:         return "SCANNER";
    case SentinelSourceRuleEngine:      return "RULE";
    case SentinelSourceSelfProtect:     return "TAMPER";
    default:                            return "UNKNOWN";
    }
}

static const char*
SeverityToString(SENTINEL_SEVERITY sev)
{
    switch (sev) {
    case SentinelSeverityInformational: return "INFO";
    case SentinelSeverityLow:           return "LOW";
    case SentinelSeverityMedium:        return "MEDIUM";
    case SentinelSeverityHigh:          return "HIGH";
    case SentinelSeverityCritical:      return "CRITICAL";
    default:                            return "???";
    }
}

/*
 * Convert LARGE_INTEGER (100-ns intervals since 1601-01-01) to
 * a human-readable local time string.
 */
static void
FormatTimestamp(LARGE_INTEGER timestamp, char *buf, size_t bufSize)
{
    FILETIME   ft;
    FILETIME   localFt;
    SYSTEMTIME st;

    ft.dwLowDateTime  = timestamp.LowPart;
    ft.dwHighDateTime = (DWORD)timestamp.HighPart;

    if (FileTimeToLocalFileTime(&ft, &localFt) &&
        FileTimeToSystemTime(&localFt, &st))
    {
        _snprintf_s(buf, bufSize, _TRUNCATE,
            "%04u-%02u-%02u %02u:%02u:%02u.%03u",
            st.wYear, st.wMonth, st.wDay,
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    } else {
        _snprintf_s(buf, bufSize, _TRUNCATE, "(invalid timestamp)");
    }
}

/* ── Event printers ─────────────────────────────────────────────────────── */

static void
PrintProcessEvent(const SENTINEL_EVENT *evt)
{
    const SENTINEL_PROCESS_EVENT *p = &evt->Payload.Process;

    if (p->IsCreate) {
        g_ProcessCreates++;
        printf("  [+] Process CREATE  PID=%-6lu  ParentPID=%-6lu\n",
            p->NewProcessId, p->ParentProcessId);
        if (p->ImagePath[0]) {
            printf("      Image:   %ls\n", p->ImagePath);
        }
        if (p->CommandLine[0]) {
            printf("      CmdLine: %ls\n", p->CommandLine);
        }
        if (p->UserSid[0]) {
            printf("      User:    %ls  IL=%lu  Elevated=%s\n",
                p->UserSid, p->IntegrityLevel,
                p->IsElevated ? "YES" : "no");
        }
    } else {
        g_ProcessExits++;
        printf("  [-] Process EXIT   PID=%-6lu  ExitCode=0x%08lX\n",
            p->NewProcessId, p->ExitStatus);
    }
}

static void
PrintThreadEvent(const SENTINEL_EVENT *evt)
{
    const SENTINEL_THREAD_EVENT *t = &evt->Payload.Thread;

    if (t->IsCreate) {
        g_ThreadCreates++;

        if (t->IsRemote) {
            g_RemoteThreads++;
            printf("  [!] Thread CREATE  TID=%-6lu  PID=%-6lu  Creator=%-6lu  "
                   "*** REMOTE THREAD ***\n",
                t->ThreadId, t->OwningProcessId, t->CreatingProcessId);
        } else {
            printf("  [+] Thread CREATE  TID=%-6lu  PID=%-6lu  Creator=%-6lu\n",
                t->ThreadId, t->OwningProcessId, t->CreatingProcessId);
        }

        if (t->StartAddress) {
            printf("      StartAddr: 0x%p\n", (void *)t->StartAddress);
        }
    } else {
        g_ThreadExits++;
        printf("  [-] Thread EXIT   TID=%-6lu  PID=%-6lu\n",
            t->ThreadId, t->OwningProcessId);
    }
}

static void
PrintGenericEvent(const SENTINEL_EVENT *evt)
{
    printf("  [?] Unhandled source=%d (%s)\n",
        evt->Source, SourceToString(evt->Source));
}

/* ── Process one event ──────────────────────────────────────────────────── */

static void
ProcessEvent(const SENTINEL_EVENT *evt)
{
    char timeBuf[64];

    g_TotalEvents++;

    FormatTimestamp(evt->Timestamp, timeBuf, sizeof(timeBuf));

    /* Event header line */
    printf("\n── Event #%lu ──────────────────────────────────────────\n",
        g_TotalEvents);
    printf("  Time:     %s\n", timeBuf);
    printf("  Source:   %-10s  Severity: %s\n",
        SourceToString(evt->Source), SeverityToString(evt->Severity));

    /* Process context */
    if (evt->ProcessCtx.ImagePath[0]) {
        printf("  Context:  PID=%-6lu  PPID=%-6lu  Sess=%lu\n",
            evt->ProcessCtx.ProcessId,
            evt->ProcessCtx.ParentProcessId,
            evt->ProcessCtx.SessionId);
        printf("  Image:    %ls\n", evt->ProcessCtx.ImagePath);
    }

    /* Dispatch to type-specific printer */
    switch (evt->Source) {
    case SentinelSourceDriverProcess:
        PrintProcessEvent(evt);
        break;
    case SentinelSourceDriverThread:
        PrintThreadEvent(evt);
        break;
    default:
        PrintGenericEvent(evt);
        break;
    }
}

/* ── Ctrl+C handler ─────────────────────────────────────────────────────── */

static BOOL WINAPI
ConsoleCtrlHandler(DWORD ctrlType)
{
    (void)ctrlType;
    printf("\n[*] Shutting down...\n");
    g_Running = FALSE;

    /*
     * Cancel pending FilterGetMessage by closing the port handle.
     * This causes the blocked call to return with an error.
     */
    if (g_Port != INVALID_HANDLE_VALUE) {
        CloseHandle(g_Port);
        g_Port = INVALID_HANDLE_VALUE;
    }

    return TRUE;
}

/* ── Print statistics ───────────────────────────────────────────────────── */

static void
PrintStatistics(void)
{
    printf("\n════════════════════════════════════════════════════════\n");
    printf("  SentinelPOC Test Consumer — Session Summary\n");
    printf("════════════════════════════════════════════════════════\n");
    printf("  Total events received:  %lu\n", g_TotalEvents);
    printf("  Process creates:        %lu\n", g_ProcessCreates);
    printf("  Process exits:          %lu\n", g_ProcessExits);
    printf("  Thread creates:         %lu\n", g_ThreadCreates);
    printf("  Thread exits:           %lu\n", g_ThreadExits);
    printf("  Remote threads:         %lu\n", g_RemoteThreads);
    printf("  Errors:                 %lu\n", g_Errors);
    printf("════════════════════════════════════════════════════════\n");
}

/* ── Main ───────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
    HRESULT     hr;
    ULONG       maxEvents = DEFAULT_MAX_EVENTS;
    CONSUMER_MESSAGE *msgBuf = NULL;

    printf("╔══════════════════════════════════════════════════════╗\n");
    printf("║  SentinelPOC Test Consumer v1.0.0   (P1-T4)        ║\n");
    printf("║  Press Ctrl+C to stop                              ║\n");
    printf("╚══════════════════════════════════════════════════════╝\n\n");

    /* Parse args */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--count") == 0 && i + 1 < argc) {
            maxEvents = (ULONG)atoi(argv[++i]);
            printf("[*] Will stop after %lu events\n", maxEvents);
        }
    }

    /* Install Ctrl+C handler */
    SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);

    /* Allocate message buffer (too large for stack — ~22KB+ struct) */
    msgBuf = (CONSUMER_MESSAGE *)malloc(sizeof(CONSUMER_MESSAGE));
    if (!msgBuf) {
        fprintf(stderr, "[!] Failed to allocate message buffer (%zu bytes)\n",
            sizeof(CONSUMER_MESSAGE));
        return 1;
    }

    /*
     * Force unbuffered stdout so output appears immediately,
     * even when running through Invoke-Command / non-interactive pipes.
     */
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    printf("[*] sizeof(SENTINEL_EVENT)       = %zu bytes\n", sizeof(SENTINEL_EVENT));
    printf("[*] sizeof(SENTINEL_FILTER_MSG)  = %zu bytes\n", sizeof(SENTINEL_FILTER_MSG));
    printf("[*] sizeof(CONSUMER_MESSAGE)     = %zu bytes\n", sizeof(CONSUMER_MESSAGE));
    printf("\n");

    /* ── Connect to filter port ───────────────────────────────────────── */

    printf("[*] Connecting to %ls ...\n", SENTINEL_FILTER_PORT_NAME);

    hr = FilterConnectCommunicationPort(
        SENTINEL_FILTER_PORT_NAME,
        0,                          /* Options */
        NULL,                       /* Context (sent to driver's connect callback) */
        0,                          /* ContextSize */
        NULL,                       /* SecurityAttributes */
        &g_Port
    );

    if (FAILED(hr)) {
        fprintf(stderr, "[!] FilterConnectCommunicationPort failed: 0x%08lX\n", hr);

        if (hr == 0x800704D6) {
            fprintf(stderr, "    -> The driver is not loaded. Run: sc start sentinel-drv\n");
        } else if (hr == 0x80070005) {
            fprintf(stderr, "    -> Access denied. Run as Administrator.\n");
        } else if (hr == 0x8007001F) {
            fprintf(stderr, "    -> General failure. Is the driver loaded and running?\n");
        }

        free(msgBuf);
        return 1;
    }

    printf("[+] Connected to filter port successfully!\n");
    printf("[*] Waiting for events...\n\n");

    /* ── Event receive loop ───────────────────────────────────────────── */

    while (g_Running) {
        SENTINEL_IPC_HEADER *hdr;

        ZeroMemory(msgBuf, sizeof(CONSUMER_MESSAGE));

        hr = FilterGetMessage(
            g_Port,
            &msgBuf->Header,
            sizeof(CONSUMER_MESSAGE),
            NULL                        /* Overlapped — synchronous */
        );

        if (FAILED(hr)) {
            if (!g_Running) {
                /* Expected — port was closed by Ctrl+C handler */
                break;
            }

            if (hr == HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED)) {
                /* Port closed / driver unloading */
                printf("[*] Port closed by driver\n");
                break;
            }

            fprintf(stderr, "[!] FilterGetMessage failed: 0x%08lX\n", hr);
            g_Errors++;

            if (g_Errors > 10) {
                fprintf(stderr, "[!] Too many errors, stopping\n");
                break;
            }
            continue;
        }

        /* Validate IPC header */
        hdr = &msgBuf->Body.Header;

        if (hdr->Magic != SENTINEL_IPC_MAGIC) {
            fprintf(stderr, "[!] Bad magic: 0x%08X (expected 0x%08X)\n",
                hdr->Magic, SENTINEL_IPC_MAGIC);
            g_Errors++;
            continue;
        }

        if (hdr->Version != SENTINEL_IPC_VERSION) {
            fprintf(stderr, "[!] Bad version: %u (expected %u)\n",
                hdr->Version, SENTINEL_IPC_VERSION);
            g_Errors++;
            continue;
        }

        if (hdr->Type != (UINT16)SentinelMsgEvent) {
            fprintf(stderr, "[!] Unexpected message type: %u\n", hdr->Type);
            g_Errors++;
            continue;
        }

        /* Process the event */
        ProcessEvent(&msgBuf->Body.Event);

        /* Check count limit */
        if (maxEvents > 0 && g_TotalEvents >= maxEvents) {
            printf("\n[*] Reached event limit (%lu)\n", maxEvents);
            break;
        }
    }

    /* ── Cleanup ──────────────────────────────────────────────────────── */

    if (g_Port != INVALID_HANDLE_VALUE) {
        CloseHandle(g_Port);
        g_Port = INVALID_HANDLE_VALUE;
    }

    free(msgBuf);

    PrintStatistics();

    return 0;
}
