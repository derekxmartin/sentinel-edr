/*
 * sentinel-hook/hooks_common.c
 * Shared helpers for hook detour functions.
 */

#include <windows.h>
#include <intrin.h>
#include "hooks_common.h"

/*
 * Guard flag: hooks fire during DLL load (NtMapViewOfSection, NtAllocateVirtualMemory
 * are called by the loader). We must not call complex APIs like GetModuleHandleExW or
 * OutputDebugStringA while the loader lock is held during init. Set to TRUE once
 * DllMain(DLL_PROCESS_ATTACH) completes.
 */
static volatile BOOL g_HooksReady = FALSE;

void SentinelHooksSetReady(void) { g_HooksReady = TRUE; }
BOOL SentinelHooksAreReady(void) { return g_HooksReady; }

/*
 * Per-thread reentrancy guard using manual TLS (TlsAlloc/TlsGetValue/TlsSetValue).
 *
 * __declspec(thread) does NOT work in dynamically loaded DLLs (LoadLibrary / KAPC
 * injection) — the implicit TLS slots aren't allocated for pre-existing threads,
 * causing an access violation (0xC0000005).
 *
 * Manual TLS via TlsAlloc works for all threads regardless of when the DLL loaded.
 * TlsGetValue/TlsSetValue are safe to call from ntdll hooks because they are
 * thin wrappers around the TEB (no allocations, no locks).
 */
static DWORD g_TlsIndex = TLS_OUT_OF_INDEXES;

void
SentinelTlsInit(void)
{
    g_TlsIndex = TlsAlloc();
}

void
SentinelTlsCleanup(void)
{
    if (g_TlsIndex != TLS_OUT_OF_INDEXES) {
        TlsFree(g_TlsIndex);
        g_TlsIndex = TLS_OUT_OF_INDEXES;
    }
}

BOOL
SentinelEnterHook(void)
{
    if (!g_HooksReady || g_TlsIndex == TLS_OUT_OF_INDEXES) {
        return FALSE;
    }

    /* Check if we're already inside a hook on this thread */
    if (TlsGetValue(g_TlsIndex) != NULL) {
        return FALSE;   /* Reentrant call — skip */
    }

    TlsSetValue(g_TlsIndex, (LPVOID)1);
    return TRUE;
}

void
SentinelLeaveHook(void)
{
    if (g_TlsIndex != TLS_OUT_OF_INDEXES) {
        TlsSetValue(g_TlsIndex, NULL);
    }
}

/* ── Hook function name table ─────────────────────────────────────────────── */

static const char *g_HookFunctionNames[] = {
    "NtAllocateVirtualMemory",      /* 0 */
    "NtProtectVirtualMemory",       /* 1 */
    "NtWriteVirtualMemory",         /* 2 */
    "NtReadVirtualMemory",          /* 3 */
    "NtCreateThreadEx",             /* 4 */
    "NtMapViewOfSection",           /* 5 */
    "NtUnmapViewOfSection",         /* 6 */
    "NtQueueApcThread",             /* 7 */
    "NtOpenProcess",                /* 8 */
    "NtSuspendThread",              /* 9 */
    "NtResumeThread",               /* 10 */
    "NtCreateSection",              /* 11 */
};

const char *
SentinelHookFunctionName(SENTINEL_HOOK_FUNCTION func)
{
    if (func >= 0 && func < SentinelHookMax) {
        return g_HookFunctionNames[func];
    }
    return "Unknown";
}

/* ── SentinelGetTargetPid ─────────────────────────────────────────────────── */

ULONG
SentinelGetTargetPid(HANDLE ProcessHandle)
{
    /* NtCurrentProcess() == (HANDLE)-1 */
    if (ProcessHandle == (HANDLE)-1 || ProcessHandle == NULL) {
        return 0;
    }

    DWORD pid = GetProcessId(ProcessHandle);
    if (pid == GetCurrentProcessId()) {
        return 0;  /* Self */
    }
    return pid;
}

/* ── SentinelGetCallingModule ─────────────────────────────────────────────── */

void
SentinelGetCallingModule(
    ULONG_PTR   ReturnAddress,
    WCHAR      *buf,
    DWORD       bufLen)
{
    HMODULE hMod = NULL;

    if (bufLen == 0) {
        return;
    }
    buf[0] = L'\0';

    if (ReturnAddress == 0) {
        return;
    }

    if (GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            (LPCWSTR)ReturnAddress,
            &hMod) && hMod) {
        GetModuleFileNameW(hMod, buf, bufLen);
    }
}

/* ── Diagnostic file log ──────────────────────────────────────────────────── */

/*
 * Write to a log file — reliable diagnostic independent of DebugView.
 * Uses FILE_APPEND_DATA so multiple processes can write concurrently.
 */
static void
SentinelLogToFile(const char *msg)
{
    HANDLE hFile = CreateFileA(
        "C:\\SentinelPOC\\hook_diag.log",
        FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD written;
        WriteFile(hFile, msg, (DWORD)lstrlenA(msg), &written, NULL);
        CloseHandle(hFile);
    }
}

/* ── SentinelEmitHookEvent ────────────────────────────────────────────────── */

/*
 * P3-T2: Log via OutputDebugStringA + file.
 * P3-T4 will replace this with named pipe send to the agent.
 */
void
SentinelEmitHookEvent(SENTINEL_HOOK_EVENT *evt)
{
    char msg[512];

    wsprintfA(msg,
        "SentinelHook: %s targetPid=%lu addr=0x%p size=0x%Ix "
        "prot=0x%lX alloc=0x%lX status=0x%08lX\n",
        SentinelHookFunctionName(evt->Function),
        evt->TargetProcessId,
        (void *)evt->BaseAddress,
        evt->RegionSize,
        evt->Protection,
        evt->AllocationType,
        evt->ReturnStatus);

    OutputDebugStringA(msg);
    SentinelLogToFile(msg);
}
