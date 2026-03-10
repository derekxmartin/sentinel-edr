/*
 * sentinel-hook/hooks_common.c
 * Shared helpers for hook detour functions.
 */

#include <windows.h>
#include <intrin.h>
#include "hooks_common.h"

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

    /*
     * GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS resolves an address
     * to the module that contains it. The UNCHANGED_REFCOUNT flag
     * avoids incrementing the module refcount.
     */
    if (GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            (LPCWSTR)ReturnAddress,
            &hMod) && hMod) {
        GetModuleFileNameW(hMod, buf, bufLen);
    }
}

/* ── SentinelEmitHookEvent ────────────────────────────────────────────────── */

/*
 * P3-T2: Log via OutputDebugStringA.
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
}
