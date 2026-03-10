/*
 * sentinel-hook/hooks_thread.c
 * Detour functions for thread/APC-related ntdll hooks (Ch. 2).
 *
 * Hooks:
 *   NtCreateThreadEx   — remote thread creation (classic injection vector)
 *   NtQueueApcThread   — APC injection (early-bird, atom bombing, etc.)
 */

#include <windows.h>
#include <intrin.h>
#include "hook_engine.h"
#include "hooks_common.h"

/* ── Ntdll typedefs ───────────────────────────────────────────────────────── */

typedef NTSTATUS (NTAPI *NtCreateThreadEx_t)(
    PHANDLE         ThreadHandle,
    ACCESS_MASK     DesiredAccess,
    PVOID           ObjectAttributes,
    HANDLE          ProcessHandle,
    PVOID           StartRoutine,
    PVOID           Argument,
    ULONG           CreateFlags,
    SIZE_T          ZeroBits,
    SIZE_T          StackSize,
    SIZE_T          MaximumStackSize,
    PVOID           AttributeList
);

typedef NTSTATUS (NTAPI *NtQueueApcThread_t)(
    HANDLE          ThreadHandle,
    PVOID           ApcRoutine,
    PVOID           ApcArgument1,
    PVOID           ApcArgument2,
    PVOID           ApcArgument3
);

/* ── Trampoline pointers ──────────────────────────────────────────────────── */

static NtCreateThreadEx_t   Original_NtCreateThreadEx   = NULL;
static NtQueueApcThread_t   Original_NtQueueApcThread   = NULL;

/* ── Detour: NtCreateThreadEx ─────────────────────────────────────────────── */

static NTSTATUS NTAPI
Hooked_NtCreateThreadEx(
    PHANDLE         ThreadHandle,
    ACCESS_MASK     DesiredAccess,
    PVOID           ObjectAttributes,
    HANDLE          ProcessHandle,
    PVOID           StartRoutine,
    PVOID           Argument,
    ULONG           CreateFlags,
    SIZE_T          ZeroBits,
    SIZE_T          StackSize,
    SIZE_T          MaximumStackSize,
    PVOID           AttributeList)
{
    NTSTATUS status = Original_NtCreateThreadEx(
        ThreadHandle, DesiredAccess, ObjectAttributes,
        ProcessHandle, StartRoutine, Argument,
        CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);

    SENTINEL_HOOK_EVENT evt = {0};
    evt.Function        = SentinelHookNtCreateThreadEx;
    evt.TargetProcessId = SentinelGetTargetPid(ProcessHandle);
    evt.BaseAddress     = (ULONG_PTR)StartRoutine;
    evt.ReturnAddress   = (ULONG_PTR)_ReturnAddress();
    evt.ReturnStatus    = status;

    SentinelGetCallingModule(evt.ReturnAddress,
                             evt.CallingModule, SENTINEL_MAX_MODULE_NAME);
    SentinelEmitHookEvent(&evt);

    return status;
}

/* ── Detour: NtQueueApcThread ─────────────────────────────────────────────── */

static NTSTATUS NTAPI
Hooked_NtQueueApcThread(
    HANDLE          ThreadHandle,
    PVOID           ApcRoutine,
    PVOID           ApcArgument1,
    PVOID           ApcArgument2,
    PVOID           ApcArgument3)
{
    NTSTATUS status = Original_NtQueueApcThread(
        ThreadHandle, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3);

    SENTINEL_HOOK_EVENT evt = {0};
    evt.Function        = SentinelHookNtQueueApcThread;
    evt.BaseAddress     = (ULONG_PTR)ApcRoutine;
    evt.ReturnAddress   = (ULONG_PTR)_ReturnAddress();
    evt.ReturnStatus    = status;

    SentinelGetCallingModule(evt.ReturnAddress,
                             evt.CallingModule, SENTINEL_MAX_MODULE_NAME);
    SentinelEmitHookEvent(&evt);

    return status;
}

/* ── Install all thread hooks ─────────────────────────────────────────────── */

void
InstallThreadHooks(void)
{
    InstallHook("ntdll.dll", "NtCreateThreadEx",
                (void *)Hooked_NtCreateThreadEx,
                (void **)&Original_NtCreateThreadEx);

    InstallHook("ntdll.dll", "NtQueueApcThread",
                (void *)Hooked_NtQueueApcThread,
                (void **)&Original_NtQueueApcThread);
}
