/*
 * sentinel-hook/hooks_section.c
 * Detour functions for section-related ntdll hooks (Ch. 2).
 *
 * Hooks:
 *   NtMapViewOfSection — section mapping (process hollowing, DLL injection)
 */

#include <windows.h>
#include <intrin.h>
#include "hook_engine.h"
#include "hooks_common.h"

/* ── Ntdll typedefs ───────────────────────────────────────────────────────── */

typedef NTSTATUS (NTAPI *NtMapViewOfSection_t)(
    HANDLE          SectionHandle,
    HANDLE          ProcessHandle,
    PVOID          *BaseAddress,
    ULONG_PTR       ZeroBits,
    SIZE_T          CommitSize,
    PLARGE_INTEGER  SectionOffset,
    PSIZE_T         ViewSize,
    ULONG           InheritDisposition,
    ULONG           AllocationType,
    ULONG           Win32Protect
);

/* ── Trampoline pointers ──────────────────────────────────────────────────── */

static NtMapViewOfSection_t     Original_NtMapViewOfSection     = NULL;

/* ── Detour: NtMapViewOfSection ───────────────────────────────────────────── */

static NTSTATUS NTAPI
Hooked_NtMapViewOfSection(
    HANDLE          SectionHandle,
    HANDLE          ProcessHandle,
    PVOID          *BaseAddress,
    ULONG_PTR       ZeroBits,
    SIZE_T          CommitSize,
    PLARGE_INTEGER  SectionOffset,
    PSIZE_T         ViewSize,
    ULONG           InheritDisposition,
    ULONG           AllocationType,
    ULONG           Win32Protect)
{
    /* Call original first — BaseAddress and ViewSize are OUT */
    NTSTATUS status;
    __try {
        status = Original_NtMapViewOfSection(
            SectionHandle, ProcessHandle, BaseAddress,
            ZeroBits, CommitSize, SectionOffset,
            ViewSize, InheritDisposition, AllocationType, Win32Protect);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    if (SentinelEnterHook()) {
        SENTINEL_HOOK_EVENT evt = {0};
        evt.Function        = SentinelHookNtMapViewOfSection;
        evt.TargetProcessId = SentinelGetTargetPid(ProcessHandle);
        evt.BaseAddress     = (ULONG_PTR)(BaseAddress ? *BaseAddress : 0);
        evt.RegionSize      = ViewSize ? *ViewSize : 0;
        evt.AllocationType  = AllocationType;
        evt.Protection      = Win32Protect;
        evt.ReturnAddress   = (ULONG_PTR)_ReturnAddress();
        evt.ReturnStatus    = status;

        SentinelGetCallingModule(evt.ReturnAddress,
                                 evt.CallingModule, SENTINEL_MAX_MODULE_NAME);
        SentinelEmitHookEvent(&evt);
        SentinelLeaveHook();
    }

    return status;
}

/* ── Install all section hooks ────────────────────────────────────────────── */

void
InstallSectionHooks(void)
{
    InstallHook("ntdll.dll", "NtMapViewOfSection",
                (void *)Hooked_NtMapViewOfSection,
                (void **)&Original_NtMapViewOfSection);
}
