/*
 * sentinel-hook/hooks_memory.c
 * Detour functions for memory-related ntdll hooks (Ch. 2).
 *
 * Hooks:
 *   NtAllocateVirtualMemory  — memory allocation (RWX detection)
 *   NtProtectVirtualMemory   — permission changes (RW→RX shellcode pattern)
 *   NtWriteVirtualMemory     — cross-process memory writes
 */

#include <windows.h>
#include <intrin.h>
#include "hook_engine.h"
#include "hooks_common.h"

/* ── Ntdll typedefs ───────────────────────────────────────────────────────── */

typedef NTSTATUS (NTAPI *NtAllocateVirtualMemory_t)(
    HANDLE      ProcessHandle,
    PVOID      *BaseAddress,
    ULONG_PTR   ZeroBits,
    PSIZE_T     RegionSize,
    ULONG       AllocationType,
    ULONG       Protect
);

typedef NTSTATUS (NTAPI *NtProtectVirtualMemory_t)(
    HANDLE      ProcessHandle,
    PVOID      *BaseAddress,
    PSIZE_T     RegionSize,
    ULONG       NewProtect,
    PULONG      OldProtect
);

typedef NTSTATUS (NTAPI *NtWriteVirtualMemory_t)(
    HANDLE      ProcessHandle,
    PVOID       BaseAddress,
    PVOID       Buffer,
    SIZE_T      NumberOfBytesToWrite,
    PSIZE_T     NumberOfBytesWritten
);

/* ── Trampoline pointers (set by InstallHook) ─────────────────────────────── */

static NtAllocateVirtualMemory_t    Original_NtAllocateVirtualMemory    = NULL;
static NtProtectVirtualMemory_t     Original_NtProtectVirtualMemory     = NULL;
static NtWriteVirtualMemory_t       Original_NtWriteVirtualMemory       = NULL;

/* ── Detour: NtAllocateVirtualMemory ──────────────────────────────────────── */

static NTSTATUS NTAPI
Hooked_NtAllocateVirtualMemory(
    HANDLE      ProcessHandle,
    PVOID      *BaseAddress,
    ULONG_PTR   ZeroBits,
    PSIZE_T     RegionSize,
    ULONG       AllocationType,
    ULONG       Protect)
{
    /* Call original first — BaseAddress and RegionSize are IN/OUT */
    NTSTATUS status = Original_NtAllocateVirtualMemory(
        ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);

    SENTINEL_HOOK_EVENT evt = {0};
    evt.Function        = SentinelHookNtAllocateVirtualMemory;
    evt.TargetProcessId = SentinelGetTargetPid(ProcessHandle);
    evt.BaseAddress     = (ULONG_PTR)(BaseAddress ? *BaseAddress : 0);
    evt.RegionSize      = RegionSize ? *RegionSize : 0;
    evt.AllocationType  = AllocationType;
    evt.Protection      = Protect;
    evt.ReturnAddress   = (ULONG_PTR)_ReturnAddress();
    evt.ReturnStatus    = status;

    SentinelGetCallingModule(evt.ReturnAddress,
                             evt.CallingModule, SENTINEL_MAX_MODULE_NAME);
    SentinelEmitHookEvent(&evt);

    return status;
}

/* ── Detour: NtProtectVirtualMemory ───────────────────────────────────────── */

static NTSTATUS NTAPI
Hooked_NtProtectVirtualMemory(
    HANDLE      ProcessHandle,
    PVOID      *BaseAddress,
    PSIZE_T     RegionSize,
    ULONG       NewProtect,
    PULONG      OldProtect)
{
    NTSTATUS status = Original_NtProtectVirtualMemory(
        ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);

    SENTINEL_HOOK_EVENT evt = {0};
    evt.Function        = SentinelHookNtProtectVirtualMemory;
    evt.TargetProcessId = SentinelGetTargetPid(ProcessHandle);
    evt.BaseAddress     = (ULONG_PTR)(BaseAddress ? *BaseAddress : 0);
    evt.RegionSize      = RegionSize ? *RegionSize : 0;
    evt.Protection      = NewProtect;
    evt.ReturnAddress   = (ULONG_PTR)_ReturnAddress();
    evt.ReturnStatus    = status;

    SentinelGetCallingModule(evt.ReturnAddress,
                             evt.CallingModule, SENTINEL_MAX_MODULE_NAME);
    SentinelEmitHookEvent(&evt);

    return status;
}

/* ── Detour: NtWriteVirtualMemory ─────────────────────────────────────────── */

static NTSTATUS NTAPI
Hooked_NtWriteVirtualMemory(
    HANDLE      ProcessHandle,
    PVOID       BaseAddress,
    PVOID       Buffer,
    SIZE_T      NumberOfBytesToWrite,
    PSIZE_T     NumberOfBytesWritten)
{
    NTSTATUS status = Original_NtWriteVirtualMemory(
        ProcessHandle, BaseAddress, Buffer,
        NumberOfBytesToWrite, NumberOfBytesWritten);

    SENTINEL_HOOK_EVENT evt = {0};
    evt.Function        = SentinelHookNtWriteVirtualMemory;
    evt.TargetProcessId = SentinelGetTargetPid(ProcessHandle);
    evt.BaseAddress     = (ULONG_PTR)BaseAddress;
    evt.RegionSize      = NumberOfBytesToWrite;
    evt.ReturnAddress   = (ULONG_PTR)_ReturnAddress();
    evt.ReturnStatus    = status;

    SentinelGetCallingModule(evt.ReturnAddress,
                             evt.CallingModule, SENTINEL_MAX_MODULE_NAME);
    SentinelEmitHookEvent(&evt);

    return status;
}

/* ── Install all memory hooks ─────────────────────────────────────────────── */

void
InstallMemoryHooks(void)
{
    InstallHook("ntdll.dll", "NtAllocateVirtualMemory",
                (void *)Hooked_NtAllocateVirtualMemory,
                (void **)&Original_NtAllocateVirtualMemory);

    InstallHook("ntdll.dll", "NtProtectVirtualMemory",
                (void *)Hooked_NtProtectVirtualMemory,
                (void **)&Original_NtProtectVirtualMemory);

    InstallHook("ntdll.dll", "NtWriteVirtualMemory",
                (void *)Hooked_NtWriteVirtualMemory,
                (void **)&Original_NtWriteVirtualMemory);
}
