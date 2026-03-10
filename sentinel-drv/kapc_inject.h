/*
 * sentinel-drv/kapc_inject.h
 * KAPC injection infrastructure (Ch. 2/5 — APC-based DLL injection).
 *
 * Two-phase injection triggered by the image-load callback:
 *   Phase 1: ntdll.dll loads → save ntdll base for the PID
 *   Phase 2: kernel32.dll loads → resolve LdrLoadDll, queue APC
 *
 * kernel32.dll is used as the trigger (not ntdll) because by that time
 * the initial thread is executing and KeGetCurrentThread() is correct.
 */

#ifndef SENTINEL_KAPC_INJECT_H
#define SENTINEL_KAPC_INJECT_H

#include <fltKernel.h>

/*
 * SentinelKapcInjectInit
 *   Initialize injection tracking structures.
 *   Called at PASSIVE_LEVEL from DriverEntry.
 */
NTSTATUS
SentinelKapcInjectInit(VOID);

/*
 * SentinelKapcInjectStop
 *   Cleanup injection tracking.
 *   Called at PASSIVE_LEVEL from DriverUnload.
 */
VOID
SentinelKapcInjectStop(VOID);

/*
 * SentinelKapcSaveNtdllBase
 *   Save ntdll.dll base address for a process (Phase 1).
 *   Called from image-load callback when ntdll.dll is detected.
 */
VOID
SentinelKapcSaveNtdllBase(
    _In_ HANDLE ProcessId,
    _In_ PVOID  NtdllBase
);

/*
 * SentinelKapcTryInject
 *   Attempt KAPC injection into a process (Phase 2).
 *   Called from image-load callback when kernel32.dll is detected.
 *   Uses the previously saved ntdll base to resolve LdrLoadDll.
 *
 *   ProcessId  — target process PID
 */
VOID
SentinelKapcTryInject(
    _In_ HANDLE ProcessId
);

#endif /* SENTINEL_KAPC_INJECT_H */
