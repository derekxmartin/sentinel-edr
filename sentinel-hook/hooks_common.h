/*
 * sentinel-hook/hooks_common.h
 * Shared helpers for hook detour functions.
 *
 * Provides:
 *   - Target PID resolution from process handle
 *   - Calling module lookup from return address
 *   - Hook event emission (OutputDebugString for now, pipe in P3-T4)
 */

#ifndef SENTINEL_HOOKS_COMMON_H
#define SENTINEL_HOOKS_COMMON_H

#include <windows.h>
#include "telemetry.h"

/*
 * SentinelGetTargetPid
 *   Resolve a process handle to a PID. Returns 0 if the handle refers
 *   to the current process (or on failure).
 */
ULONG SentinelGetTargetPid(HANDLE ProcessHandle);

/*
 * SentinelGetCallingModule
 *   Given a return address, resolve the module that contains it.
 *   Writes the full module path into buf (up to bufLen WCHARs).
 */
void SentinelGetCallingModule(
    ULONG_PTR   ReturnAddress,
    WCHAR      *buf,
    DWORD       bufLen
);

/*
 * SentinelEmitHookEvent
 *   Emit a hook event. Currently logs via OutputDebugStringA.
 *   P3-T4 will replace this with named pipe send.
 */
void SentinelEmitHookEvent(SENTINEL_HOOK_EVENT *evt);

/*
 * SentinelHookFunctionName
 *   Return a human-readable name for a SENTINEL_HOOK_FUNCTION enum value.
 */
const char *SentinelHookFunctionName(SENTINEL_HOOK_FUNCTION func);

/* ── Per-file hook installers ─────────────────────────────────────────────── */

void InstallMemoryHooks(void);
void InstallThreadHooks(void);
void InstallSectionHooks(void);

#endif /* SENTINEL_HOOKS_COMMON_H */
