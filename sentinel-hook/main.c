/*
 * sentinel-hook/main.c
 * User-mode hooking DLL entry point (Ch. 2).
 *
 * Injected into target processes via KAPC (Phase 2).
 * Installs inline hooks on ntdll/kernel32 functions using the hook engine.
 *
 * P3-T1: Hook engine skeleton with Sleep test hook.
 * P3-T2: Core injection-detection hooks (NtAllocateVirtualMemory, etc.)
 */

#include <windows.h>
#include "hook_engine.h"
#include "hooks_common.h"

/* ── Hook installation ─────────────────────────────────────────────────────── */

static void
InstallAllHooks(void)
{
    HookEngineInit();

    /* P3-T2: Core injection-detection hooks */
    InstallMemoryHooks();       /* NtAllocate/Protect/WriteVirtualMemory */
    InstallThreadHooks();       /* NtCreateThreadEx, NtQueueApcThread */
    InstallSectionHooks();      /* NtMapViewOfSection */
}

static void
RemoveAllInstalledHooks(void)
{
    HookEngineCleanup();
}

/* ── DllMain ───────────────────────────────────────────────────────────────── */

BOOL APIENTRY
DllMain(
    HMODULE hModule,
    DWORD   dwReason,
    LPVOID  lpReserved
)
{
    (void)lpReserved;

    switch (dwReason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        OutputDebugStringA("SentinelHook: DLL_PROCESS_ATTACH\n");
        InstallAllHooks();
        break;

    case DLL_PROCESS_DETACH:
        OutputDebugStringA("SentinelHook: DLL_PROCESS_DETACH\n");
        RemoveAllInstalledHooks();
        break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }

    return TRUE;
}
