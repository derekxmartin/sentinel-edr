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
    char buf[256];

    HookEngineInit();

    /* P3-T2: Core injection-detection hooks */
    InstallMemoryHooks();       /* NtAllocate/Protect/WriteVirtualMemory */
    InstallThreadHooks();       /* NtCreateThreadEx, NtQueueApcThread */
    InstallSectionHooks();      /* NtMapViewOfSection */

    /* OutputDebugStringA is safe here — previous crashes were caused by
       the SIB disassembler bug (now fixed), not by debug output. */
    wsprintfA(buf, "SentinelHook: PID=%lu hooks=%d ready\n",
              GetCurrentProcessId(), HookEngineGetInstallCount());
    OutputDebugStringA(buf);
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

    __try {
        switch (dwReason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hModule);
            SentinelTlsInit();
            InstallAllHooks();
            SentinelHooksSetReady();
            break;

        case DLL_PROCESS_DETACH:
            RemoveAllInstalledHooks();
            SentinelTlsCleanup();
            break;

        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
            break;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        /* Swallow exceptions — never crash the host process from DllMain */
        return TRUE;
    }

    return TRUE;
}
