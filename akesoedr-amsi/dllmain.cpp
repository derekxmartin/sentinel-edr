/*
 * akesoedr-amsi/dllmain.cpp
 * DLL entry point and COM exports for the custom AMSI provider.
 *
 * Exports:
 *   DllGetClassObject  — COM asks for our class factory
 *   DllCanUnloadNow    — COM asks if DLL can be freed
 *
 * P7-T4: Custom AMSI Provider.
 * Book reference: Chapter 10 — AMSI Integration.
 */

#include "amsi_provider.h"
#include "constants.h"

#include <windows.h>

/* ── DLL module handle ──────────────────────────────────────────────────── */

static HMODULE g_hModule = nullptr;

/* ── DllMain ────────────────────────────────────────────────────────────── */

BOOL WINAPI
DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    (void)lpvReserved;

    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        g_hModule = hinstDLL;
        DisableThreadLibraryCalls(hinstDLL);
        break;

    case DLL_PROCESS_DETACH:
        break;
    }

    return TRUE;
}

/* ── DllGetClassObject ──────────────────────────────────────────────────── */

/*
 * Called by COM when a process needs to create an instance of our
 * AMSI provider. Returns our class factory.
 */
STDAPI
DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID* ppv)
{
    if (!ppv) return E_POINTER;

    if (!IsEqualCLSID(rclsid, AKESOEDR_AMSI_PROVIDER_CLSID)) {
        return CLASS_E_CLASSNOTAVAILABLE;
    }

    auto* factory = new (std::nothrow) AkesoEDRAmsiClassFactory();
    if (!factory) return E_OUTOFMEMORY;

    HRESULT hr = factory->QueryInterface(riid, ppv);
    factory->Release();
    return hr;
}

/* ── DllCanUnloadNow ────────────────────────────────────────────────────── */

/*
 * COM periodically asks if the DLL can be unloaded. We return S_FALSE
 * (keep loaded) as long as any objects are alive.
 */
STDAPI
DllCanUnloadNow(void)
{
    return (g_DllRefCount == 0) ? S_OK : S_FALSE;
}
