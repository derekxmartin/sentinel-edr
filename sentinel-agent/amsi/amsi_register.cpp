/*
 * sentinel-agent/amsi/amsi_register.cpp
 * AMSI provider registry registration/unregistration.
 *
 * Creates the registry keys Windows needs to discover our custom AMSI
 * provider DLL. Called from PipelineStart() and PipelineStop().
 *
 * Two key paths:
 *   1. HKLM\SOFTWARE\Microsoft\AMSI\Providers\{CLSID}
 *      — Tells Windows AMSI to load this provider
 *   2. HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32
 *      — Tells COM where the DLL is and its threading model
 *
 * P7-T4: Custom AMSI Provider.
 * Book reference: Chapter 10 — AMSI Integration.
 */

#define INITGUID
#include "amsi_register.h"
#include "constants.h"

#include <cstdio>
#include <cstring>

/* ── Helper: GUID to registry string ────────────────────────────────────── */

static void
GuidToString(const GUID& guid, WCHAR* buf, size_t bufLen)
{
    _snwprintf_s(buf, bufLen, _TRUNCATE,
        L"{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
        guid.Data1, guid.Data2, guid.Data3,
        guid.Data4[0], guid.Data4[1],
        guid.Data4[2], guid.Data4[3],
        guid.Data4[4], guid.Data4[5],
        guid.Data4[6], guid.Data4[7]);
}

/* ── Helper: recursive registry key deletion ─────────────────────────────── */

static LONG
RegDeleteKeyRecursive(HKEY hParent, const WCHAR* subKey)
{
    HKEY hKey;
    LONG status = RegOpenKeyExW(hParent, subKey, 0, KEY_ALL_ACCESS, &hKey);
    if (status != ERROR_SUCCESS) return status;

    /* Delete all sub-keys first */
    WCHAR childName[256];
    while (RegEnumKeyW(hKey, 0, childName, 256) == ERROR_SUCCESS) {
        RegDeleteKeyRecursive(hKey, childName);
    }

    RegCloseKey(hKey);
    return RegDeleteKeyW(hParent, subKey);
}

/* ── AmsiProviderRegister ────────────────────────────────────────────────── */

bool
AmsiProviderRegister(const WCHAR* dllPath)
{
    WCHAR clsidStr[64];
    GuidToString(SENTINEL_AMSI_PROVIDER_CLSID, clsidStr, 64);

    std::printf("SentinelAgent: Registering AMSI provider %ls\n", clsidStr);

    /* ── 1. Create AMSI provider key ────────────────────────────────── */

    WCHAR amsiKeyPath[256];
    _snwprintf_s(amsiKeyPath, 256, _TRUNCATE,
        L"SOFTWARE\\Microsoft\\AMSI\\Providers\\%ls", clsidStr);

    HKEY hAmsiKey;
    LONG status = RegCreateKeyExW(
        HKEY_LOCAL_MACHINE, amsiKeyPath, 0, nullptr,
        REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hAmsiKey, nullptr);

    if (status != ERROR_SUCCESS) {
        std::printf("SentinelAgent: Failed to create AMSI provider key (error %ld)\n",
                    status);
        if (status == ERROR_ACCESS_DENIED) {
            std::printf("SentinelAgent: AMSI registration requires administrator privileges\n");
        }
        return false;
    }

    RegCloseKey(hAmsiKey);

    /* ── 2. Create CLSID key ────────────────────────────────────────── */

    WCHAR clsidKeyPath[256];
    _snwprintf_s(clsidKeyPath, 256, _TRUNCATE,
        L"SOFTWARE\\Classes\\CLSID\\%ls", clsidStr);

    HKEY hClsidKey;
    status = RegCreateKeyExW(
        HKEY_LOCAL_MACHINE, clsidKeyPath, 0, nullptr,
        REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hClsidKey, nullptr);

    if (status != ERROR_SUCCESS) {
        std::printf("SentinelAgent: Failed to create CLSID key (error %ld)\n",
                    status);
        return false;
    }

    /* Set display name */
    const WCHAR displayName[] = L"SentinelEDR AMSI Provider";
    RegSetValueExW(hClsidKey, nullptr, 0, REG_SZ,
        (const BYTE*)displayName, sizeof(displayName));

    RegCloseKey(hClsidKey);

    /* ── 3. Create InprocServer32 key ───────────────────────────────── */

    WCHAR inprocKeyPath[256];
    _snwprintf_s(inprocKeyPath, 256, _TRUNCATE,
        L"SOFTWARE\\Classes\\CLSID\\%ls\\InprocServer32", clsidStr);

    HKEY hInprocKey;
    status = RegCreateKeyExW(
        HKEY_LOCAL_MACHINE, inprocKeyPath, 0, nullptr,
        REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hInprocKey, nullptr);

    if (status != ERROR_SUCCESS) {
        std::printf("SentinelAgent: Failed to create InprocServer32 key (error %ld)\n",
                    status);
        return false;
    }

    /* Set DLL path */
    DWORD pathBytes = (DWORD)((wcslen(dllPath) + 1) * sizeof(WCHAR));
    RegSetValueExW(hInprocKey, nullptr, 0, REG_SZ,
        (const BYTE*)dllPath, pathBytes);

    /* Set threading model */
    const WCHAR threadModel[] = L"Both";
    RegSetValueExW(hInprocKey, L"ThreadingModel", 0, REG_SZ,
        (const BYTE*)threadModel, sizeof(threadModel));

    RegCloseKey(hInprocKey);

    std::printf("SentinelAgent: AMSI provider registered (DLL: %ls)\n", dllPath);
    return true;
}

/* ── AmsiProviderUnregister ──────────────────────────────────────────────── */

bool
AmsiProviderUnregister()
{
    WCHAR clsidStr[64];
    GuidToString(SENTINEL_AMSI_PROVIDER_CLSID, clsidStr, 64);

    std::printf("SentinelAgent: Unregistering AMSI provider %ls\n", clsidStr);

    /* ── 1. Remove AMSI provider key ────────────────────────────────── */

    WCHAR amsiKeyPath[256];
    _snwprintf_s(amsiKeyPath, 256, _TRUNCATE,
        L"SOFTWARE\\Microsoft\\AMSI\\Providers\\%ls", clsidStr);

    LONG status = RegDeleteKeyW(HKEY_LOCAL_MACHINE, amsiKeyPath);
    if (status != ERROR_SUCCESS && status != ERROR_FILE_NOT_FOUND) {
        std::printf("SentinelAgent: Failed to delete AMSI provider key (error %ld)\n",
                    status);
    }

    /* ── 2. Remove CLSID key (recursive — has InprocServer32 subkey) ── */

    WCHAR clsidKeyPath[256];
    _snwprintf_s(clsidKeyPath, 256, _TRUNCATE,
        L"SOFTWARE\\Classes\\CLSID\\%ls", clsidStr);

    status = RegDeleteKeyRecursive(HKEY_LOCAL_MACHINE, clsidKeyPath);
    if (status != ERROR_SUCCESS && status != ERROR_FILE_NOT_FOUND) {
        std::printf("SentinelAgent: Failed to delete CLSID key (error %ld)\n",
                    status);
    }

    std::printf("SentinelAgent: AMSI provider unregistered\n");
    return true;
}
