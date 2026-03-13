/*
 * sentinel-agent/amsi/amsi_register.h
 * AMSI provider registry registration/unregistration.
 *
 * The agent EXE creates and removes registry keys that tell Windows
 * about our custom AMSI provider DLL. The DLL itself is loaded by
 * COM into target processes (e.g., powershell.exe).
 *
 * Registry keys created:
 *   HKLM\SOFTWARE\Microsoft\AMSI\Providers\{CLSID}
 *   HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32
 *
 * P7-T4: Custom AMSI Provider.
 * Book reference: Chapter 10 — AMSI Integration.
 */

#ifndef SENTINEL_AMSI_REGISTER_H
#define SENTINEL_AMSI_REGISTER_H

#include <windows.h>

/*
 * Register the custom AMSI provider DLL in the registry.
 * dllPath: Full path to sentinel-amsi.dll (e.g., L"C:\\SentinelPOC\\sentinel-amsi.dll").
 * Returns true on success.
 */
bool AmsiProviderRegister(const WCHAR* dllPath);

/*
 * Remove the custom AMSI provider registry keys.
 * Returns true on success.
 */
bool AmsiProviderUnregister();

#endif /* SENTINEL_AMSI_REGISTER_H */
