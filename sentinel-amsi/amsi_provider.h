/*
 * sentinel-amsi/amsi_provider.h
 * Custom AMSI provider — COM in-process server.
 *
 * Implements IAntimalwareProvider so that Windows calls our Scan() method
 * for every AmsiScanBuffer() invocation (PowerShell, VBScript, JScript).
 * Content is evaluated against a string-signature list; matches return
 * AMSI_RESULT_DETECTED.
 *
 * This DLL is loaded into the target process (e.g., powershell.exe) by
 * COM, not by our agent. The agent EXE handles registry registration.
 *
 * P7-T4: Custom AMSI Provider.
 * Book reference: Chapter 10 — AMSI Integration.
 */

#ifndef SENTINEL_AMSI_PROVIDER_H
#define SENTINEL_AMSI_PROVIDER_H

#include <windows.h>
#include <amsi.h>
#include <vector>
#include <string>

/* ── SentinelAmsiProvider ────────────────────────────────────────────────── */

class SentinelAmsiProvider : public IAntimalwareProvider {
public:
    SentinelAmsiProvider();
    ~SentinelAmsiProvider();

    /* IUnknown */
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override;
    ULONG   STDMETHODCALLTYPE AddRef() override;
    ULONG   STDMETHODCALLTYPE Release() override;

    /* IAntimalwareProvider */
    HRESULT STDMETHODCALLTYPE Scan(IAmsiStream* stream, AMSI_RESULT* result) override;
    void    STDMETHODCALLTYPE CloseSession(ULONGLONG session) override;
    HRESULT STDMETHODCALLTYPE DisplayName(LPWSTR* displayName) override;

private:
    LONG    m_refCount;

    /* Signature matching */
    bool    m_signaturesLoaded;
    std::vector<std::string> m_signatures;   /* Lowercase patterns */

    void    LoadSignatures();
    bool    MatchContent(const BYTE* data, ULONG size);
};

/* ── SentinelAmsiClassFactory ────────────────────────────────────────────── */

class SentinelAmsiClassFactory : public IClassFactory {
public:
    SentinelAmsiClassFactory();

    /* IUnknown */
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override;
    ULONG   STDMETHODCALLTYPE AddRef() override;
    ULONG   STDMETHODCALLTYPE Release() override;

    /* IClassFactory */
    HRESULT STDMETHODCALLTYPE CreateInstance(IUnknown* pOuter, REFIID riid, void** ppv) override;
    HRESULT STDMETHODCALLTYPE LockServer(BOOL lock) override;

private:
    LONG    m_refCount;
};

/* ── DLL-wide state ──────────────────────────────────────────────────────── */

extern volatile LONG g_DllRefCount;

#endif /* SENTINEL_AMSI_PROVIDER_H */
