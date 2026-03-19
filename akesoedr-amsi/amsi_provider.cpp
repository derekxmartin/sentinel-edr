/*
 * akesoedr-amsi/amsi_provider.cpp
 * Custom AMSI provider implementation.
 *
 * Implements IAntimalwareProvider::Scan() with string-signature matching.
 * On each scan request from Windows, the provider:
 *   1. Reads content from the IAmsiStream via CONTENT_ADDRESS attribute
 *   2. Converts to lowercase for case-insensitive comparison
 *   3. Searches for any signature substring match
 *   4. Returns AMSI_RESULT_DETECTED on match, NOT_DETECTED otherwise
 *
 * Signatures are loaded from C:\AkesoEDR\amsi_signatures.txt on first
 * Scan() call (lazy initialization to avoid file I/O in DllMain).
 *
 * Note: PowerShell's IAmsiStream requires 8-byte (ULONGLONG) buffers for
 * GetAttribute(CONTENT_SIZE) and GetAttribute(CONTENT_ADDRESS). Using
 * 4-byte ULONG buffers returns E_INVALIDARG on Windows Server 2019+.
 *
 * P7-T4: Custom AMSI Provider.
 * Book reference: Chapter 10 — AMSI Integration.
 */

#define INITGUID
#include "amsi_provider.h"
#include "constants.h"

/*
 * IID_IAntimalwareProvider is declared in <amsi.h> via MIDL but not
 * defined in any standard .lib. Define the symbol here from the UUID
 * in the MIDL_INTERFACE annotation: {b2cabfe3-fe04-42b1-a5df-08d483d4d125}
 */
extern "C" const GUID IID_IAntimalwareProvider =
    { 0xb2cabfe3, 0xfe04, 0x42b1,
      { 0xa5, 0xdf, 0x08, 0xd4, 0x83, 0xd4, 0xd1, 0x25 } };

#include <cstdio>
#include <cstring>
#include <algorithm>
#include <fstream>

/* ── Constants ──────────────────────────────────────────────────────────── */

#define SIGNATURE_FILE_PATH     "C:\\AkesoEDR\\amsi_signatures.txt"
#define MAX_SCAN_SIZE           (64 * 1024)     /* Cap at 64KB */

/* ── DLL-wide ref count ─────────────────────────────────────────────────── */

volatile LONG g_DllRefCount = 0;

/* ── AkesoEDRAmsiProvider ────────────────────────────────────────────────── */

AkesoEDRAmsiProvider::AkesoEDRAmsiProvider()
    : m_refCount(1)
    , m_signaturesLoaded(false)
{
    InterlockedIncrement(&g_DllRefCount);
}

AkesoEDRAmsiProvider::~AkesoEDRAmsiProvider()
{
    InterlockedDecrement(&g_DllRefCount);
}

/* ── IUnknown ────────────────────────────────────────────────────────────── */

HRESULT STDMETHODCALLTYPE
AkesoEDRAmsiProvider::QueryInterface(REFIID riid, void** ppv)
{
    if (!ppv) return E_POINTER;

    if (IsEqualIID(riid, IID_IUnknown) ||
        IsEqualIID(riid, IID_IAntimalwareProvider)) {
        *ppv = static_cast<IAntimalwareProvider*>(this);
        AddRef();
        return S_OK;
    }

    *ppv = nullptr;
    return E_NOINTERFACE;
}

ULONG STDMETHODCALLTYPE
AkesoEDRAmsiProvider::AddRef()
{
    return InterlockedIncrement(&m_refCount);
}

ULONG STDMETHODCALLTYPE
AkesoEDRAmsiProvider::Release()
{
    LONG ref = InterlockedDecrement(&m_refCount);
    if (ref == 0) {
        delete this;
    }
    return ref;
}

/* ── IAntimalwareProvider ────────────────────────────────────────────────── */

HRESULT STDMETHODCALLTYPE
AkesoEDRAmsiProvider::Scan(IAmsiStream* stream, AMSI_RESULT* result)
{
    if (!stream || !result) return E_INVALIDARG;

    /* Default: not detected */
    *result = AMSI_RESULT_NOT_DETECTED;

    /* Lazy-load signatures on first scan */
    if (!m_signaturesLoaded) {
        LoadSignatures();
    }

    /* No signatures loaded — pass everything through */
    if (m_signatures.empty()) {
        return S_OK;
    }

    /*
     * Obtain content to scan. Two strategies:
     *   1. CONTENT_ADDRESS attribute — direct pointer to buffer (preferred)
     *   2. Read() method — copy into local buffer (fallback)
     *
     * PowerShell's IAmsiStream requires ULONGLONG (8-byte) buffers for
     * GetAttribute calls. Using ULONG (4-byte) returns E_INVALIDARG.
     * Read() returns E_NOTIMPL on PowerShell streams.
     */
    const BYTE* scanData = nullptr;
    ULONG scanSize = 0;
    std::vector<BYTE> readBuffer;

    /* Strategy 1: Direct pointer via CONTENT_ADDRESS + CONTENT_SIZE */
    ULONGLONG contentAddr = 0;
    ULONG retSize = 0;
    HRESULT hr = stream->GetAttribute(
        AMSI_ATTRIBUTE_CONTENT_ADDRESS, sizeof(contentAddr),
        (BYTE*)&contentAddr, &retSize);

    ULONGLONG contentSize = 0;
    ULONG retSize2 = 0;
    HRESULT hr2 = stream->GetAttribute(
        AMSI_ATTRIBUTE_CONTENT_SIZE, sizeof(contentSize),
        (BYTE*)&contentSize, &retSize2);

    if (SUCCEEDED(hr) && contentAddr != 0 &&
        SUCCEEDED(hr2) && contentSize > 0) {
        scanData = reinterpret_cast<const BYTE*>(contentAddr);
        scanSize = (contentSize > MAX_SCAN_SIZE)
            ? MAX_SCAN_SIZE : (ULONG)contentSize;
    } else {
        /* Strategy 2: Read() fallback */
        ULONG readSize = (SUCCEEDED(hr2) && contentSize > 0)
            ? (ULONG)((contentSize > MAX_SCAN_SIZE) ? MAX_SCAN_SIZE : contentSize)
            : MAX_SCAN_SIZE;

        readBuffer.resize(readSize);
        ULONG bytesRead = 0;
        hr = stream->Read(0, readSize, readBuffer.data(), &bytesRead);

        if (SUCCEEDED(hr) && bytesRead > 0) {
            scanData = readBuffer.data();
            scanSize = bytesRead;
        } else {
            return S_OK;
        }
    }

    /* Check for signature match */
    if (MatchContent(scanData, scanSize)) {
        *result = AMSI_RESULT_DETECTED;
    }

    return S_OK;
}

void STDMETHODCALLTYPE
AkesoEDRAmsiProvider::CloseSession(ULONGLONG session)
{
    /* Nothing to clean up per session */
    (void)session;
}

HRESULT STDMETHODCALLTYPE
AkesoEDRAmsiProvider::DisplayName(LPWSTR* displayName)
{
    if (!displayName) return E_POINTER;

    const WCHAR name[] = L"AkesoEDR AMSI Provider";
    *displayName = (LPWSTR)CoTaskMemAlloc(sizeof(name));
    if (!*displayName) return E_OUTOFMEMORY;

    memcpy(*displayName, name, sizeof(name));
    return S_OK;
}

/* ── Signature loading ──────────────────────────────────────────────────── */

void
AkesoEDRAmsiProvider::LoadSignatures()
{
    m_signaturesLoaded = true;

    std::ifstream file(SIGNATURE_FILE_PATH);
    if (!file.is_open()) {
        return;
    }

    std::string line;
    while (std::getline(file, line)) {
        /* Skip empty lines and comments */
        if (line.empty() || line[0] == '#') continue;

        /* Trim trailing whitespace */
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n'
                                 || line.back() == ' ' || line.back() == '\t')) {
            line.pop_back();
        }

        if (line.empty()) continue;

        /* Convert to lowercase for case-insensitive matching */
        std::transform(line.begin(), line.end(), line.begin(),
            [](unsigned char c) { return (char)tolower(c); });

        m_signatures.push_back(line);
    }
}

/* ── Content matching ────────────────────────────────────────────────────── */

/*
 * AMSI content may be Unicode (WCHAR) or ANSI. We handle both by:
 *   1. Trying to match against the raw bytes as ASCII/UTF-8
 *   2. If content looks like UTF-16LE (common for PowerShell), converting
 *      to narrow chars for matching
 *
 * This is a pragmatic approach — PowerShell submits UTF-16LE content,
 * while other apps may use UTF-8/ASCII.
 */
bool
AkesoEDRAmsiProvider::MatchContent(const BYTE* data, ULONG size)
{
    if (size == 0) return false;

    /*
     * Strategy 1: Convert everything to a lowercase narrow string.
     * If the content is UTF-16LE (every other byte is 0x00 for ASCII range),
     * extract the narrow chars. Otherwise, treat as UTF-8/ASCII.
     */

    /* Detect UTF-16LE: check if odd bytes are mostly zero */
    bool isUtf16 = false;
    if (size >= 4) {
        int zeroCount = 0;
        int checkLen = (size > 64) ? 64 : (int)size;
        for (int i = 1; i < checkLen; i += 2) {
            if (data[i] == 0) zeroCount++;
        }
        isUtf16 = (zeroCount > checkLen / 4);
    }

    std::string narrow;

    if (isUtf16) {
        /* Extract narrow chars from UTF-16LE */
        narrow.reserve(size / 2);
        for (ULONG i = 0; i + 1 < size; i += 2) {
            char c = (char)data[i];
            /* Skip high byte — we only match ASCII-range signatures */
            narrow.push_back((char)tolower((unsigned char)c));
        }
    } else {
        /* Treat as UTF-8/ASCII */
        narrow.reserve(size);
        for (ULONG i = 0; i < size; i++) {
            narrow.push_back((char)tolower(data[i]));
        }
    }

    /* Search for any signature match */
    for (const auto& sig : m_signatures) {
        if (narrow.find(sig) != std::string::npos) {
            return true;
        }
    }

    return false;
}

/* ── AkesoEDRAmsiClassFactory ────────────────────────────────────────────── */

AkesoEDRAmsiClassFactory::AkesoEDRAmsiClassFactory()
    : m_refCount(1)
{
}

HRESULT STDMETHODCALLTYPE
AkesoEDRAmsiClassFactory::QueryInterface(REFIID riid, void** ppv)
{
    if (!ppv) return E_POINTER;

    if (IsEqualIID(riid, IID_IUnknown) ||
        IsEqualIID(riid, IID_IClassFactory)) {
        *ppv = static_cast<IClassFactory*>(this);
        AddRef();
        return S_OK;
    }

    *ppv = nullptr;
    return E_NOINTERFACE;
}

ULONG STDMETHODCALLTYPE
AkesoEDRAmsiClassFactory::AddRef()
{
    return InterlockedIncrement(&m_refCount);
}

ULONG STDMETHODCALLTYPE
AkesoEDRAmsiClassFactory::Release()
{
    LONG ref = InterlockedDecrement(&m_refCount);
    if (ref == 0) {
        delete this;
    }
    return ref;
}

HRESULT STDMETHODCALLTYPE
AkesoEDRAmsiClassFactory::CreateInstance(IUnknown* pOuter, REFIID riid, void** ppv)
{
    if (pOuter) return CLASS_E_NOAGGREGATION;
    if (!ppv) return E_POINTER;

    auto* provider = new (std::nothrow) AkesoEDRAmsiProvider();
    if (!provider) return E_OUTOFMEMORY;

    HRESULT hr = provider->QueryInterface(riid, ppv);
    provider->Release();    /* QI added a ref; release our initial ref */
    return hr;
}

HRESULT STDMETHODCALLTYPE
AkesoEDRAmsiClassFactory::LockServer(BOOL lock)
{
    if (lock) {
        InterlockedIncrement(&g_DllRefCount);
    } else {
        InterlockedDecrement(&g_DllRefCount);
    }
    return S_OK;
}
