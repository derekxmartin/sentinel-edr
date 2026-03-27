/*
 * akesoedr-agent/scanner/av_scanner.cpp
 * AkesoAV integration scanner implementation.
 *
 * Loads akesoav.dll via the edr_shim AVEngine wrapper, registers a
 * SIEM callback to forward native AV events through SiemWriter, and
 * provides on-access file scanning for minifilter events.
 */

#include "av_scanner.h"
#include "../config.h"
#include "../output/siem_writer.h"

#include <cstdio>
#include <cstring>

/* ── Init / Shutdown ──────────────────────────────────────────────── */

bool
AVScanner::Init(const AkesoEDRConfig& cfg, SiemWriter* siemWriter)
{
    m_enabled    = cfg.avEnabled;
    m_siemWriter = siemWriter;

    if (!m_enabled) {
        return true;  /* Disabled — not an error */
    }

    /* Initialize AVEngine from the config file.
     * The shim reads [av] section (dll_path, db_path, etc.) itself. */
    if (!m_avEngine.init(cfg.configFilePath)) {
        std::printf("AkesoEDRAgent: WARNING: AV engine init failed "
                    "(AV scanning disabled)\n");
        m_enabled = false;
        return false;
    }

    /* Resolve akav_set_siem_callback from the loaded DLL */
    HMODULE hDll = m_avEngine.dll_handle();
    if (hDll) {
        m_fnSetSiemCallback = (pfn_akav_set_siem_callback)
            GetProcAddress(hDll, "akav_set_siem_callback");
    }

    /* Register SIEM callback if available */
    if (m_fnSetSiemCallback && m_avEngine.engine_handle()) {
        m_fnSetSiemCallback(m_avEngine.engine_handle(),
                            SiemCallbackStatic, this);
        std::printf("AkesoEDRAgent: AV SIEM callback registered\n");
    }

    std::printf("AkesoEDRAgent: AV scanner initialized (engine: %s, db: %s)\n",
                m_avEngine.engine_version(), m_avEngine.db_version());

    return true;
}

void
AVScanner::Shutdown()
{
    m_avEngine.shutdown();
    m_enabled = false;
}

/* ── On-access file scan ──────────────────────────────────────────── */

bool
AVScanner::ScanFile(const AKESOEDR_FILE_EVENT& fileEvt,
                    AKESOEDR_EVENT& alertOut)
{
    if (!m_enabled || !m_avEngine.av_available())
        return false;

    /* Only scan on CREATE and WRITE operations */
    if (fileEvt.Operation != AkesoEDRFileOpCreate &&
        fileEvt.Operation != AkesoEDRFileOpWrite)
        return false;

    /* Skip files where hash was skipped (too large) */
    if (fileEvt.HashSkipped)
        return false;

    /* Convert wide path to narrow for AV engine.
     * The driver provides NT device paths (\Device\HarddiskVolume2\...),
     * but the AV engine expects Win32 paths. We do a simple conversion
     * for common volume mappings. */
    char narrowPath[MAX_PATH * 2] = {};
    WideCharToMultiByte(CP_UTF8, 0, fileEvt.FilePath, -1,
                        narrowPath, sizeof(narrowPath), nullptr, nullptr);

    /* Skip NT device paths that we can't resolve — the on-access scanner
     * already handles path conversion for YARA. For AV, we attempt the
     * scan directly and let the AV engine handle it. */

    AVTelemetry result = m_avEngine.scan_file(narrowPath);

    if (!result.av_detected)
        return false;

    /* Build an AKESOEDR_EVENT alert for the EDR pipeline */
    AkesoEDREventInit(&alertOut, AkesoEDRSourceScanner, AkesoEDRSeverityHigh);

    alertOut.ProcessCtx.ProcessId = fileEvt.RequestingProcessId;

    auto& scan = alertOut.Payload.Scanner;
    scan.ScanType = AkesoEDRScanOnAccess;
    wcsncpy_s(scan.TargetPath, fileEvt.FilePath, _TRUNCATE);
    scan.IsMatch = TRUE;

    /* Store AV detection name in YaraRule field (reused for AV) */
    _snprintf_s(scan.YaraRule, sizeof(scan.YaraRule), _TRUNCATE,
                "AV:%s", result.av_malware_name);

    /* Copy SHA256 from file event */
    strncpy_s(scan.Sha256Hex, fileEvt.Sha256Hex, _TRUNCATE);

    return true;
}

/* ── SIEM callback ────────────────────────────────────────────────── */

void
AVScanner::SiemCallbackStatic(const void* event, void* user_data)
{
    auto* self = static_cast<AVScanner*>(user_data);
    self->OnSiemEvent(event);
}

void
AVScanner::OnSiemEvent(const void* event)
{
    if (!m_siemWriter) return;

    /* Replicate the akav_siem_event_t layout to avoid build dependency
     * on akesoav.h. Must match the struct in akesoav.h exactly. */
    struct AkavSiemEvent {
        char event_id[64];
        char timestamp[32];
        char source_type[32];
        char event_type[32];
        char agent_id[128];
        char payload_json[8192];
    };

    const auto* avEvt = static_cast<const AkavSiemEvent*>(event);

    /* Build raw NDJSON line preserving the native AV envelope */
    char buf[8704];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "{\"source_type\":\"%s\""
        ",\"event_type\":\"%s\""
        ",\"event_id\":\"%s\""
        ",\"timestamp\":\"%s\""
        ",\"agent_id\":\"%s\""
        ",\"payload\":%s"
        "}",
        avEvt->source_type,
        avEvt->event_type,
        avEvt->event_id,
        avEvt->timestamp,
        avEvt->agent_id,
        avEvt->payload_json);

    m_siemWriter->EnqueueRaw(std::string(buf));
}
