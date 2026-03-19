/*
 * akesoedr-agent/cmd_handler.cpp
 * Command pipe server implementation.
 *
 * Listens on \\.\pipe\AkesoEDRCommand for CLI client connections,
 * dispatches commands, and returns JSON-encoded replies.
 *
 * P9-T1: Core CLI Commands.
 * P9-T2: Inspection Commands (connections, processes, hooks).
 * Book reference: Chapter 1 — Agent Design.
 */

#include "cmd_handler.h"
#include "config.h"
#include "event_processor.h"
#include "pipeline.h"        /* g_EventQueue for queue depth */
#include "json_writer.h"     /* SeverityName(), SourceName() */
#include "ipc.h"
#include "ipc_serialize.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <deque>
#include <tlhelp32.h>       /* CreateToolhelp32Snapshot, Module32First/Next */

/* ── Start / Stop ────────────────────────────────────────────────────────── */

void
CommandHandler::Start(EventProcessor* processor,
                      std::function<bool()> driverStatusFn,
                      const AkesoEDRConfig* config)
{
    m_processor      = processor;
    m_config         = config;
    m_driverStatusFn = std::move(driverStatusFn);
    m_startTime      = GetTickCount64();
    m_running.store(true);
    m_shutdownEvent  = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    m_thread         = std::thread(&CommandHandler::ServerThread, this);
}

void
CommandHandler::Stop()
{
    m_running.store(false);
    if (m_shutdownEvent) {
        SetEvent(m_shutdownEvent);
    }

    /* Cancel any blocking ConnectNamedPipe / ReadFile */
    if (m_activePipe != INVALID_HANDLE_VALUE) {
        CancelIoEx(m_activePipe, nullptr);
    }

    /* Wake the listener by connecting and immediately closing */
    HANDLE hDummy = CreateFileW(
        AKESOEDR_PIPE_COMMAND,
        GENERIC_READ | GENERIC_WRITE,
        0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hDummy != INVALID_HANDLE_VALUE) {
        CloseHandle(hDummy);
    }

    if (m_thread.joinable()) {
        m_thread.join();
    }

    if (m_shutdownEvent) {
        CloseHandle(m_shutdownEvent);
        m_shutdownEvent = nullptr;
    }
}

/* ── Server thread ───────────────────────────────────────────────────────── */

void
CommandHandler::ServerThread()
{
    std::printf("AkesoEDRAgent: Command server started on %ls\n",
                AKESOEDR_PIPE_COMMAND);

    while (m_running.load()) {

        /* Create a new pipe instance (single instance — one CLI at a time) */
        HANDLE hPipe = CreateNamedPipeW(
            AKESOEDR_PIPE_COMMAND,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1,  /* max instances: 1 CLI at a time */
            AKESOEDR_PIPE_OUT_BUFFER,
            AKESOEDR_PIPE_IN_BUFFER,
            5000,
            nullptr);

        if (hPipe == INVALID_HANDLE_VALUE) {
            std::printf("AkesoEDRAgent: Command pipe create failed %lu\n",
                        GetLastError());
            WaitForSingleObject(m_shutdownEvent, 1000);
            continue;
        }

        m_activePipe = hPipe;

        /* Wait for a CLI client to connect */
        BOOL connected = ConnectNamedPipe(hPipe, nullptr)
                         || (GetLastError() == ERROR_PIPE_CONNECTED);

        if (!connected || !m_running.load()) {
            CloseHandle(hPipe);
            m_activePipe = INVALID_HANDLE_VALUE;
            continue;
        }

        HandleClient(hPipe);

        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
        m_activePipe = INVALID_HANDLE_VALUE;
    }

    std::printf("AkesoEDRAgent: Command server stopped\n");
}

/* ── Handle a single CLI client ──────────────────────────────────────────── */

void
CommandHandler::HandleClient(HANDLE hPipe)
{
    BYTE    readBuf[sizeof(UINT32) + sizeof(AKESOEDR_IPC_COMMAND) + 256];
    DWORD   bytesRead = 0;

    /* 1. Read and validate handshake */
    if (!ReadFile(hPipe, readBuf, sizeof(readBuf), &bytesRead, nullptr)
        || bytesRead == 0) {
        return;
    }

    if (bytesRead >= sizeof(UINT32) + sizeof(AKESOEDR_IPC_HANDSHAKE)) {
        auto* hs = reinterpret_cast<AKESOEDR_IPC_HANDSHAKE*>(
            readBuf + sizeof(UINT32));

        if (AkesoEDRIpcHeaderValidate(&hs->Header) != AkesoEDRSerializeOk
            || hs->Header.Type != AkesoEDRMsgHandshake
            || hs->ClientType != AkesoEDRClientCli) {
            return;     /* Bad handshake */
        }

        /* Send handshake reply */
        AKESOEDR_IPC_HANDSHAKE_REPLY reply;
        AkesoEDRIpcBuildHandshakeReply(
            &reply, AkesoEDRHandshakeOk,
            GetCurrentProcessId(),
            hs->Header.SequenceNum);

        BYTE    replyBuf[128];
        UINT32  replyBytes = 0;
        if (AkesoEDRIpcWriteFrame(replyBuf, sizeof(replyBuf),
                &reply, sizeof(reply), &replyBytes) == AkesoEDRSerializeOk) {
            DWORD written = 0;
            WriteFile(hPipe, replyBuf, replyBytes, &written, nullptr);
        }
    } else {
        return;     /* Incomplete handshake */
    }

    /* 2. Read command */
    bytesRead = 0;
    if (!ReadFile(hPipe, readBuf, sizeof(readBuf), &bytesRead, nullptr)
        || bytesRead == 0) {
        return;
    }

    if (bytesRead < sizeof(UINT32) + sizeof(AKESOEDR_IPC_HEADER)) {
        return;
    }

    auto* cmd = reinterpret_cast<AKESOEDR_IPC_COMMAND*>(
        readBuf + sizeof(UINT32));

    if (AkesoEDRIpcHeaderValidate(&cmd->Header) != AkesoEDRSerializeOk
        || cmd->Header.Type != AkesoEDRMsgCommand) {
        return;
    }

    /* 3. Dispatch command and build JSON response */
    std::string json;
    UINT32 status = 0;

    switch (cmd->CommandType) {
    case AkesoEDRCmdStatus:
        json = HandleStatus();
        break;
    case AkesoEDRCmdAlerts:
        json = HandleAlerts(cmd->Argument);
        break;
    case AkesoEDRCmdScan:
        json = HandleScan(cmd->Argument);
        break;
    case AkesoEDRCmdRulesReload:
        json = HandleRulesReload();
        break;
    case AkesoEDRCmdConnections:
        json = HandleConnections();
        break;
    case AkesoEDRCmdProcesses:
        json = HandleProcesses();
        break;
    case AkesoEDRCmdHooks:
        json = HandleHooks();
        break;
    case AkesoEDRCmdConfig:
        json = HandleConfig();
        break;
    case AkesoEDRCmdRulesUpdate:
        json = HandleRulesUpdate();
        break;
    default:
        json = "{\"error\":\"Unknown command\"}";
        status = 1;
        break;
    }

    /* 4. Send reply */
    SendReply(hPipe, cmd->CommandType, status, json,
              cmd->Header.SequenceNum + 1);
}

/* ── Command handlers ────────────────────────────────────────────────────── */

std::string
CommandHandler::HandleStatus()
{
    ULONGLONG uptimeMs = GetTickCount64() - m_startTime;
    ULONGLONG uptimeS  = uptimeMs / 1000;

    auto counts = m_processor->GetRuleCounts();
    bool driverOk = m_driverStatusFn ? m_driverStatusFn() : false;

    char buf[1024];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "{\"agent\":\"running\","
        "\"uptime_s\":%llu,"
        "\"events\":%llu,"
        "\"driver\":%s,"
        "\"yara\":%s,"
        "\"yara_rules\":%d,"
        "\"rules\":{\"single\":%zu,\"sequence\":%zu,\"threshold\":%zu},"
        "\"queue_depth\":%zu}",
        uptimeS,
        m_processor->EventsProcessed(),
        driverOk ? "true" : "false",
        m_processor->IsYaraReady() ? "true" : "false",
        counts.yara,
        counts.singleEvent,
        counts.sequence,
        counts.threshold,
        g_EventQueue.Size());

    return buf;
}

std::string
CommandHandler::HandleAlerts(const wchar_t* arg)
{
    /* Parse optional count from argument (default 20) */
    int maxAlerts = 20;
    if (arg && arg[0] != L'\0') {
        int n = _wtoi(arg);
        if (n > 0 && n <= 100) maxAlerts = n;
    }

    auto history = m_processor->GetAlertHistory();

    std::string json = "{\"count\":";
    json += std::to_string(history.size());
    json += ",\"alerts\":[";

    /* Return the most recent maxAlerts entries */
    int start = (int)history.size() - maxAlerts;
    if (start < 0) start = 0;

    bool first = true;
    for (int i = start; i < (int)history.size(); i++) {
        const auto& alert = history[i];
        if (!first) json += ",";
        first = false;

        char entry[512];
        _snprintf_s(entry, sizeof(entry), _TRUNCATE,
            "{\"severity\":\"%s\","
            "\"rule\":\"%s\","
            "\"trigger\":\"%s\","
            "\"pid\":%lu}",
            SeverityName(alert.Severity),
            alert.Payload.Alert.RuleName,
            SourceName(alert.Payload.Alert.TriggerSource),
            alert.ProcessCtx.ProcessId);

        json += entry;
    }

    json += "]}";
    return json;
}

std::string
CommandHandler::HandleScan(const wchar_t* arg)
{
    if (!arg || arg[0] == L'\0') {
        return "{\"error\":\"No path specified\"}";
    }

    if (!m_processor->IsYaraReady()) {
        return "{\"error\":\"YARA scanner not ready\"}";
    }

    AKESOEDR_SCANNER_EVENT result = {};
    bool ok = m_processor->ScanFileOnDemand(arg, result);

    if (!ok) {
        return "{\"error\":\"Scan failed (file not found or access denied)\"}";
    }

    /* Convert wide path to narrow for JSON */
    char narrowPath[AKESOEDR_MAX_PATH];
    WideCharToMultiByte(CP_UTF8, 0, arg, -1,
                        narrowPath, sizeof(narrowPath), nullptr, nullptr);

    char buf[1024];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "{\"path\":\"%s\","
        "\"match\":%s,"
        "\"rule\":\"%s\"}",
        narrowPath,
        result.IsMatch ? "true" : "false",
        result.IsMatch ? result.YaraRule : "(none)");

    /* Escape backslashes in path for valid JSON */
    std::string json = buf;
    size_t pos = 0;
    while ((pos = json.find('\\', pos)) != std::string::npos) {
        /* Only escape if not already escaped */
        if (pos + 1 < json.size() && json[pos + 1] == '\\') {
            pos += 2;
        } else if (pos + 1 < json.size() && json[pos + 1] == '"') {
            pos += 2;   /* Skip \" */
        } else {
            json.insert(pos, 1, '\\');
            pos += 2;
        }
    }

    return json;
}

std::string
CommandHandler::HandleRulesReload()
{
    bool ok = m_processor->ReloadRules();
    auto counts = m_processor->GetRuleCounts();

    char buf[256];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "{\"reloaded\":%s,"
        "\"rules\":{\"single\":%zu,\"sequence\":%zu,\"threshold\":%zu}}",
        ok ? "true" : "false",
        counts.singleEvent,
        counts.sequence,
        counts.threshold);

    return buf;
}

/* ── P9-T2: Helpers ─────────────────────────────────────────────────────── */

static std::string
IpToString(ULONG addr)
{
    /* addr is in network byte order (big-endian) */
    char buf[32];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE, "%u.%u.%u.%u",
                (addr) & 0xFF,
                (addr >> 8) & 0xFF,
                (addr >> 16) & 0xFF,
                (addr >> 24) & 0xFF);
    return buf;
}

static const char*
IntegrityLevelName(ULONG rid)
{
    if (rid >= 0x4000) return "System";
    if (rid >= 0x3000) return "High";
    if (rid >= 0x2000) return "Medium";
    if (rid >= 0x1000) return "Low";
    return "Untrusted";
}

/*
 * Check if a specific DLL is loaded in a process.
 * Uses CreateToolhelp32Snapshot + Module32FirstW/NextW.
 */
static bool
IsModuleLoaded(ULONG pid, const wchar_t* dllName)
{
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (hSnap == INVALID_HANDLE_VALUE) {
        return false;
    }

    MODULEENTRY32W me = {};
    me.dwSize = sizeof(me);

    if (Module32FirstW(hSnap, &me)) {
        do {
            if (_wcsicmp(me.szModule, dllName) == 0) {
                CloseHandle(hSnap);
                return true;
            }
        } while (Module32NextW(hSnap, &me));
    }

    CloseHandle(hSnap);
    return false;
}

static std::string
NarrowPath(const std::wstring& wide)
{
    if (wide.empty()) return "";
    char buf[AKESOEDR_MAX_PATH];
    WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1,
                        buf, sizeof(buf), nullptr, nullptr);
    return buf;
}

/*
 * Escape backslashes in a string for JSON output.
 * Skips already-escaped sequences (\\ and \").
 */
static void
JsonEscapeBackslashes(std::string& s)
{
    size_t pos = 0;
    while ((pos = s.find('\\', pos)) != std::string::npos) {
        if (pos + 1 < s.size() && (s[pos + 1] == '\\' || s[pos + 1] == '"')) {
            pos += 2;
        } else {
            s.insert(pos, 1, '\\');
            pos += 2;
        }
    }
}

/* ── P9-T2: Inspection command handlers ─────────────────────────────────── */

std::string
CommandHandler::HandleConnections()
{
    std::vector<ConnectionEntry> entries;
    m_processor->GetNetworkTable().GetSnapshot(entries);

    std::string json = "{\"count\":";
    json += std::to_string(entries.size());
    json += ",\"connections\":[";

    bool first = true;
    for (const auto& conn : entries) {
        if (!first) json += ",";
        first = false;

        char entry[512];
        _snprintf_s(entry, sizeof(entry), _TRUNCATE,
            "{\"remote\":\"%s\","
            "\"port\":%u,"
            "\"proto\":\"%s\","
            "\"hits\":%llu,"
            "\"pids\":[",
            IpToString(conn.RemoteAddr).c_str(),
            (unsigned)conn.RemotePort,
            conn.Protocol == 6 ? "TCP" : (conn.Protocol == 17 ? "UDP" : "Other"),
            conn.ConnectionCount);

        json += entry;

        /* PID list */
        bool firstPid = true;
        for (ULONG pid : conn.Pids) {
            if (!firstPid) json += ",";
            firstPid = false;
            json += std::to_string(pid);
        }

        json += "]}";
    }

    json += "]}";
    return json;
}

std::string
CommandHandler::HandleProcesses()
{
    std::vector<ProcessEntry> entries;
    m_processor->GetProcessTable().GetSnapshot(entries);

    std::string json = "{\"count\":";
    json += std::to_string(entries.size());
    json += ",\"processes\":[";

    bool first = true;
    for (const auto& proc : entries) {
        if (!first) json += ",";
        first = false;

        std::string imagePath = NarrowPath(proc.ImagePath);

        char entry[1024];
        _snprintf_s(entry, sizeof(entry), _TRUNCATE,
            "{\"pid\":%lu,"
            "\"ppid\":%lu,"
            "\"image\":\"%s\","
            "\"integrity\":\"%s\","
            "\"elevated\":%s,"
            "\"alive\":%s}",
            proc.Pid,
            proc.ParentPid,
            imagePath.c_str(),
            IntegrityLevelName(proc.IntegrityLevel),
            proc.IsElevated ? "true" : "false",
            proc.Alive ? "true" : "false");

        std::string entryStr = entry;
        JsonEscapeBackslashes(entryStr);
        json += entryStr;
    }

    json += "]}";
    return json;
}

std::string
CommandHandler::HandleHooks()
{
    std::vector<ProcessEntry> entries;
    m_processor->GetProcessTable().GetSnapshot(entries);

    std::string json = "{\"count\":0,\"processes\":[";

    int count = 0;
    bool first = true;
    for (const auto& proc : entries) {
        if (!proc.Alive) continue;  /* Only check alive processes */

        bool hooked = IsModuleLoaded(proc.Pid, L"akesoedr-hook.dll");

        if (!first) json += ",";
        first = false;

        std::string imagePath = NarrowPath(proc.ImagePath);

        char entry[1024];
        _snprintf_s(entry, sizeof(entry), _TRUNCATE,
            "{\"pid\":%lu,"
            "\"image\":\"%s\","
            "\"hooked\":%s}",
            proc.Pid,
            imagePath.c_str(),
            hooked ? "true" : "false");

        std::string entryStr = entry;
        JsonEscapeBackslashes(entryStr);
        json += entryStr;
        count++;
    }

    json += "]}";

    /* Patch the count at the beginning */
    std::string countStr = std::to_string(count);
    size_t countPos = json.find("\"count\":");
    if (countPos != std::string::npos) {
        size_t valStart = countPos + 8;  /* length of "count": */
        size_t valEnd = json.find(',', valStart);
        json.replace(valStart, valEnd - valStart, countStr);
    }

    return json;
}

/* ── Reply helper ────────────────────────────────────────────────────────── */

bool
CommandHandler::SendReply(HANDLE hPipe, UINT32 cmdType, UINT32 status,
                          const std::string& json, UINT32 seqNum)
{
    /*
     * Wire layout:
     *   [UINT32 frame_length]
     *   [AKESOEDR_IPC_COMMAND_REPLY header]
     *   [JSON payload bytes]
     */
    AKESOEDR_IPC_COMMAND_REPLY replyHdr = {};
    UINT32 jsonSize = (UINT32)json.size();
    UINT32 payloadAfterHeader = sizeof(replyHdr) - sizeof(AKESOEDR_IPC_HEADER)
                              + jsonSize;

    AkesoEDRIpcHeaderInit(&replyHdr.Header, AkesoEDRMsgCommandReply,
                          payloadAfterHeader, seqNum);
    replyHdr.CommandType = cmdType;
    replyHdr.Status      = status;
    replyHdr.DataSize    = jsonSize;

    /* Assemble into a single buffer */
    UINT32 totalMsg = sizeof(replyHdr) + jsonSize;
    UINT32 totalFrame = sizeof(UINT32) + totalMsg;

    std::vector<BYTE> buf(totalFrame);

    /* Length prefix */
    *(UINT32*)buf.data() = totalMsg;

    /* Reply header */
    memcpy(buf.data() + sizeof(UINT32), &replyHdr, sizeof(replyHdr));

    /* JSON payload */
    if (jsonSize > 0) {
        memcpy(buf.data() + sizeof(UINT32) + sizeof(replyHdr),
               json.data(), jsonSize);
    }

    DWORD written = 0;
    return WriteFile(hPipe, buf.data(), totalFrame, &written, nullptr) != 0;
}

/* ── HandleConfig (P9-T3) ───────────────────────────────────────────────── */

std::string
CommandHandler::HandleConfig()
{
    if (m_config) {
        return ConfigToJson(*m_config);
    }
    return "{\"error\":\"Configuration not available\"}";
}

/* ── HandleRulesUpdate (P9-T4) ─────────────────────────────────────────── */

std::string
CommandHandler::HandleRulesUpdate()
{
    RulesUpdateResult res = m_processor->ValidateAndReloadRules();

    char buf[2048];

    if (!res.validated) {
        /* Escape the error message for JSON */
        std::string escapedErr;
        for (char c : res.error) {
            if (c == '"')       escapedErr += "\\\"";
            else if (c == '\\') escapedErr += "\\\\";
            else                escapedErr += c;
        }

        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "{\"validated\":false,\"reloaded\":false,"
            "\"error\":\"%s\"}",
            escapedErr.c_str());
    } else {
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "{\"validated\":true,\"reloaded\":true,"
            "\"single\":%d,\"sequence\":%d,"
            "\"threshold\":%d,\"yara\":%d}",
            res.singleCount, res.sequenceCount,
            res.thresholdCount, res.yaraCount);
    }

    return buf;
}
