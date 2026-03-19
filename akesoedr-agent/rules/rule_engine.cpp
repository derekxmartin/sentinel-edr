/*
 * akesoedr-agent/rules/rule_engine.cpp
 * Single-event detection rule engine implementation.
 *
 * P4-T3: Single-Event Rule Engine.
 */

#include "rule_engine.h"
#include "rule_parser.h"
#include "json_writer.h"
#include <cstdio>
#include <algorithm>
#include <regex>
#include <objbase.h>

/* ── Case-insensitive helpers ────────────────────────────────────────────── */

static std::string
ToLowerStr(const std::string& s)
{
    std::string result = s;
    std::transform(result.begin(), result.end(), result.begin(),
                   [](unsigned char c) { return (char)std::tolower(c); });
    return result;
}

/* ── WcharToUtf8 (local copy to avoid json_writer internal dependency) ──── */

static std::string
WToUtf8(const WCHAR* ws)
{
    if (ws == nullptr || ws[0] == L'\0') return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, ws, -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) return {};
    std::string result(len - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, ws, -1, &result[0], len, nullptr, nullptr);
    return result;
}

static std::string
PointerToHex(ULONG_PTR ptr)
{
    char buf[24];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE, "0x%llx", (unsigned long long)ptr);
    return buf;
}

static std::string
DwordToHex(ULONG val)
{
    char buf[16];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE, "0x%lx", val);
    return buf;
}

static std::string
UlongToStr(ULONG val)
{
    char buf[16];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE, "%lu", val);
    return buf;
}

static std::string
BoolToStr(BOOLEAN val)
{
    return val ? "true" : "false";
}

/* ── Init ────────────────────────────────────────────────────────────────── */

bool
RuleEngine::Init(const std::string& rulesDir)
{
    m_rules.clear();

    if (!RuleParser::ParseDirectory(rulesDir, m_rules)) {
        std::fprintf(stderr, "RuleEngine: Failed to parse rules directory %s\n",
                     rulesDir.c_str());
        return false;
    }

    /* Remove disabled rules */
    m_rules.erase(
        std::remove_if(m_rules.begin(), m_rules.end(),
                        [](const DetectionRule& r) { return !r.enabled; }),
        m_rules.end());

    std::printf("AkesoEDRAgent: Loaded %zu detection rule(s)\n",
                m_rules.size());

    for (const auto& rule : m_rules) {
        std::printf("  - %s [%s] (%zu condition%s)\n",
                    rule.name.c_str(),
                    SeverityName(rule.severity),
                    rule.conditions.size(),
                    rule.conditions.size() == 1 ? "" : "s");
    }

    return true;
}

/* ── Evaluate ────────────────────────────────────────────────────────────── */

void
RuleEngine::Evaluate(const AKESOEDR_EVENT& evt,
                     ProcessTable& processTable,
                     std::vector<AKESOEDR_EVENT>& alerts)
{
    /* Don't evaluate rule engine's own alert events (prevent recursion) */
    if (evt.Source == AkesoEDRSourceRuleEngine) {
        return;
    }

    for (const auto& rule : m_rules) {
        if (MatchesRule(evt, rule, processTable)) {
            /* Create alert event */
            AKESOEDR_EVENT alertEvt = {};
            AkesoEDREventInit(&alertEvt, AkesoEDRSourceRuleEngine,
                              rule.severity);

            /* Copy process context from trigger event */
            alertEvt.ProcessCtx = evt.ProcessCtx;

            /* Fill alert payload */
            auto& alert = alertEvt.Payload.Alert;
            strncpy_s(alert.RuleName, sizeof(alert.RuleName),
                      rule.name.c_str(), _TRUNCATE);
            alert.Severity = rule.severity;
            alert.TriggerSource = evt.Source;
            alert.TriggerEventId = evt.EventId;

            alerts.push_back(alertEvt);
        }
    }
}

/* ── MatchesRule ──────────────────────────────────────────────────────────── */

bool
RuleEngine::MatchesRule(const AKESOEDR_EVENT& evt,
                        const DetectionRule& rule,
                        ProcessTable& processTable)
{
    /* Check source filter */
    if (!rule.sources.empty()) {
        bool sourceMatch = false;
        for (auto src : rule.sources) {
            if (evt.Source == src) {
                sourceMatch = true;
                break;
            }
        }
        if (!sourceMatch) return false;
    }

    /* All conditions must match (AND logic) */
    for (const auto& cond : rule.conditions) {
        if (!EvaluateCondition(evt, cond, processTable)) {
            return false;
        }
    }

    return true;
}

/* ── EvaluateCondition ───────────────────────────────────────────────────── */

bool
RuleEngine::EvaluateCondition(const AKESOEDR_EVENT& evt,
                              const RuleCondition& cond,
                              ProcessTable& processTable)
{
    std::string fieldVal = ResolveField(evt, cond.field, processTable);

    switch (cond.op) {
    case ConditionOp::Equals: {
        return ToLowerStr(fieldVal) == ToLowerStr(cond.value);
    }

    case ConditionOp::Contains: {
        std::string lowerField = ToLowerStr(fieldVal);
        std::string lowerValue = ToLowerStr(cond.value);
        return lowerField.find(lowerValue) != std::string::npos;
    }

    case ConditionOp::Regex: {
        try {
            std::regex re(cond.value,
                          std::regex_constants::ECMAScript |
                          std::regex_constants::icase);
            return std::regex_search(fieldVal, re);
        } catch (const std::regex_error&) {
            return false;
        }
    }

    case ConditionOp::GreaterThan: {
        unsigned long long fieldNum = 0, condNum = 0;
        try {
            fieldNum = std::stoull(fieldVal, nullptr, 0);
            condNum = std::stoull(cond.value, nullptr, 0);
        } catch (...) {
            return false;
        }
        return fieldNum > condNum;
    }
    }

    return false;
}

/* ── ResolveField ────────────────────────────────────────────────────────── */

std::string
RuleEngine::ResolveField(const AKESOEDR_EVENT& evt,
                         const std::string& field,
                         ProcessTable& processTable)
{
    /* ── Top-level event fields ─────────────────────────────────────────── */
    if (field == "source")
        return SourceName(evt.Source);
    if (field == "severity")
        return SeverityName(evt.Severity);

    /* ── Process context fields (process.*) ─────────────────────────────── */
    if (field == "process.pid")
        return UlongToStr(evt.ProcessCtx.ProcessId);
    if (field == "process.parentPid")
        return UlongToStr(evt.ProcessCtx.ParentProcessId);
    if (field == "process.threadId")
        return UlongToStr(evt.ProcessCtx.ThreadId);
    if (field == "process.sessionId")
        return UlongToStr(evt.ProcessCtx.SessionId);
    if (field == "process.imagePath")
        return WToUtf8(evt.ProcessCtx.ImagePath);
    if (field == "process.commandLine")
        return WToUtf8(evt.ProcessCtx.CommandLine);
    if (field == "process.userSid")
        return WToUtf8(evt.ProcessCtx.UserSid);
    if (field == "process.integrityLevel")
        return UlongToStr(evt.ProcessCtx.IntegrityLevel);
    if (field == "process.isElevated")
        return BoolToStr(evt.ProcessCtx.IsElevated);

    /* ── Parent process fields (parent.*) via ProcessTable ──────────────── */
    if (field == "parent.imagePath") {
        ProcessEntry parent;
        if (processTable.Lookup(evt.ProcessCtx.ParentProcessId, parent)) {
            return WToUtf8(parent.ImagePath.c_str());
        }
        return {};
    }
    if (field == "parent.commandLine") {
        ProcessEntry parent;
        if (processTable.Lookup(evt.ProcessCtx.ParentProcessId, parent)) {
            return WToUtf8(parent.CommandLine.c_str());
        }
        return {};
    }

    /* ── Hook DLL payload fields (payload.*) ────────────────────────────── */
    if (evt.Source == AkesoEDRSourceHookDll) {
        const auto& hook = evt.Payload.Hook;
        if (field == "payload.function")
            return HookFunctionName(hook.Function);
        if (field == "payload.targetPid")
            return UlongToStr(hook.TargetProcessId);
        if (field == "payload.baseAddress")
            return PointerToHex(hook.BaseAddress);
        if (field == "payload.regionSize")
            return PointerToHex(hook.RegionSize);
        if (field == "payload.protection")
            return DwordToHex(hook.Protection);
        if (field == "payload.allocationType")
            return DwordToHex(hook.AllocationType);
        if (field == "payload.returnAddress")
            return PointerToHex(hook.ReturnAddress);
        if (field == "payload.callingModule")
            return WToUtf8(hook.CallingModule);
        if (field == "payload.stackHash")
            return DwordToHex(hook.StackHash);
        if (field == "payload.returnStatus")
            return DwordToHex(hook.ReturnStatus);
    }

    /* ── Driver process payload fields ──────────────────────────────────── */
    if (evt.Source == AkesoEDRSourceDriverProcess) {
        const auto& proc = evt.Payload.Process;
        if (field == "payload.isCreate")
            return BoolToStr(proc.IsCreate);
        if (field == "payload.newProcessId")
            return UlongToStr(proc.NewProcessId);
        if (field == "payload.parentProcessId")
            return UlongToStr(proc.ParentProcessId);
        if (field == "payload.imagePath")
            return WToUtf8(proc.ImagePath);
        if (field == "payload.commandLine")
            return WToUtf8(proc.CommandLine);
        if (field == "payload.userSid")
            return WToUtf8(proc.UserSid);
        if (field == "payload.integrityLevel")
            return UlongToStr(proc.IntegrityLevel);
        if (field == "payload.isElevated")
            return BoolToStr(proc.IsElevated);
        if (field == "payload.exitStatus")
            return DwordToHex(proc.ExitStatus);
    }

    /* ── Driver thread payload fields ───────────────────────────────────── */
    if (evt.Source == AkesoEDRSourceDriverThread) {
        const auto& thread = evt.Payload.Thread;
        if (field == "payload.isCreate")
            return BoolToStr(thread.IsCreate);
        if (field == "payload.threadId")
            return UlongToStr(thread.ThreadId);
        if (field == "payload.owningProcessId")
            return UlongToStr(thread.OwningProcessId);
        if (field == "payload.creatingProcessId")
            return UlongToStr(thread.CreatingProcessId);
        if (field == "payload.startAddress")
            return PointerToHex(thread.StartAddress);
        if (field == "payload.isRemote")
            return BoolToStr(thread.IsRemote);
    }

    /* ── Driver object payload fields ───────────────────────────────────── */
    if (evt.Source == AkesoEDRSourceDriverObject) {
        const auto& obj = evt.Payload.Object;
        if (field == "payload.sourceProcessId")
            return UlongToStr(obj.SourceProcessId);
        if (field == "payload.targetProcessId")
            return UlongToStr(obj.TargetProcessId);
        if (field == "payload.targetImagePath")
            return WToUtf8(obj.TargetImagePath);
        if (field == "payload.desiredAccess")
            return DwordToHex(obj.DesiredAccess);
        if (field == "payload.grantedAccess")
            return DwordToHex(obj.GrantedAccess);
    }

    /* ── Driver image load payload fields ───────────────────────────────── */
    if (evt.Source == AkesoEDRSourceDriverImageLoad) {
        const auto& img = evt.Payload.ImageLoad;
        if (field == "payload.processId")
            return UlongToStr(img.ProcessId);
        if (field == "payload.imagePath")
            return WToUtf8(img.ImagePath);
        if (field == "payload.imageBase")
            return PointerToHex(img.ImageBase);
        if (field == "payload.imageSize")
            return PointerToHex(img.ImageSize);
        if (field == "payload.isSigned")
            return BoolToStr(img.IsSigned);
    }

    /* ── Driver registry payload fields ─────────────────────────────────── */
    if (evt.Source == AkesoEDRSourceDriverRegistry) {
        const auto& reg = evt.Payload.Registry;
        if (field == "payload.keyPath")
            return WToUtf8(reg.KeyPath);
        if (field == "payload.valueName")
            return WToUtf8(reg.ValueName);
        if (field == "payload.dataType")
            return UlongToStr(reg.DataType);
    }

    /* ── Driver minifilter (file) payload fields ────────────────────────── */
    if (evt.Source == AkesoEDRSourceDriverMinifilter) {
        const auto& file = evt.Payload.File;
        if (field == "payload.filePath")
            return WToUtf8(file.FilePath);
        if (field == "payload.newFilePath")
            return WToUtf8(file.NewFilePath);
        if (field == "payload.processId")
            return UlongToStr(file.RequestingProcessId);
    }

    /* ── Network payload fields ─────────────────────────────────────────── */
    if (evt.Source == AkesoEDRSourceDriverNetwork) {
        const auto& net = evt.Payload.Network;
        if (field == "payload.processId")
            return UlongToStr(net.ProcessId);
        if (field == "payload.localPort")
            return UlongToStr(net.LocalPort);
        if (field == "payload.remotePort")
            return UlongToStr(net.RemotePort);
        if (field == "payload.protocol")
            return UlongToStr(net.Protocol);
    }

    return {};  /* Unknown field */
}
