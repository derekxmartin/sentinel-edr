/*
 * sentinel-agent/rules/rule_parser.cpp
 * Simple YAML-subset parser implementation.
 *
 * P4-T3: Single-Event Rule Engine.
 */

#include "rule_parser.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cstdio>
#include <windows.h>

/* ── String helpers ──────────────────────────────────────────────────────── */

std::string
RuleParser::Trim(const std::string& s)
{
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return {};
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

std::string
RuleParser::Unquote(const std::string& s)
{
    if (s.size() >= 2 &&
        ((s.front() == '"' && s.back() == '"') ||
         (s.front() == '\'' && s.back() == '\''))) {
        return s.substr(1, s.size() - 2);
    }
    return s;
}

/* ── Enum parsers ────────────────────────────────────────────────────────── */

static std::string
ToLower(const std::string& s)
{
    std::string result = s;
    std::transform(result.begin(), result.end(), result.begin(),
                   [](unsigned char c) { return (char)std::tolower(c); });
    return result;
}

ConditionOp
RuleParser::ParseOp(const std::string& op)
{
    std::string lower = ToLower(op);
    if (lower == "equals" || lower == "eq" || lower == "==")
        return ConditionOp::Equals;
    if (lower == "contains" || lower == "has")
        return ConditionOp::Contains;
    if (lower == "regex" || lower == "matches")
        return ConditionOp::Regex;
    if (lower == "greater-than" || lower == "gt" || lower == ">")
        return ConditionOp::GreaterThan;
    return ConditionOp::Equals;     /* Default */
}

SENTINEL_SEVERITY
RuleParser::ParseSeverity(const std::string& sev)
{
    std::string lower = ToLower(sev);
    if (lower == "informational" || lower == "info")
        return SentinelSeverityInformational;
    if (lower == "low")
        return SentinelSeverityLow;
    if (lower == "medium" || lower == "med")
        return SentinelSeverityMedium;
    if (lower == "high")
        return SentinelSeverityHigh;
    if (lower == "critical" || lower == "crit")
        return SentinelSeverityCritical;
    return SentinelSeverityMedium;  /* Default */
}

SENTINEL_EVENT_SOURCE
RuleParser::ParseSource(const std::string& src)
{
    std::string lower = ToLower(src);
    if (lower == "driverprocess")   return SentinelSourceDriverProcess;
    if (lower == "driverthread")    return SentinelSourceDriverThread;
    if (lower == "driverobject")    return SentinelSourceDriverObject;
    if (lower == "driverimageload") return SentinelSourceDriverImageLoad;
    if (lower == "driverregistry")  return SentinelSourceDriverRegistry;
    if (lower == "driverminifilter") return SentinelSourceDriverMinifilter;
    if (lower == "drivernetwork")   return SentinelSourceDriverNetwork;
    if (lower == "hookdll")         return SentinelSourceHookDll;
    if (lower == "etw")             return SentinelSourceEtw;
    if (lower == "amsi")            return SentinelSourceAmsi;
    if (lower == "scanner")         return SentinelSourceScanner;
    if (lower == "selfprotect")     return SentinelSourceSelfProtect;
    return SentinelSourceMax;       /* Invalid */
}

RuleAction
RuleParser::ParseAction(const std::string& action)
{
    std::string lower = ToLower(action);
    if (lower == "block") return RuleAction::Block;
    return RuleAction::Log;         /* Default */
}

/* ── Parse a single rule block ───────────────────────────────────────────── */

bool
RuleParser::ParseRule(const std::vector<std::string>& lines, DetectionRule& rule)
{
    rule.severity = SentinelSeverityMedium;
    rule.action = RuleAction::Log;
    rule.enabled = true;

    bool inConditions = false;
    RuleCondition currentCond = {};
    bool hasCond = false;

    for (const auto& rawLine : lines) {
        std::string line = rawLine;

        /* Strip comments */
        size_t commentPos = line.find('#');
        if (commentPos != std::string::npos) {
            line = line.substr(0, commentPos);
        }

        std::string trimmed = Trim(line);
        if (trimmed.empty()) continue;

        /* Check if this is a condition list item (starts with -) */
        bool isListItem = false;
        size_t leadingSpaces = line.find_first_not_of(" \t");
        if (leadingSpaces != std::string::npos && leadingSpaces >= 2 &&
            line[leadingSpaces] == '-') {
            isListItem = true;
        }

        if (isListItem && inConditions) {
            /* Save previous condition if complete */
            if (hasCond && !currentCond.field.empty()) {
                rule.conditions.push_back(currentCond);
            }
            currentCond = {};
            hasCond = true;

            /* Parse "- field: value" */
            std::string content = Trim(trimmed.substr(1)); /* Skip '-' */
            size_t colonPos = content.find(':');
            if (colonPos != std::string::npos) {
                std::string key = Trim(content.substr(0, colonPos));
                std::string val = Trim(content.substr(colonPos + 1));
                val = Unquote(val);

                if (key == "field") currentCond.field = val;
                else if (key == "op") currentCond.op = ParseOp(val);
                else if (key == "value") currentCond.value = val;
            }
        } else if (leadingSpaces != std::string::npos && leadingSpaces >= 4 &&
                   inConditions && !isListItem) {
            /* Continuation of a condition item (indented key: value) */
            size_t colonPos = trimmed.find(':');
            if (colonPos != std::string::npos) {
                std::string key = Trim(trimmed.substr(0, colonPos));
                std::string val = Trim(trimmed.substr(colonPos + 1));
                val = Unquote(val);

                if (key == "field") currentCond.field = val;
                else if (key == "op") currentCond.op = ParseOp(val);
                else if (key == "value") currentCond.value = val;
            }
        } else {
            /* Top-level key: value */
            if (inConditions && hasCond && !currentCond.field.empty()) {
                rule.conditions.push_back(currentCond);
                currentCond = {};
                hasCond = false;
            }
            inConditions = false;

            size_t colonPos = trimmed.find(':');
            if (colonPos == std::string::npos) continue;

            std::string key = Trim(trimmed.substr(0, colonPos));
            std::string val = Trim(trimmed.substr(colonPos + 1));
            val = Unquote(val);

            if (key == "name") {
                rule.name = val;
            } else if (key == "source") {
                /* May be comma-separated */
                std::stringstream ss(val);
                std::string token;
                while (std::getline(ss, token, ',')) {
                    token = Trim(token);
                    auto src = ParseSource(token);
                    if (src != SentinelSourceMax) {
                        rule.sources.push_back(src);
                    }
                }
            } else if (key == "severity") {
                rule.severity = ParseSeverity(val);
            } else if (key == "action") {
                rule.action = ParseAction(val);
            } else if (key == "enabled") {
                rule.enabled = (ToLower(val) != "false" && val != "0");
            } else if (key == "conditions") {
                inConditions = true;
            }
        }
    }

    /* Save last condition */
    if (hasCond && !currentCond.field.empty()) {
        rule.conditions.push_back(currentCond);
    }

    /* Validate: must have a name and at least one condition */
    return !rule.name.empty() && !rule.conditions.empty();
}

/* ── Parse a YAML file ───────────────────────────────────────────────────── */

bool
RuleParser::ParseFile(const std::string& path,
                      std::vector<DetectionRule>& rules)
{
    std::ifstream file(path);
    if (!file.is_open()) {
        std::fprintf(stderr, "RuleParser: Cannot open %s\n", path.c_str());
        return false;
    }

    std::vector<std::string> currentBlock;
    std::string line;

    while (std::getline(file, line)) {
        std::string trimmed = Trim(line);

        /* Document separator — parse accumulated block */
        if (trimmed == "---") {
            if (!currentBlock.empty()) {
                DetectionRule rule;
                if (ParseRule(currentBlock, rule)) {
                    rules.push_back(std::move(rule));
                }
                currentBlock.clear();
            }
            continue;
        }

        currentBlock.push_back(line);
    }

    /* Parse final block */
    if (!currentBlock.empty()) {
        DetectionRule rule;
        if (ParseRule(currentBlock, rule)) {
            rules.push_back(std::move(rule));
        }
    }

    return true;
}

/* ── Parse all YAML files in a directory ──────────────────────────────────── */

bool
RuleParser::ParseDirectory(const std::string& dirPath,
                           std::vector<DetectionRule>& rules)
{
    std::string searchPath = dirPath + "\\*.yaml";
    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA(searchPath.c_str(), &findData);

    if (hFind == INVALID_HANDLE_VALUE) {
        /* Also try .yml extension */
        searchPath = dirPath + "\\*.yml";
        hFind = FindFirstFileA(searchPath.c_str(), &findData);
        if (hFind == INVALID_HANDLE_VALUE) {
            std::fprintf(stderr, "RuleParser: No rule files in %s\n",
                         dirPath.c_str());
            return true;    /* Not an error — just no rules */
        }
    }

    do {
        std::string filePath = dirPath + "\\" + findData.cFileName;
        ParseFile(filePath, rules);
    } while (FindNextFileA(hFind, &findData));

    FindClose(hFind);

    /* Also scan for .yml if we started with .yaml */
    if (searchPath.find(".yaml") != std::string::npos) {
        searchPath = dirPath + "\\*.yml";
        hFind = FindFirstFileA(searchPath.c_str(), &findData);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                std::string filePath = dirPath + "\\" + findData.cFileName;
                ParseFile(filePath, rules);
            } while (FindNextFileA(hFind, &findData));
            FindClose(hFind);
        }
    }

    return true;
}
