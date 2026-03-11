/*
 * sentinel-agent/rules/threshold_engine.cpp
 * Threshold-based detection engine implementation.
 *
 * P4-T5: Threshold Rule Engine.
 */

#include "threshold_engine.h"
#include "rule_engine.h"
#include "rule_parser.h"
#include "json_writer.h"
#include <cstdio>
#include <algorithm>

/* ── Init ────────────────────────────────────────────────────────────────── */

bool
ThresholdEngine::Init(const std::string& rulesDir)
{
    m_rules.clear();
    m_windows.clear();

    if (!RuleParser::ParseThresholdDirectory(rulesDir, m_rules)) {
        std::fprintf(stderr, "ThresholdEngine: Failed to parse rules dir %s\n",
                     rulesDir.c_str());
        return false;
    }

    /* Remove disabled rules */
    m_rules.erase(
        std::remove_if(m_rules.begin(), m_rules.end(),
                        [](const ThresholdRule& r) { return !r.enabled; }),
        m_rules.end());

    /* Allocate one window map per rule */
    m_windows.resize(m_rules.size());

    std::printf("SentinelAgent: Loaded %zu threshold rule(s)\n",
                m_rules.size());

    for (const auto& rule : m_rules) {
        std::printf("  - [THR] %s [%s] (>=%u in %lums, %s)\n",
                    rule.name.c_str(),
                    SeverityName(rule.severity),
                    rule.threshold,
                    rule.windowMs,
                    rule.perProcess ? "per-PID" : "global");
    }

    return true;
}

/* ── Evaluate ────────────────────────────────────────────────────────────── */

void
ThresholdEngine::Evaluate(const SENTINEL_EVENT& evt,
                           ProcessTable& processTable,
                           std::vector<SENTINEL_EVENT>& alerts)
{
    /* Don't evaluate rule engine's own alert events */
    if (evt.Source == SentinelSourceRuleEngine) {
        return;
    }

    std::lock_guard<std::mutex> lock(m_mutex);

    for (size_t ri = 0; ri < m_rules.size(); ++ri) {
        const auto& rule = m_rules[ri];

        /* Check source filter */
        if (!rule.sources.empty()) {
            bool sourceMatch = false;
            for (auto src : rule.sources) {
                if (evt.Source == src) {
                    sourceMatch = true;
                    break;
                }
            }
            if (!sourceMatch) continue;
        }

        /* Check if event matches filter conditions */
        if (!MatchesFilter(evt, rule, processTable)) {
            continue;
        }

        /* Determine grouping key: PID or 0 for global */
        ULONG key = rule.perProcess ? evt.ProcessCtx.ProcessId : 0;

        auto& windowMap = m_windows[ri];
        auto& q = windowMap[key];

        /* Purge expired timestamps */
        PurgeExpired(q, evt.Timestamp, rule.windowMs);

        /* Add current event timestamp */
        q.push_back(evt.Timestamp);

        /* Check threshold */
        if (q.size() >= rule.threshold) {
            /* Emit alert */
            SENTINEL_EVENT alertEvt = {};
            SentinelEventInit(&alertEvt, SentinelSourceRuleEngine,
                              rule.severity);
            alertEvt.ProcessCtx = evt.ProcessCtx;

            auto& alert = alertEvt.Payload.Alert;
            strncpy_s(alert.RuleName, sizeof(alert.RuleName),
                      rule.name.c_str(), _TRUNCATE);
            alert.Severity = rule.severity;
            alert.TriggerSource = evt.Source;
            alert.TriggerEventId = evt.EventId;

            alerts.push_back(alertEvt);

            /* Clear the window to avoid repeated alerts until next window */
            q.clear();
        }
    }
}

/* ── MatchesFilter ───────────────────────────────────────────────────────── */

bool
ThresholdEngine::MatchesFilter(const SENTINEL_EVENT& evt,
                                const ThresholdRule& rule,
                                ProcessTable& processTable)
{
    for (const auto& cond : rule.conditions) {
        if (!RuleEngine::EvaluateCondition(evt, cond, processTable)) {
            return false;
        }
    }
    return !rule.conditions.empty();
}

/* ── PurgeExpired ────────────────────────────────────────────────────────── */

void
ThresholdEngine::PurgeExpired(std::deque<LARGE_INTEGER>& q,
                               const LARGE_INTEGER& now,
                               DWORD windowMs)
{
    LONGLONG windowTicks = (LONGLONG)windowMs * 10000LL;  /* ms → 100ns */
    while (!q.empty()) {
        LONGLONG elapsed = now.QuadPart - q.front().QuadPart;
        if (elapsed > windowTicks) {
            q.pop_front();
        } else {
            break;  /* Queue is chronological; rest are within window */
        }
    }
}
