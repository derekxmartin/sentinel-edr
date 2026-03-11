/*
 * sentinel-agent/rules/threshold_engine.h
 * Threshold-based detection engine.
 *
 * Counts events matching filter conditions within a sliding time window.
 * When the count exceeds the threshold, an alert is emitted.
 * Supports per-PID or global (all PIDs) counting.
 *
 * P4-T5: Threshold Rule Engine.
 */

#ifndef SENTINEL_THRESHOLD_ENGINE_H
#define SENTINEL_THRESHOLD_ENGINE_H

#include <string>
#include <vector>
#include <deque>
#include <unordered_map>
#include <mutex>
#include "rule_types.h"
#include "process_table.h"

/* ── Threshold engine ──────────────────────────────────────────────────── */

class ThresholdEngine {
public:
    /*
     * Load all threshold rules from .yaml files in the given directory.
     * Returns true even if no threshold rules found.
     */
    bool Init(const std::string& rulesDir);

    /*
     * Evaluate an event against all loaded threshold rules.
     * If a threshold is exceeded, an alert SENTINEL_EVENT is appended.
     */
    void Evaluate(const SENTINEL_EVENT& evt,
                  ProcessTable& processTable,
                  std::vector<SENTINEL_EVENT>& alerts);

    /* Number of loaded threshold rules. */
    size_t RuleCount() const { return m_rules.size(); }

private:
    std::vector<ThresholdRule> m_rules;

    /*
     * Sliding window: per-rule, per-key (PID or 0 for global) queue of
     * event timestamps (FILETIME as LARGE_INTEGER).
     */
    std::vector<std::unordered_map<ULONG, std::deque<LARGE_INTEGER>>> m_windows;
    std::mutex m_mutex;

    /* Check if all conditions in a rule match the event. */
    bool MatchesFilter(const SENTINEL_EVENT& evt,
                       const ThresholdRule& rule,
                       ProcessTable& processTable);

    /* Remove timestamps older than windowMs from a deque. */
    static void PurgeExpired(std::deque<LARGE_INTEGER>& q,
                             const LARGE_INTEGER& now,
                             DWORD windowMs);
};

#endif /* SENTINEL_THRESHOLD_ENGINE_H */
