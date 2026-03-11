/*
 * sentinel-agent/rules/rule_types.h
 * Data structures for parsed detection rules.
 *
 * Rules are loaded from YAML files and evaluated against each incoming
 * SENTINEL_EVENT. Conditions use dot-notation field paths (e.g.,
 * "process.imagePath", "payload.function") and support equals, contains,
 * regex, and greater-than operators.
 *
 * P4-T3: Single-Event Rule Engine.
 */

#ifndef SENTINEL_RULE_TYPES_H
#define SENTINEL_RULE_TYPES_H

#include <string>
#include <vector>
#include "telemetry.h"

/* ── Rule action ─────────────────────────────────────────────────────────── */

enum class RuleAction {
    Log,        /* Default: emit alert event to log */
    Block,      /* Future: block the operation at sensor level */
};

/* ── Condition operator ──────────────────────────────────────────────────── */

enum class ConditionOp {
    Equals,         /* Case-insensitive string equality */
    Contains,       /* Case-insensitive substring search */
    Regex,          /* std::regex match */
    GreaterThan,    /* Numeric comparison (unsigned) */
};

/* ── Single condition ────────────────────────────────────────────────────── */

struct RuleCondition {
    std::string     field;      /* Dot-notation path: "process.imagePath" */
    ConditionOp     op;
    std::string     value;      /* Comparison value */
};

/* ── Detection rule ──────────────────────────────────────────────────────── */

struct DetectionRule {
    std::string                         name;
    std::vector<SENTINEL_EVENT_SOURCE>  sources;    /* Empty = match all */
    std::vector<RuleCondition>          conditions; /* AND logic */
    SENTINEL_SEVERITY                   severity;
    RuleAction                          action;
    bool                                enabled;
};

#endif /* SENTINEL_RULE_TYPES_H */
