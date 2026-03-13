/*
 * sentinel-agent/rules/rule_validator.h
 * Dry-run rule validation without activating.
 *
 * Used by the rules update workflow to validate pulled rules before
 * hot-reloading. If validation fails, the agent keeps old rules and
 * the CLI rolls back the git pull.
 *
 * P9-T4: Rules Update.
 */

#ifndef SENTINEL_RULE_VALIDATOR_H
#define SENTINEL_RULE_VALIDATOR_H

#include <string>

/* ── Validation result ─────────────────────────────────────────────────── */

struct ValidationResult {
    bool        success;
    int         singleCount;
    int         sequenceCount;
    int         thresholdCount;
    int         yaraCount;
    std::string error;      /* Empty on success */
};

/* ── Validation functions ──────────────────────────────────────────────── */

/*
 * Parse all .yaml rule files in rulesDir into temporary vectors.
 * Does NOT activate any rules — purely a dry-run parse.
 * Returns counts and success/failure with error message.
 */
ValidationResult ValidateDetectionRules(const char* rulesDir);

/*
 * Compile all .yar files in yaraRulesDir with a temporary YARA compiler.
 * Does NOT replace the active scanner rules — purely a dry-run compile.
 * Returns rule count and success/failure with error message.
 */
ValidationResult ValidateYaraRules(const char* yaraRulesDir);

#endif /* SENTINEL_RULE_VALIDATOR_H */
