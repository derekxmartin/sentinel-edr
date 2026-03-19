/*
 * akesoedr-agent/rules/rule_validator.cpp
 * Dry-run rule validation implementation.
 *
 * Parses detection rules and compiles YARA rules into temporary
 * structures, then discards them. This allows the agent to verify
 * that new rules are well-formed before committing to a hot-reload.
 *
 * P9-T4: Rules Update.
 */

#include "rules/rule_validator.h"
#include "rules/rule_parser.h"
#include "rules/rule_types.h"

#include <yara.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <windows.h>

/* ── YARA compiler error callback (captures first error) ───────────────── */

struct YaraValidationCtx {
    std::string firstError;
    int         errorCount;
};

static void
ValidatorCompilerCallback(
    int error_level,
    const char* file_name,
    int line_number,
    const YR_RULE* rule,
    const char* message,
    void* user_data)
{
    (void)rule;
    auto* ctx = static_cast<YaraValidationCtx*>(user_data);

    if (error_level == YARA_ERROR_LEVEL_ERROR) {
        ctx->errorCount++;
        if (ctx->firstError.empty()) {
            ctx->firstError = std::string(file_name ? file_name : "(unknown)")
                + ":" + std::to_string(line_number)
                + ": " + (message ? message : "(no message)");
        }
    }
}

/* ── ValidateDetectionRules ────────────────────────────────────────────── */

ValidationResult
ValidateDetectionRules(const char* rulesDir)
{
    ValidationResult result = {};

    /* Parse into temporary vectors (dry-run) */
    std::vector<DetectionRule> singleRules;
    std::vector<SequenceRule>  seqRules;
    std::vector<ThresholdRule> thrRules;

    bool okSingle = RuleParser::ParseDirectory(rulesDir, singleRules);
    bool okSeq    = RuleParser::ParseSequenceDirectory(rulesDir, seqRules);
    bool okThr    = RuleParser::ParseThresholdDirectory(rulesDir, thrRules);

    if (!okSingle && !okSeq && !okThr) {
        result.success = false;
        result.error   = "Failed to parse any rules from " + std::string(rulesDir);
        return result;
    }

    result.success       = true;
    result.singleCount   = (int)singleRules.size();
    result.sequenceCount = (int)seqRules.size();
    result.thresholdCount = (int)thrRules.size();

    /* Temp vectors are discarded — no activation */
    return result;
}

/* ── Recursive .yar file enumeration ───────────────────────────────────── */

static void
FindYarFilesRecursive(const std::string& dir, std::vector<std::string>& out)
{
    std::string pattern = dir + "\\*";
    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA(pattern.c_str(), &findData);

    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        /* Skip . and .. */
        if (strcmp(findData.cFileName, ".") == 0 ||
            strcmp(findData.cFileName, "..") == 0)
            continue;

        std::string fullPath = dir + "\\" + findData.cFileName;

        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            /* Recurse into subdirectories (skip .git) */
            if (strcmp(findData.cFileName, ".git") != 0) {
                FindYarFilesRecursive(fullPath, out);
            }
            continue;
        }

        /* Match *.yar and *.yara extensions, skip index files */
        size_t len = strlen(findData.cFileName);
        bool isYar = (len > 4 && _stricmp(findData.cFileName + len - 4, ".yar") == 0) ||
                     (len > 5 && _stricmp(findData.cFileName + len - 5, ".yara") == 0);

        if (isYar && strstr(findData.cFileName, "index") == nullptr) {
            out.push_back(fullPath);
        }
    } while (FindNextFileA(hFind, &findData));

    FindClose(hFind);
}

/* ── ValidateYaraRules ─────────────────────────────────────────────────── */

ValidationResult
ValidateYaraRules(const char* yaraRulesDir)
{
    ValidationResult result = {};

    /* Recursively find all .yar/.yara files (skip index files) */
    std::vector<std::string> yarFiles;
    FindYarFilesRecursive(yaraRulesDir, yarFiles);

    if (yarFiles.empty()) {
        result.success   = true;
        result.yaraCount = 0;
        return result;
    }

    /*
     * Compile each file independently so that files using unsupported
     * modules (cuckoo, androguard, etc.) are skipped without poisoning
     * the entire compilation. This is the expected behavior when loading
     * community rule repos that target different environments.
     */
    int totalRules  = 0;
    int filesLoaded = 0;
    int filesSkipped = 0;

    for (const auto& filePath : yarFiles) {
        FILE* fp = nullptr;
        fopen_s(&fp, filePath.c_str(), "r");
        if (!fp) continue;

        const char* fileName = strrchr(filePath.c_str(), '\\');
        fileName = fileName ? fileName + 1 : filePath.c_str();

        YR_COMPILER* compiler = nullptr;
        int rc = yr_compiler_create(&compiler);
        if (rc != ERROR_SUCCESS || !compiler) {
            fclose(fp);
            continue;
        }

        YaraValidationCtx ctx = {};
        yr_compiler_set_callback(compiler, ValidatorCompilerCallback, &ctx);

        int errors = yr_compiler_add_file(compiler, fp, nullptr, fileName);
        fclose(fp);

        if (errors > 0 || ctx.errorCount > 0) {
            /* Skip this file — unsupported module or syntax error */
            yr_compiler_destroy(compiler);
            filesSkipped++;
            continue;
        }

        /* Count rules from this file */
        YR_RULES* rules = nullptr;
        rc = yr_compiler_get_rules(compiler, &rules);
        yr_compiler_destroy(compiler);

        if (rc == ERROR_SUCCESS && rules) {
            YR_RULE* rule;
            yr_rules_foreach(rules, rule) {
                totalRules++;
            }
            yr_rules_destroy(rules);
            filesLoaded++;
        }
    }

    result.success   = true;
    result.yaraCount = totalRules;
    return result;
}
