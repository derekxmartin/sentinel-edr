/*
 * sentinel-agent/scanner/yara_scanner.h
 * YARA scanner module.
 *
 * Wraps libyara to provide file and buffer scanning against compiled
 * YARA rules. Supports concurrent scanning (via shared_mutex) and
 * hot-reload of rules without agent restart.
 *
 * Thread safety:
 *   - ScanFile() and ScanBuffer() acquire a shared lock (concurrent reads).
 *   - Reload() acquires an exclusive lock (blocks until active scans finish,
 *     then swaps the compiled rules pointer atomically).
 *
 * P8-T1: YARA Scanner Integration.
 * Book reference: Chapter 9 — Scanners.
 */

#ifndef SENTINEL_YARA_SCANNER_H
#define SENTINEL_YARA_SCANNER_H

#include <windows.h>
#include <cstdint>
#include <string>
#include <shared_mutex>
#include "telemetry.h"

/* Forward-declare YARA types to avoid exposing yara.h to all consumers */
struct YR_RULES;
struct YR_SCAN_CONTEXT;

class YaraScanner {
public:
    YaraScanner();
    ~YaraScanner();

    /*
     * Initialize the YARA engine and compile rules from the given directory.
     * rulesDir: path containing *.yar files (e.g., "C:\\SentinelPOC\\yara-rules").
     * Returns true on success (even if zero rules loaded — not a fatal error).
     * Returns false if yr_initialize() fails.
     */
    bool Init(const char* rulesDir);

    /*
     * Shut down the YARA engine: destroy compiled rules, call yr_finalize().
     * Safe to call if Init() was never called or already shut down.
     */
    void Shutdown();

    /*
     * Scan a file on disk against loaded YARA rules.
     * Populates result.YaraRule with the first matching rule name.
     * Sets result.IsMatch = TRUE on match, FALSE otherwise.
     * Skips files larger than SENTINEL_SCAN_MAX_FILE_SIZE (50 MB).
     * Returns true if scan completed (regardless of match), false on error.
     */
    bool ScanFile(const wchar_t* filePath,
                  SENTINEL_SCAN_TYPE scanType,
                  SENTINEL_SCANNER_EVENT& result);

    /*
     * Scan an in-memory buffer against loaded YARA rules.
     * Populates result.YaraRule with the first matching rule name.
     * Returns true if scan completed, false on error.
     */
    bool ScanBuffer(const uint8_t* data, size_t size,
                    SENTINEL_SCANNER_EVENT& result);

    /*
     * Hot-reload: recompile all *.yar files from the rules directory.
     * Thread-safe: acquires exclusive lock, compiles new rules first,
     * then swaps the pointer atomically. If compilation fails, old rules
     * remain active and false is returned.
     */
    bool Reload();

    /* Number of compiled YARA rules currently loaded. */
    int RuleCount() const;

    /* Whether the scanner is initialized with at least one rule. */
    bool IsReady() const;

private:
    YR_RULES*                   m_rules;
    mutable std::shared_mutex   m_rulesMutex;
    std::string                 m_rulesDir;
    bool                        m_initialized;
    int                         m_ruleCount;

    /*
     * Compile all *.yar files from m_rulesDir into a new YR_RULES*.
     * Returns nullptr if no rules found or compilation fails.
     * Sets outRuleCount to the number of compiled rules.
     */
    YR_RULES* CompileRulesFromDir(int& outRuleCount);

    /*
     * YARA scan callback — invoked for each matching rule.
     * Captures the first match into the user_data struct.
     */
    static int YaraScanCallback(
        YR_SCAN_CONTEXT* context,
        int message,
        void* message_data,
        void* user_data);
};

#endif /* SENTINEL_YARA_SCANNER_H */
