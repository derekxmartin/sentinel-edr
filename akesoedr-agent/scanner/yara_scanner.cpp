/*
 * akesoedr-agent/scanner/yara_scanner.cpp
 * YARA scanner implementation.
 *
 * Integrates libyara to scan files and memory buffers against compiled
 * YARA rules. The scanner is initialized once during agent startup and
 * supports hot-reload of rules via Reload().
 *
 * Key YARA API calls:
 *   yr_initialize()          — Global init (reference-counted)
 *   yr_compiler_create()     — Create rule compiler
 *   yr_compiler_add_file()   — Feed .yar source files to compiler
 *   yr_compiler_get_rules()  — Extract compiled rules
 *   yr_rules_scan_file()     — Scan a file on disk
 *   yr_rules_scan_mem()      — Scan an in-memory buffer
 *   yr_rules_destroy()       — Free compiled rules
 *   yr_finalize()            — Global cleanup
 *
 * P8-T1: YARA Scanner Integration.
 * Book reference: Chapter 9 — Scanners.
 */

#include "scanner/yara_scanner.h"
#include "constants.h"

#include <yara.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

/* ── Callback data passed through YARA scan ─────────────────────────────── */

struct ScanCallbackData {
    char    firstMatchRule[AKESOEDR_MAX_YARA_MATCH];
    bool    matched;
};

/* ── Compiler error callback ────────────────────────────────────────────── */

static void CompilerErrorCallback(
    int error_level,
    const char* file_name,
    int line_number,
    const YR_RULE* rule,
    const char* message,
    void* user_data)
{
    (void)rule;
    (void)user_data;

    const char* level = (error_level == YARA_ERROR_LEVEL_ERROR)
        ? "ERROR" : "WARNING";

    std::printf("[YARA] %s: %s:%d: %s\n",
                level,
                file_name ? file_name : "(unknown)",
                line_number,
                message ? message : "(no message)");
}

/* ── Constructor / Destructor ───────────────────────────────────────────── */

YaraScanner::YaraScanner()
    : m_rules(nullptr)
    , m_maxFileSize(50 * 1024 * 1024)
    , m_initialized(false)
    , m_ruleCount(0)
{
}

YaraScanner::~YaraScanner()
{
    Shutdown();
}

/* ── Init / Shutdown ────────────────────────────────────────────────────── */

bool
YaraScanner::Init(const char* rulesDir, UINT32 maxFileSize)
{
    if (m_initialized) return true;

    int rc = yr_initialize();
    if (rc != ERROR_SUCCESS) {
        std::printf("[YARA] yr_initialize() failed: %d\n", rc);
        return false;
    }

    m_initialized = true;
    m_rulesDir = rulesDir;
    m_maxFileSize = maxFileSize;

    /* Compile rules from directory */
    m_rules = CompileRulesFromDir(m_ruleCount);

    if (!m_rules) {
        std::printf("[YARA] No rules compiled from %s\n", rulesDir);
    } else {
        std::printf("[YARA] Scanner loaded %d rules from %s\n",
                    m_ruleCount, rulesDir);
    }

    return true;
}

void
YaraScanner::Shutdown()
{
    if (!m_initialized) return;

    {
        std::unique_lock<std::shared_mutex> lock(m_rulesMutex);
        if (m_rules) {
            yr_rules_destroy(m_rules);
            m_rules = nullptr;
        }
        m_ruleCount = 0;
    }

    yr_finalize();
    m_initialized = false;
}

/* ── ScanFile ───────────────────────────────────────────────────────────── */

bool
YaraScanner::ScanFile(const wchar_t* filePath,
                      AKESOEDR_SCAN_TYPE scanType,
                      AKESOEDR_SCANNER_EVENT& result)
{
    /* Initialize result */
    memset(&result, 0, sizeof(result));
    result.ScanType = scanType;
    result.IsMatch = FALSE;

    if (filePath) {
        wcsncpy_s(result.TargetPath, AKESOEDR_MAX_PATH, filePath, _TRUNCATE);
    }

    std::shared_lock<std::shared_mutex> lock(m_rulesMutex);

    if (!m_rules) return false;

    /* Convert wide path to UTF-8 for YARA API */
    char utf8Path[AKESOEDR_MAX_PATH * 3];
    int len = WideCharToMultiByte(
        CP_UTF8, 0, filePath, -1,
        utf8Path, sizeof(utf8Path), nullptr, nullptr);

    if (len <= 0) {
        std::printf("[YARA] Failed to convert path to UTF-8\n");
        return false;
    }

    /* Check file size before scanning */
    HANDLE hFile = CreateFileW(
        filePath, GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

    if (hFile == INVALID_HANDLE_VALUE) {
        return false;   /* File not accessible */
    }

    LARGE_INTEGER fileSize;
    if (GetFileSizeEx(hFile, &fileSize)) {
        CloseHandle(hFile);
        if (fileSize.QuadPart > m_maxFileSize) {
            return true;    /* Skip oversized file, not an error */
        }
    } else {
        CloseHandle(hFile);
    }

    /* Run YARA scan */
    ScanCallbackData cbData = {};
    cbData.matched = false;

    int rc = yr_rules_scan_file(
        m_rules,
        utf8Path,
        0,                          /* flags */
        YaraScanCallback,
        &cbData,
        10                          /* timeout in seconds */
    );

    if (rc != ERROR_SUCCESS) {
        /* Non-fatal: file may be locked or inaccessible */
        return false;
    }

    if (cbData.matched) {
        result.IsMatch = TRUE;
        strncpy_s(result.YaraRule, sizeof(result.YaraRule),
                  cbData.firstMatchRule, _TRUNCATE);
    }

    return true;
}

/* ── ScanBuffer ─────────────────────────────────────────────────────────── */

bool
YaraScanner::ScanBuffer(const uint8_t* data, size_t size,
                        AKESOEDR_SCANNER_EVENT& result)
{
    /* Initialize result */
    memset(&result, 0, sizeof(result));
    result.ScanType = AkesoEDRScanMemory;
    result.IsMatch = FALSE;

    std::shared_lock<std::shared_mutex> lock(m_rulesMutex);

    if (!m_rules || !data || size == 0) return false;

    ScanCallbackData cbData = {};
    cbData.matched = false;

    int rc = yr_rules_scan_mem(
        m_rules,
        data,
        size,
        0,                          /* flags */
        YaraScanCallback,
        &cbData,
        10                          /* timeout in seconds */
    );

    if (rc != ERROR_SUCCESS) {
        return false;
    }

    if (cbData.matched) {
        result.IsMatch = TRUE;
        strncpy_s(result.YaraRule, sizeof(result.YaraRule),
                  cbData.firstMatchRule, _TRUNCATE);
    }

    return true;
}

/* ── Reload ─────────────────────────────────────────────────────────────── */

bool
YaraScanner::Reload()
{
    if (!m_initialized) return false;

    /* Compile new rules BEFORE taking the exclusive lock.
     * This minimizes the time scans are blocked during reload. */
    int newCount = 0;
    YR_RULES* newRules = CompileRulesFromDir(newCount);

    if (!newRules) {
        std::printf("[YARA] Reload failed: compilation error (old rules kept)\n");
        return false;
    }

    /* Swap under exclusive lock */
    YR_RULES* oldRules;
    {
        std::unique_lock<std::shared_mutex> lock(m_rulesMutex);
        oldRules = m_rules;
        m_rules = newRules;
        m_ruleCount = newCount;
    }

    /* Destroy old rules outside the lock */
    if (oldRules) {
        yr_rules_destroy(oldRules);
    }

    std::printf("[YARA] Reloaded: %d rules from %s\n",
                newCount, m_rulesDir.c_str());
    return true;
}

/* ── Accessors ──────────────────────────────────────────────────────────── */

int
YaraScanner::RuleCount() const
{
    std::shared_lock<std::shared_mutex> lock(m_rulesMutex);
    return m_ruleCount;
}

bool
YaraScanner::IsReady() const
{
    std::shared_lock<std::shared_mutex> lock(m_rulesMutex);
    return m_initialized && m_rules != nullptr;
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
        if (strcmp(findData.cFileName, ".") == 0 ||
            strcmp(findData.cFileName, "..") == 0)
            continue;

        std::string fullPath = dir + "\\" + findData.cFileName;

        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (strcmp(findData.cFileName, ".git") != 0) {
                FindYarFilesRecursive(fullPath, out);
            }
            continue;
        }

        size_t len = strlen(findData.cFileName);
        bool isYar = (len > 4 && _stricmp(findData.cFileName + len - 4, ".yar") == 0) ||
                     (len > 5 && _stricmp(findData.cFileName + len - 5, ".yara") == 0);

        if (isYar && strstr(findData.cFileName, "index") == nullptr) {
            out.push_back(fullPath);
        }
    } while (FindNextFileA(hFind, &findData));

    FindClose(hFind);
}

/* ── CompileRulesFromDir ────────────────────────────────────────────────── */

YR_RULES*
YaraScanner::CompileRulesFromDir(int& outRuleCount)
{
    outRuleCount = 0;

    /* Recursively find all .yar/.yara files (skip index files) */
    std::vector<std::string> yarFiles;
    FindYarFilesRecursive(m_rulesDir, yarFiles);

    if (yarFiles.empty()) {
        std::printf("[YARA] No .yar files found in %s\n", m_rulesDir.c_str());
        return nullptr;
    }

    /*
     * Two-pass compilation:
     * Pass 1: Test each file independently to identify compatible files.
     * Pass 2: Compile all compatible files into a single YR_RULES.
     *
     * This handles community repos that include rules requiring modules
     * (cuckoo, androguard, etc.) not compiled into our libyara.
     */

    /* Pass 1: filter to compatible files */
    std::vector<std::string> goodFiles;

    for (const auto& filePath : yarFiles) {
        FILE* fp = nullptr;
        fopen_s(&fp, filePath.c_str(), "r");
        if (!fp) continue;

        const char* fileName = strrchr(filePath.c_str(), '\\');
        fileName = fileName ? fileName + 1 : filePath.c_str();

        YR_COMPILER* testCompiler = nullptr;
        int rc = yr_compiler_create(&testCompiler);
        if (rc != ERROR_SUCCESS || !testCompiler) {
            fclose(fp);
            continue;
        }

        /* Silence errors during probe */
        yr_compiler_set_callback(testCompiler, CompilerErrorCallback, nullptr);

        int errors = yr_compiler_add_file(testCompiler, fp, nullptr, fileName);
        fclose(fp);
        yr_compiler_destroy(testCompiler);

        if (errors == 0) {
            goodFiles.push_back(filePath);
        } else {
            std::printf("[YARA] Skipping incompatible: %s\n", fileName);
        }
    }

    if (goodFiles.empty()) {
        std::printf("[YARA] No compatible .yar files in %s\n",
                    m_rulesDir.c_str());
        return nullptr;
    }

    std::printf("[YARA] %zu/%zu files compatible\n",
                goodFiles.size(), yarFiles.size());

    /* Pass 2: compile all compatible files into one ruleset */
    YR_COMPILER* compiler = nullptr;
    int rc = yr_compiler_create(&compiler);

    if (rc != ERROR_SUCCESS || !compiler) {
        std::printf("[YARA] yr_compiler_create() failed: %d\n", rc);
        return nullptr;
    }

    yr_compiler_set_callback(compiler, CompilerErrorCallback, nullptr);

    for (const auto& filePath : goodFiles) {
        FILE* fp = nullptr;
        fopen_s(&fp, filePath.c_str(), "r");
        if (!fp) continue;

        const char* fileName = strrchr(filePath.c_str(), '\\');
        fileName = fileName ? fileName + 1 : filePath.c_str();

        yr_compiler_add_file(compiler, fp, nullptr, fileName);
        fclose(fp);
    }

    /* Extract compiled rules */
    YR_RULES* rules = nullptr;
    rc = yr_compiler_get_rules(compiler, &rules);
    yr_compiler_destroy(compiler);

    if (rc != ERROR_SUCCESS || !rules) {
        std::printf("[YARA] yr_compiler_get_rules() failed: %d\n", rc);
        return nullptr;
    }

    /* Count rules by iterating */
    YR_RULE* rule;
    int count = 0;
    yr_rules_foreach(rules, rule) {
        count++;
    }

    outRuleCount = count;
    return rules;
}

/* ── YARA scan callback ─────────────────────────────────────────────────── */

int
YaraScanner::YaraScanCallback(
    YR_SCAN_CONTEXT* context,
    int message,
    void* message_data,
    void* user_data)
{
    (void)context;

    auto* cbData = static_cast<ScanCallbackData*>(user_data);

    if (message == CALLBACK_MSG_RULE_MATCHING) {
        auto* rule = static_cast<YR_RULE*>(message_data);

        if (!cbData->matched && rule->identifier) {
            strncpy_s(cbData->firstMatchRule,
                      sizeof(cbData->firstMatchRule),
                      rule->identifier, _TRUNCATE);
            cbData->matched = true;
        }
    }

    return CALLBACK_CONTINUE;
}
