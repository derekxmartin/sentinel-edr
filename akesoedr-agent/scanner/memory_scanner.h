/*
 * akesoedr-agent/scanner/memory_scanner.h
 * Process memory scanner for unbacked executable regions.
 *
 * Enumerates a target process's virtual address space, identifies
 * MEM_PRIVATE regions with executable protection (not backed by
 * image files), reads their contents, and scans against YARA rules.
 *
 * Triggered by the sequence rule engine when a shellcode injection
 * pattern is detected (alloc RW -> protect RX -> create thread).
 *
 * Thread safety:
 *   ScanProcess() is called from the single ProcessorThread,
 *   so no internal synchronization is needed.
 *
 * P8-T3: Memory Scanner.
 * Book reference: Chapter 9 -- Scanners.
 */

#ifndef AKESOEDR_MEMORY_SCANNER_H
#define AKESOEDR_MEMORY_SCANNER_H

#include <windows.h>
#include "telemetry.h"

/* Forward declaration -- avoids pulling in yara.h transitively */
class YaraScanner;

class MemoryScanner {
public:
    /*
     * Bind to a YaraScanner instance (owned by EventProcessor).
     * maxRegionSize: skip memory regions larger than this (bytes).
     * Must be called after YaraScanner::Init().
     */
    void Init(YaraScanner* scanner, UINT32 maxRegionSize);

    /* Release resources. */
    void Shutdown();

    /*
     * Scan a target process for unbacked executable memory regions.
     *
     * Enumerates virtual memory via VirtualQueryEx, filters for
     * MEM_PRIVATE + PAGE_EXECUTE_* regions, reads contents via
     * ReadProcessMemory, and scans against YARA rules.
     *
     * Returns true if a YARA match is found; populates alertOut as
     * a AkesoEDRSourceScanner event with AkesoEDRScanMemory type.
     * Returns false if no match or on error (process inaccessible).
     */
    bool ScanProcess(ULONG targetPid, AKESOEDR_EVENT& alertOut);

    /* Whether the scanner has a valid YaraScanner with loaded rules. */
    bool IsReady() const;

private:
    YaraScanner* m_scanner        = nullptr;
    UINT32       m_maxRegionSize = 10 * 1024 * 1024;
};

#endif /* AKESOEDR_MEMORY_SCANNER_H */
