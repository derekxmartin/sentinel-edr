/*
 * akesoedr-agent/process_table.h
 * In-memory process metadata table for cross-process enrichment.
 *
 * Maintains a PID → ProcessEntry map updated from process creation/termination
 * events. Used by EventProcessor to enrich events with parent process context
 * (e.g., parent image path) that may not be present in the event itself.
 *
 * P4-T2: Event Processing & JSON Logging.
 */

#ifndef AKESOEDR_PROCESS_TABLE_H
#define AKESOEDR_PROCESS_TABLE_H

#include <windows.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include "telemetry.h"

/* ── Process entry ───────────────────────────────────────────────────────── */

struct ProcessEntry {
    ULONG           Pid;
    ULONG           ParentPid;
    std::wstring    ImagePath;
    std::wstring    CommandLine;
    std::wstring    UserSid;
    ULONG           IntegrityLevel;
    BOOLEAN         IsElevated;
    LARGE_INTEGER   CreateTime;
    bool            Alive;
};

/* ── Process table ───────────────────────────────────────────────────────── */

class ProcessTable {
public:
    /*
     * Update the table based on an incoming event.
     * - DriverProcess create → insert/update entry
     * - DriverProcess terminate → mark entry as dead
     * - HookDll events → upsert from ProcessCtx if PID not yet tracked
     */
    void OnEvent(const AKESOEDR_EVENT& evt);

    /* Look up a process entry by PID. Returns true if found. */
    bool Lookup(ULONG pid, ProcessEntry& out);

    /*
     * Get a thread-safe snapshot of all process entries.
     * Entries are sorted by PID ascending.
     */
    void GetSnapshot(std::vector<ProcessEntry>& out);

    /*
     * Look up the parent process and return its image path.
     * Returns empty string if parent not found in table.
     */
    std::wstring GetParentImagePath(const AKESOEDR_EVENT& evt);

private:
    std::unordered_map<ULONG, ProcessEntry> m_entries;
    std::mutex m_mutex;

    void UpsertFromProcessCtx(const AKESOEDR_PROCESS_CTX& ctx);
};

#endif /* AKESOEDR_PROCESS_TABLE_H */
