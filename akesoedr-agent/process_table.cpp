/*
 * akesoedr-agent/process_table.cpp
 * In-memory process metadata table implementation.
 *
 * P4-T2: Event Processing & JSON Logging.
 */

#include "process_table.h"
#include <cstring>
#include <algorithm>

/* ── Helper: upsert a process entry from ProcessCtx ──────────────────────── */

void
ProcessTable::UpsertFromProcessCtx(const AKESOEDR_PROCESS_CTX& ctx)
{
    if (ctx.ProcessId == 0) return;

    auto it = m_entries.find(ctx.ProcessId);
    if (it != m_entries.end()) {
        /* Already tracked — update if image path was empty */
        if (it->second.ImagePath.empty() && ctx.ImagePath[0] != L'\0') {
            it->second.ImagePath = ctx.ImagePath;
        }
        if (it->second.CommandLine.empty() && ctx.CommandLine[0] != L'\0') {
            it->second.CommandLine = ctx.CommandLine;
        }
        if (it->second.UserSid.empty() && ctx.UserSid[0] != L'\0') {
            it->second.UserSid = ctx.UserSid;
        }
        return;
    }

    /* New entry */
    ProcessEntry entry = {};
    entry.Pid            = ctx.ProcessId;
    entry.ParentPid      = ctx.ParentProcessId;
    entry.IntegrityLevel = ctx.IntegrityLevel;
    entry.IsElevated     = ctx.IsElevated;
    entry.CreateTime     = ctx.ProcessCreateTime;
    entry.Alive          = true;

    if (ctx.ImagePath[0] != L'\0') {
        entry.ImagePath = ctx.ImagePath;
    }
    if (ctx.CommandLine[0] != L'\0') {
        entry.CommandLine = ctx.CommandLine;
    }
    if (ctx.UserSid[0] != L'\0') {
        entry.UserSid = ctx.UserSid;
    }

    m_entries[ctx.ProcessId] = std::move(entry);
}

/* ── OnEvent ─────────────────────────────────────────────────────────────── */

void
ProcessTable::OnEvent(const AKESOEDR_EVENT& evt)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    /* Handle process creation/termination events from driver */
    if (evt.Source == AkesoEDRSourceDriverProcess) {
        const auto& proc = evt.Payload.Process;

        if (proc.IsCreate) {
            ProcessEntry entry = {};
            entry.Pid            = proc.NewProcessId;
            entry.ParentPid      = proc.ParentProcessId;
            entry.IntegrityLevel = proc.IntegrityLevel;
            entry.IsElevated     = proc.IsElevated;
            entry.CreateTime     = evt.Timestamp;
            entry.Alive          = true;

            if (proc.ImagePath[0] != L'\0') {
                entry.ImagePath = proc.ImagePath;
            }
            if (proc.CommandLine[0] != L'\0') {
                entry.CommandLine = proc.CommandLine;
            }
            if (proc.UserSid[0] != L'\0') {
                entry.UserSid = proc.UserSid;
            }

            m_entries[proc.NewProcessId] = std::move(entry);
        } else {
            /* Terminate — mark dead but keep entry for post-mortem lookups */
            auto it = m_entries.find(proc.NewProcessId);
            if (it != m_entries.end()) {
                it->second.Alive = false;
            }
        }
        return;
    }

    /* For all other events, upsert from ProcessCtx */
    UpsertFromProcessCtx(evt.ProcessCtx);
}

/* ── Lookup ──────────────────────────────────────────────────────────────── */

bool
ProcessTable::Lookup(ULONG pid, ProcessEntry& out)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_entries.find(pid);
    if (it == m_entries.end()) {
        return false;
    }
    out = it->second;
    return true;
}

/* ── GetParentImagePath ──────────────────────────────────────────────────── */

std::wstring
ProcessTable::GetParentImagePath(const AKESOEDR_EVENT& evt)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    ULONG parentPid = evt.ProcessCtx.ParentProcessId;
    if (parentPid == 0) {
        return {};
    }

    auto it = m_entries.find(parentPid);
    if (it == m_entries.end()) {
        return {};
    }

    return it->second.ImagePath;
}

/* ── GetSnapshot ────────────────────────────────────────────────────────── */

void
ProcessTable::GetSnapshot(std::vector<ProcessEntry>& out)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    out.clear();
    out.reserve(m_entries.size());

    for (const auto& kv : m_entries) {
        out.push_back(kv.second);
    }

    std::sort(out.begin(), out.end(),
              [](const ProcessEntry& a, const ProcessEntry& b) {
                  return a.Pid < b.Pid;
              });
}
