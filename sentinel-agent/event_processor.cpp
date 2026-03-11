/*
 * sentinel-agent/event_processor.cpp
 * Event processing orchestrator implementation.
 *
 * P4-T2: Event Processing & JSON Logging.
 */

#include "event_processor.h"
#include <cstdio>

/* ── Init / Shutdown ─────────────────────────────────────────────────────── */

bool
EventProcessor::Init(const char* logPath)
{
    m_eventsProcessed = 0;
    return m_jsonWriter.Open(logPath);
}

void
EventProcessor::Shutdown()
{
    m_jsonWriter.Close();
}

/* ── Process ─────────────────────────────────────────────────────────────── */

void
EventProcessor::Process(const SENTINEL_EVENT& evt)
{
    m_eventsProcessed++;

    /* 1. Update process table from this event */
    m_processTable.OnEvent(evt);

    /* 2. Enrich: look up parent image path */
    std::wstring parentImagePath = m_processTable.GetParentImagePath(evt);

    /* 3. Write JSON to log file */
    m_jsonWriter.WriteEvent(evt, parentImagePath);

    /* 4. Print summary to stdout for console mode */
    PrintSummary(evt);
}

/* ── Console summary ─────────────────────────────────────────────────────── */

void
EventProcessor::PrintSummary(const SENTINEL_EVENT& evt)
{
    if (evt.Source == SentinelSourceHookDll) {
        const auto& hook = evt.Payload.Hook;
        std::printf("[%llu] source=%s func=%s pid=%lu targetPid=%lu "
                    "addr=0x%llx size=0x%llx prot=0x%lx status=0x%08lx\n",
                    m_eventsProcessed,
                    SourceName(evt.Source),
                    HookFunctionName(hook.Function),
                    evt.ProcessCtx.ProcessId,
                    hook.TargetProcessId,
                    (unsigned long long)hook.BaseAddress,
                    (unsigned long long)hook.RegionSize,
                    hook.Protection,
                    hook.ReturnStatus);
    } else if (evt.Source == SentinelSourceDriverProcess) {
        const auto& proc = evt.Payload.Process;
        std::printf("[%llu] source=%s %s pid=%lu ppid=%lu\n",
                    m_eventsProcessed,
                    SourceName(evt.Source),
                    proc.IsCreate ? "CREATE" : "EXIT",
                    proc.NewProcessId,
                    proc.ParentProcessId);
    } else {
        std::printf("[%llu] source=%s pid=%lu\n",
                    m_eventsProcessed,
                    SourceName(evt.Source),
                    evt.ProcessCtx.ProcessId);
    }
}
