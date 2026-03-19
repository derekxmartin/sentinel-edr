/*
 * akesoedr-agent/pipeline.h
 * Event processing pipeline for the AkesoEDR agent.
 *
 * Architecture:
 *   Driver port receiver thread  ──┐
 *                                  │
 *   Pipe server receiver thread(s)─┼──► EventQueue ──► Processing thread
 *                                  │
 *   ETW consumer thread           ─┘
 *
 * The pipeline receives AKESOEDR_EVENT from three sources:
 *   1. Driver filter communication port (\AkesoEDRPort)
 *   2. Named pipe from hook DLLs (\\.\pipe\AkesoEDRTelemetry)
 *   3. ETW real-time trace session (e.g. .NET Runtime assembly loads)
 *
 * All events are funneled into a thread-safe EventQueue and consumed
 * by a processing thread (currently logs to file; future phases add
 * rule evaluation and alerting).
 */

#ifndef AKESOEDR_PIPELINE_H
#define AKESOEDR_PIPELINE_H

#include <windows.h>
#include <deque>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include "telemetry.h"

struct AkesoEDRConfig;  /* Forward declaration (defined in config.h) */

/* ── Thread-safe event queue ──────────────────────────────────────────────── */

class EventQueue {
public:
    /* Push an event into the queue. Thread-safe. */
    void Push(const AKESOEDR_EVENT& evt);

    /*
     * Pop an event from the queue. Blocks up to timeoutMs.
     * Returns true if an event was dequeued, false on timeout or shutdown.
     */
    bool Pop(AKESOEDR_EVENT& evt, DWORD timeoutMs);

    /* Signal shutdown — wake all waiting consumers. */
    void Shutdown();

    /* Get current queue depth (approximate). */
    size_t Size();

private:
    std::deque<AKESOEDR_EVENT>  m_queue;
    std::mutex                  m_mutex;
    std::condition_variable     m_cv;
    bool                        m_shutdown = false;
};

/* ── Global pipeline objects (defined in pipeline.cpp) ────────────────────── */

/*
 * Exposed for sub-components (ETW consumer, pipe server) that need to
 * push events into the queue from their own threads.
 */
extern EventQueue        g_EventQueue;
extern std::atomic<bool> g_Shutdown;

/* ── Pipeline lifecycle ───────────────────────────────────────────────────── */

/*
 * Start all pipeline threads:
 *   - Driver port receiver
 *   - Named pipe server (listener + per-client handlers)
 *   - Event processing thread
 */
void PipelineStart(const AkesoEDRConfig& cfg);

/*
 * Stop all pipeline threads with graceful shutdown (5 second timeout).
 * Drains remaining events before exiting.
 */
void PipelineStop();

#endif /* AKESOEDR_PIPELINE_H */
