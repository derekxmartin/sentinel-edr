/*
 * sentinel-agent/service.h
 * Windows service framework for the SentinelEDR agent.
 *
 * The agent runs as a Windows service (SERVICE_WIN32_OWN_PROCESS).
 * ServiceMain is registered with the SCM via StartServiceCtrlDispatcher.
 * The --console flag bypasses the SCM for debugging.
 *
 * P9-T3: RunConsoleMode now accepts a SentinelConfig reference.
 */

#ifndef SENTINEL_SERVICE_H
#define SENTINEL_SERVICE_H

#include <windows.h>

struct SentinelConfig;  /* Forward declaration (defined in config.h) */

/*
 * ServiceMain — SCM entry point.
 * Registered via SERVICE_TABLE_ENTRY in main().
 */
void WINAPI ServiceMain(DWORD argc, LPWSTR* argv);

/*
 * RunConsoleMode — Run the agent as a console application for debugging.
 * Ctrl+C triggers graceful shutdown.
 */
void RunConsoleMode(const SentinelConfig& cfg);

/*
 * GetAgentConfig — Access the file-scope config loaded in main().
 * Used by ServiceMain to pass config into PipelineStart.
 */
const SentinelConfig& GetAgentConfig();

#endif /* SENTINEL_SERVICE_H */
