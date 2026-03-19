/*
 * akesoedr-agent/service.h
 * Windows service framework for the AkesoEDR agent.
 *
 * The agent runs as a Windows service (SERVICE_WIN32_OWN_PROCESS).
 * ServiceMain is registered with the SCM via StartServiceCtrlDispatcher.
 * The --console flag bypasses the SCM for debugging.
 *
 * P9-T3: RunConsoleMode now accepts a AkesoEDRConfig reference.
 */

#ifndef AKESOEDR_SERVICE_H
#define AKESOEDR_SERVICE_H

#include <windows.h>

struct AkesoEDRConfig;  /* Forward declaration (defined in config.h) */

/*
 * ServiceMain — SCM entry point.
 * Registered via SERVICE_TABLE_ENTRY in main().
 */
void WINAPI ServiceMain(DWORD argc, LPWSTR* argv);

/*
 * RunConsoleMode — Run the agent as a console application for debugging.
 * Ctrl+C triggers graceful shutdown.
 */
void RunConsoleMode(const AkesoEDRConfig& cfg);

/*
 * GetAgentConfig — Access the file-scope config loaded in main().
 * Used by ServiceMain to pass config into PipelineStart.
 */
const AkesoEDRConfig& GetAgentConfig();

#endif /* AKESOEDR_SERVICE_H */
