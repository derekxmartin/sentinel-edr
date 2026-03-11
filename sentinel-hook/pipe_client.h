/*
 * sentinel-hook/pipe_client.h
 * Named pipe client for sending hook events to the agent.
 *
 * The pipe client bridges hook detours (which fire under loader lock)
 * to the agent via \\.\pipe\SentinelTelemetry. It uses a lock-free
 * ring buffer for event capture and a background worker thread for
 * serialization and pipe I/O.
 *
 * Loader-lock safety:
 *   SentinelPipeClientPush is safe to call from hook detours under
 *   loader lock — it uses only InterlockedIncrement, memcpy,
 *   GetSystemTimePreciseAsFileTime, and SetEvent.
 *
 *   The worker thread (which calls CoCreateGuid, CreateFileW, WriteFile)
 *   is created lazily on the first push after DllMain completes.
 */

#ifndef SENTINEL_PIPE_CLIENT_H
#define SENTINEL_PIPE_CLIENT_H

#include <windows.h>
#include "telemetry.h"

/*
 * SentinelPipeClientInit
 *   Initialize pipe client state (events, ring buffer zeroed).
 *   Called from DllMain(DLL_PROCESS_ATTACH). Does NOT create threads.
 */
void SentinelPipeClientInit(void);

/*
 * SentinelPipeClientShutdown
 *   Signal the worker thread to exit, wait up to 2 seconds, close handles.
 *   Called from DllMain(DLL_PROCESS_DETACH).
 */
void SentinelPipeClientShutdown(void);

/*
 * SentinelPipeClientPush
 *   Push a hook event into the ring buffer. Loader-lock safe.
 *   On the first call after hooks are ready, lazily creates the
 *   background worker thread.
 */
void SentinelPipeClientPush(SENTINEL_HOOK_EVENT *evt);

#endif /* SENTINEL_PIPE_CLIENT_H */
