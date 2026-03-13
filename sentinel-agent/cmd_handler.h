/*
 * sentinel-agent/cmd_handler.h
 * Command pipe server for CLI → agent communication.
 *
 * Listens on \\.\pipe\SentinelCommand for CLI connections.
 * Dispatches commands to EventProcessor and returns JSON replies.
 *
 * P9-T1: Core CLI Commands.
 * P9-T2: Inspection Commands (connections, processes, hooks).
 * P9-T3: Configuration query command.
 * P9-T4: Rules update (validate-and-reload).
 * Book reference: Chapter 1 — Agent Design.
 */

#ifndef SENTINEL_CMD_HANDLER_H
#define SENTINEL_CMD_HANDLER_H

#include <windows.h>
#include <thread>
#include <atomic>
#include <functional>
#include <string>

/* Forward declarations */
class EventProcessor;
struct SentinelConfig;

class CommandHandler {
public:
    /*
     * Start the command pipe server thread.
     * processor: pointer to the EventProcessor for querying state.
     * driverStatusFn: callback that returns true if the driver port is connected.
     * config: pointer to active configuration (for config query command).
     */
    void Start(EventProcessor* processor,
               std::function<bool()> driverStatusFn,
               const SentinelConfig* config = nullptr);

    /* Stop the command pipe server and join the thread. */
    void Stop();

private:
    EventProcessor*         m_processor = nullptr;
    const SentinelConfig*   m_config    = nullptr;
    std::function<bool()>   m_driverStatusFn;
    std::thread             m_thread;
    std::atomic<bool>       m_running{false};
    HANDLE                  m_shutdownEvent = nullptr;
    HANDLE                  m_activePipe    = INVALID_HANDLE_VALUE;
    ULONGLONG               m_startTime     = 0;

    void ServerThread();

    /* Handle a single connected CLI client. */
    void HandleClient(HANDLE hPipe);

    /* Command dispatch — returns JSON response string. */
    std::string HandleStatus();
    std::string HandleAlerts(const wchar_t* arg);
    std::string HandleScan(const wchar_t* arg);
    std::string HandleRulesReload();

    /* P9-T2: Inspection commands */
    std::string HandleConnections();
    std::string HandleProcesses();
    std::string HandleHooks();

    /* P9-T3: Configuration query */
    std::string HandleConfig();

    /* P9-T4: Rules update (validate + reload) */
    std::string HandleRulesUpdate();

    /* Send a SENTINEL_IPC_COMMAND_REPLY with JSON payload. */
    bool SendReply(HANDLE hPipe, UINT32 cmdType, UINT32 status,
                   const std::string& json, UINT32 seqNum);
};

#endif /* SENTINEL_CMD_HANDLER_H */
