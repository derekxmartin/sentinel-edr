/*
 * common/ipc.h
 * IPC protocol definitions for AkesoEDR.
 *
 * Two transport paths:
 *   1. Driver → Agent:  Filter communication port (FltCreateCommunicationPort)
 *   2. Hook DLL → Agent: Named pipe (\\.\pipe\AkesoEDRTelemetry)
 *   3. CLI → Agent:      Named pipe (\\.\pipe\AkesoEDRCommand)
 *
 * Message framing (both transports):
 *   [4-byte little-endian length] [payload]
 *
 *   The length field contains the size of the payload only (not including
 *   the 4-byte length prefix itself).
 *
 * Protocol:
 *   - Client sends AKESOEDR_IPC_HANDSHAKE as the first message after connect.
 *   - Server validates magic + version, replies with AKESOEDR_IPC_HANDSHAKE_REPLY.
 *   - After handshake, client sends AKESOEDR_IPC_MSG containing events.
 *   - Server may send AKESOEDR_IPC_MSG containing commands (CLI path).
 *   - Either side may send AKESOEDR_IPC_DISCONNECT before closing.
 *
 * Compiles in kernel-mode (C17, WDK), user-mode C17, and user-mode C++20.
 */

#ifndef AKESOEDR_IPC_H
#define AKESOEDR_IPC_H

#ifdef _KERNEL_MODE
    #include <ntddk.h>
#else
    #include <windows.h>
    #ifdef __cplusplus
    extern "C" {
    #endif
#endif

#include "telemetry.h"

/* ── Pipe / port names ───────────────────────────────────────────────────── */

/* Named pipe for hook DLL → agent telemetry */
#define AKESOEDR_PIPE_TELEMETRY     L"\\\\.\\pipe\\AkesoEDRTelemetry"

/* Named pipe for CLI → agent commands */
#define AKESOEDR_PIPE_COMMAND       L"\\\\.\\pipe\\AkesoEDRCommand"

/* Filter communication port for driver → agent */
#define AKESOEDR_FILTER_PORT_NAME   L"\\AkesoEDRPort"

/* ── Protocol constants ──────────────────────────────────────────────────── */

#define AKESOEDR_IPC_MAGIC          0x534E5443  /* 'SNTC' */
#define AKESOEDR_IPC_VERSION        1

/* Maximum message payload size (64 KB — generous for a single event) */
#define AKESOEDR_IPC_MAX_PAYLOAD    (64 * 1024)

/* Maximum number of events that can be batched in a single message */
#define AKESOEDR_IPC_MAX_BATCH      16

/* Named pipe buffer sizes */
#define AKESOEDR_PIPE_IN_BUFFER     (128 * 1024)
#define AKESOEDR_PIPE_OUT_BUFFER    (128 * 1024)

/* Named pipe max instances */
#define AKESOEDR_PIPE_MAX_INSTANCES 64

/* ── Message types ───────────────────────────────────────────────────────── */

typedef enum _AKESOEDR_IPC_MSG_TYPE {
    AkesoEDRMsgHandshake        = 1,
    AkesoEDRMsgHandshakeReply   = 2,
    AkesoEDRMsgEvent            = 3,    /* Telemetry event(s) */
    AkesoEDRMsgCommand          = 4,    /* CLI command */
    AkesoEDRMsgCommandReply     = 5,    /* Command response */
    AkesoEDRMsgDisconnect       = 6,
    AkesoEDRMsgHeartbeat        = 7
} AKESOEDR_IPC_MSG_TYPE;

/* ── Message frame header ────────────────────────────────────────────────── */

/*
 * Wire format:
 *   [UINT32 TotalLength]        ← size of everything after this field
 *   [AKESOEDR_IPC_HEADER]       ← message header
 *   [payload bytes]             ← type-specific payload
 *
 * TotalLength = sizeof(AKESOEDR_IPC_HEADER) + payload size
 */

#pragma pack(push, 1)

typedef struct _AKESOEDR_IPC_HEADER {
    UINT32                  Magic;          /* AKESOEDR_IPC_MAGIC */
    UINT16                  Version;        /* AKESOEDR_IPC_VERSION */
    UINT16                  Type;           /* AKESOEDR_IPC_MSG_TYPE */
    UINT32                  PayloadSize;    /* Size of payload following this header */
    UINT32                  SequenceNum;    /* Monotonically increasing per connection */
} AKESOEDR_IPC_HEADER;

/* ── Handshake (client → server) ─────────────────────────────────────────── */

typedef enum _AKESOEDR_CLIENT_TYPE {
    AkesoEDRClientDriver    = 1,
    AkesoEDRClientHookDll   = 2,
    AkesoEDRClientCli       = 3
} AKESOEDR_CLIENT_TYPE;

typedef struct _AKESOEDR_IPC_HANDSHAKE {
    AKESOEDR_IPC_HEADER     Header;
    UINT32                  ClientType;     /* AKESOEDR_CLIENT_TYPE */
    UINT32                  ClientPid;
} AKESOEDR_IPC_HANDSHAKE;

/* ── Handshake reply (server → client) ───────────────────────────────────── */

typedef enum _AKESOEDR_HANDSHAKE_STATUS {
    AkesoEDRHandshakeOk         = 0,
    AkesoEDRHandshakeBadMagic   = 1,
    AkesoEDRHandshakeBadVersion = 2,
    AkesoEDRHandshakeRejected   = 3
} AKESOEDR_HANDSHAKE_STATUS;

typedef struct _AKESOEDR_IPC_HANDSHAKE_REPLY {
    AKESOEDR_IPC_HEADER     Header;
    UINT32                  Status;         /* AKESOEDR_HANDSHAKE_STATUS */
    UINT32                  ServerPid;
} AKESOEDR_IPC_HANDSHAKE_REPLY;

/* ── Event message (telemetry data) ──────────────────────────────────────── */

typedef struct _AKESOEDR_IPC_EVENT_MSG {
    AKESOEDR_IPC_HEADER     Header;
    UINT32                  EventCount;     /* Number of events in batch (1..MAX_BATCH) */
    /* Followed by EventCount x AKESOEDR_EVENT structs */
} AKESOEDR_IPC_EVENT_MSG;

/* ── Command message (CLI → agent) ───────────────────────────────────────── */

typedef enum _AKESOEDR_CMD_TYPE {
    AkesoEDRCmdStatus       = 1,
    AkesoEDRCmdAlerts       = 2,
    AkesoEDRCmdScan         = 3,
    AkesoEDRCmdRulesReload  = 4,
    AkesoEDRCmdConnections  = 5,
    AkesoEDRCmdProcesses    = 6,
    AkesoEDRCmdHooks        = 7,
    AkesoEDRCmdConfig       = 8,
    AkesoEDRCmdRulesUpdate  = 9
} AKESOEDR_CMD_TYPE;

#define AKESOEDR_CMD_MAX_ARG    512

typedef struct _AKESOEDR_IPC_COMMAND {
    AKESOEDR_IPC_HEADER     Header;
    UINT32                  CommandType;    /* AKESOEDR_CMD_TYPE */
    WCHAR                   Argument[AKESOEDR_CMD_MAX_ARG];
} AKESOEDR_IPC_COMMAND;

/* ── Command reply (agent → CLI) ─────────────────────────────────────────── */

#define AKESOEDR_CMD_MAX_REPLY  (32 * 1024)

typedef struct _AKESOEDR_IPC_COMMAND_REPLY {
    AKESOEDR_IPC_HEADER     Header;
    UINT32                  CommandType;    /* Echo back the command type */
    UINT32                  Status;         /* 0 = success */
    UINT32                  DataSize;       /* Size of data following this struct */
    /* Followed by DataSize bytes of response data (JSON) */
} AKESOEDR_IPC_COMMAND_REPLY;

/* ── Disconnect message ──────────────────────────────────────────────────── */

typedef struct _AKESOEDR_IPC_DISCONNECT {
    AKESOEDR_IPC_HEADER     Header;
    UINT32                  Reason;         /* 0 = normal, 1 = error */
} AKESOEDR_IPC_DISCONNECT;

/* ── Heartbeat message ───────────────────────────────────────────────────── */

typedef struct _AKESOEDR_IPC_HEARTBEAT {
    AKESOEDR_IPC_HEADER     Header;
    UINT64                  UptimeMs;
    UINT32                  EventsProcessed;
} AKESOEDR_IPC_HEARTBEAT;

#pragma pack(pop)

/* ── Filter communication port structures (driver ↔ agent) ───────────────── */

/*
 * These map to the FltSendMessage / FilterGetMessage / FilterReplyMessage
 * protocol used between the minifilter driver and the agent service.
 *
 * The driver sends a AKESOEDR_FILTER_MSG containing one event.
 * The agent replies with a AKESOEDR_FILTER_REPLY containing an action.
 */

typedef struct _AKESOEDR_FILTER_MSG {
    /* FilterGetMessage prepends FILTER_MESSAGE_HEADER; this is the body */
    AKESOEDR_IPC_HEADER     Header;
    AKESOEDR_EVENT          Event;
} AKESOEDR_FILTER_MSG;

typedef enum _AKESOEDR_FILTER_ACTION {
    AkesoEDRFilterAllow     = 0,
    AkesoEDRFilterBlock     = 1,
    AkesoEDRFilterLog       = 2
} AKESOEDR_FILTER_ACTION;

typedef struct _AKESOEDR_FILTER_REPLY {
    /* FilterReplyMessage prepends FILTER_REPLY_HEADER; this is the body */
    UINT32                  Action;         /* AKESOEDR_FILTER_ACTION */
} AKESOEDR_FILTER_REPLY;

/* ── Close extern "C" ────────────────────────────────────────────────────── */

#ifndef _KERNEL_MODE
    #ifdef __cplusplus
    } /* extern "C" */
    #endif
#endif

#endif /* AKESOEDR_IPC_H */
