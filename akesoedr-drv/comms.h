/*
 * akesoedr-drv/comms.h
 * Filter communication port interface for driver → agent telemetry.
 *
 * The communication port is built on FltCreateCommunicationPort (minifilter
 * framework). The agent connects from user-mode via FilterConnectCommunicationPort.
 *
 * Functions:
 *   AkesoEDRCommsInit  — Create the communication port (called from DriverEntry)
 *   AkesoEDRCommsStop  — Close the port and disconnect clients (called from unload)
 *   AkesoEDRCommsSend  — Send a telemetry event to the connected agent
 *
 * IRQL: All functions run at PASSIVE_LEVEL unless noted.
 */

#ifndef AKESOEDR_COMMS_H
#define AKESOEDR_COMMS_H

#include <fltKernel.h>
#include "telemetry.h"

/* ── Public API ──────────────────────────────────────────────────────────── */

/*
 * Initialize the filter communication port.
 * Must be called after FltRegisterFilter succeeds.
 */
NTSTATUS
AkesoEDRCommsInit(
    _In_ PFLT_FILTER Filter
);

/*
 * Tear down the communication port and disconnect any connected client.
 * Safe to call if AkesoEDRCommsInit was never called or already stopped.
 */
VOID
AkesoEDRCommsStop(VOID);

/*
 * Send a AKESOEDR_EVENT to the connected agent.
 * If no agent is connected, the event is silently dropped.
 *
 * IRQL: <= APC_LEVEL (FltSendMessage requirement)
 *
 * Returns:
 *   STATUS_SUCCESS          — event sent
 *   STATUS_PORT_DISCONNECTED — no agent connected (event dropped)
 *   Other NTSTATUS          — send failure
 */
NTSTATUS
AkesoEDRCommsSend(
    _In_ const AKESOEDR_EVENT* Event
);

/*
 * Check whether an agent is currently connected.
 */
BOOLEAN
AkesoEDRCommsIsConnected(VOID);

#endif /* AKESOEDR_COMMS_H */
