/*
 * sentinel-drv/comms.c
 * Filter communication port implementation.
 *
 * Uses FltCreateCommunicationPort to create a port that the agent service
 * connects to via FilterConnectCommunicationPort. Events are sent to the
 * agent via FltSendMessage.
 *
 * Only one client connection is accepted at a time (the agent service).
 *
 * IRQL: All port callbacks run at PASSIVE_LEVEL.
 */

#include <fltKernel.h>
#include <ntstrsafe.h>

#include "comms.h"
#include "constants.h"
#include "telemetry.h"
#include "ipc.h"

/* ── State ───────────────────────────────────────────────────────────────── */

static PFLT_PORT    s_ServerPort    = NULL;   /* Listening port */
static PFLT_PORT    s_ClientPort    = NULL;   /* Connected client port */
static PFLT_FILTER  s_Filter        = NULL;   /* Cached filter handle */

/* ── Port callback forward declarations ──────────────────────────────────── */

NTSTATUS
SentinelPortConnect(
    _In_  PFLT_PORT                ClientPort,
    _In_  PVOID                    ServerPortCookie,
    _In_reads_bytes_(SizeOfContext) PVOID ConnectionContext,
    _In_  ULONG                    SizeOfContext,
    _Outptr_ PVOID*                ConnectionCookie
);

VOID
SentinelPortDisconnect(
    _In_ PVOID ConnectionCookie
);

NTSTATUS
SentinelPortMessage(
    _In_  PVOID                    PortCookie,
    _In_reads_bytes_opt_(InputSize) PVOID InputBuffer,
    _In_  ULONG                    InputSize,
    _Out_writes_bytes_to_opt_(OutputSize, *ReturnOutputLength) PVOID OutputBuffer,
    _In_  ULONG                    OutputSize,
    _Out_ PULONG                   ReturnOutputLength
);

/* ── SentinelCommsInit ───────────────────────────────────────────────────── */

NTSTATUS
SentinelCommsInit(
    _In_ PFLT_FILTER Filter
)
{
    NTSTATUS            status;
    UNICODE_STRING      portName;
    OBJECT_ATTRIBUTES   oa;
    PSECURITY_DESCRIPTOR sd = NULL;

    PAGED_CODE();

    s_Filter = Filter;

    /*
     * Build a security descriptor that allows all access.
     * In production, restrict to the agent service SID.
     */
    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "SentinelPOC: FltBuildDefaultSecurityDescriptor failed 0x%08X\n", status));
        return status;
    }

    RtlInitUnicodeString(&portName, SENTINEL_FILTER_PORT_NAME);

    InitializeObjectAttributes(
        &oa,
        &portName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        sd
    );

    /*
     * Create the communication port.
     * MaxConnections = 1 — only the agent service connects.
     */
    status = FltCreateCommunicationPort(
        Filter,
        &s_ServerPort,
        &oa,
        NULL,                       /* ServerPortCookie */
        SentinelPortConnect,
        SentinelPortDisconnect,
        SentinelPortMessage,
        1                           /* MaxConnections */
    );

    FltFreeSecurityDescriptor(sd);

    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "SentinelPOC: FltCreateCommunicationPort failed 0x%08X\n", status));
        return status;
    }

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "SentinelPOC: Communication port created (%wZ)\n", &portName));

    return STATUS_SUCCESS;
}

/* ── SentinelCommsStop ───────────────────────────────────────────────────── */

VOID
SentinelCommsStop(VOID)
{
    PAGED_CODE();

    /* Close client connection if active */
    if (s_ClientPort) {
        FltCloseClientPort(s_Filter, &s_ClientPort);
        s_ClientPort = NULL;
    }

    /* Close server (listening) port */
    if (s_ServerPort) {
        FltCloseCommunicationPort(s_ServerPort);
        s_ServerPort = NULL;
    }

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "SentinelPOC: Communication port closed\n"));
}

/* ── SentinelCommsSend ───────────────────────────────────────────────────── */

NTSTATUS
SentinelCommsSend(
    _In_ const SENTINEL_EVENT* Event
)
{
    SENTINEL_FILTER_MSG *msg;
    ULONG               replyLength = 0;
    NTSTATUS            status;

    /* No client connected — silently drop */
    if (!s_ClientPort) {
        return STATUS_PORT_DISCONNECTED;
    }

    /*
     * SENTINEL_FILTER_MSG contains SENTINEL_EVENT (~22 KB) — too large
     * for the kernel stack.  Pool-allocate to avoid stack overflow.
     */
    msg = (SENTINEL_FILTER_MSG *)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(SENTINEL_FILTER_MSG), SENTINEL_TAG_EVENT);
    if (!msg) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /*
     * Build the filter message.
     * The header is for protocol validation on the receiving end.
     */
    RtlZeroMemory(msg, sizeof(*msg));

    msg->Header.Magic       = SENTINEL_IPC_MAGIC;
    msg->Header.Version     = SENTINEL_IPC_VERSION;
    msg->Header.Type        = (UINT16)SentinelMsgEvent;
    msg->Header.PayloadSize = sizeof(SENTINEL_EVENT);
    msg->Header.SequenceNum = 0;     /* Sequence tracking added later */

    RtlCopyMemory(&msg->Event, Event, sizeof(SENTINEL_EVENT));

    /*
     * FltSendMessage sends data to the user-mode port and optionally
     * waits for a reply. We use a short timeout to avoid blocking
     * callbacks for too long.
     *
     * IRQL: must be <= APC_LEVEL.
     */
    {
        LARGE_INTEGER timeout;
        timeout.QuadPart = -10000000LL;  /* 1 second relative timeout */

        status = FltSendMessage(
            s_Filter,
            &s_ClientPort,
            msg,
            sizeof(*msg),
            NULL,                   /* ReplyBuffer — no reply expected for events */
            &replyLength,
            &timeout
        );
    }

    if (!NT_SUCCESS(status) && status != STATUS_TIMEOUT) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "SentinelPOC: FltSendMessage failed 0x%08X\n", status));
    }

    ExFreePoolWithTag(msg, SENTINEL_TAG_EVENT);

    return status;
}

/* ── SentinelCommsIsConnected ────────────────────────────────────────────── */

BOOLEAN
SentinelCommsIsConnected(VOID)
{
    return (s_ClientPort != NULL);
}

/* ── Port connect callback ───────────────────────────────────────────────── */

NTSTATUS
SentinelPortConnect(
    _In_  PFLT_PORT                ClientPort,
    _In_  PVOID                    ServerPortCookie,
    _In_reads_bytes_(SizeOfContext) PVOID ConnectionContext,
    _In_  ULONG                    SizeOfContext,
    _Outptr_ PVOID*                ConnectionCookie
)
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);

    PAGED_CODE();

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "SentinelPOC: Agent connected to communication port\n"));

    /* Store client port for sending events */
    s_ClientPort = ClientPort;
    *ConnectionCookie = NULL;

    return STATUS_SUCCESS;
}

/* ── Port disconnect callback ────────────────────────────────────────────── */

VOID
SentinelPortDisconnect(
    _In_ PVOID ConnectionCookie
)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);

    PAGED_CODE();

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "SentinelPOC: Agent disconnected from communication port\n"));

    /* Close our handle to the client port */
    FltCloseClientPort(s_Filter, &s_ClientPort);
    s_ClientPort = NULL;
}

/* ── Port message callback ───────────────────────────────────────────────── */

/*
 * Handle messages FROM the agent TO the driver.
 * Currently unused — the driver only sends events, doesn't receive commands.
 * This will be extended in Phase 9 for sensor control IOCTLs.
 */
NTSTATUS
SentinelPortMessage(
    _In_  PVOID                    PortCookie,
    _In_reads_bytes_opt_(InputSize) PVOID InputBuffer,
    _In_  ULONG                    InputSize,
    _Out_writes_bytes_to_opt_(OutputSize, *ReturnOutputLength) PVOID OutputBuffer,
    _In_  ULONG                    OutputSize,
    _Out_ PULONG                   ReturnOutputLength
)
{
    UNREFERENCED_PARAMETER(PortCookie);
    UNREFERENCED_PARAMETER(InputBuffer);
    UNREFERENCED_PARAMETER(InputSize);
    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputSize);

    PAGED_CODE();

    *ReturnOutputLength = 0;

    return STATUS_SUCCESS;
}
