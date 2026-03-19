/*
 * sentinel-drv/wfp_callout.c
 * Windows Filtering Platform (WFP) callout registration and classify.
 *
 * Registers inspection-only callouts on two ALE layers:
 *   1. FWPM_LAYER_ALE_AUTH_CONNECT_V4   — outbound connections
 *   2. FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4 — inbound connections
 *
 * Classify functions extract connection metadata (IPs, ports, protocol,
 * PID) and emit SENTINEL_NETWORK_EVENT telemetry via the filter comms
 * port. All traffic is always permitted (FWP_ACTION_CONTINUE).
 *
 * IRQL: ALE classify functions run at PASSIVE_LEVEL, so SentinelCommsSend
 * (which calls FltSendMessage at <= APC_LEVEL) can be invoked directly.
 *
 * Rate limiting: A per-PID hash table limits events to
 * SENTINEL_NET_MAX_EVENTS_PER_SEC per process. A timer DPC resets
 * counters every second.
 *
 * Book reference: Chapter 7 — Network Filter Drivers.
 * SentinelEDR Phase 6, Task 1.
 */

#include <fltKernel.h>
#include <ntstrsafe.h>

/*
 * fwpsk.h requires ndis.h for NET_BUFFER_LIST and related types.
 * NDIS version must be set before including ndis.h.
 * fltKernel.h already pulls in ntddk.h — do NOT include it again.
 */
#define NDIS60 1
#include <ndis.h>

#pragma warning(push)
#pragma warning(disable:4201)   /* nameless struct/union in fwpsk.h */
#include <fwpsk.h>
#pragma warning(pop)
#include <fwpmk.h>

#include "wfp_callout.h"
#include "constants.h"
#include "telemetry.h"
#include "comms.h"

/* ── Section placement ───────────────────────────────────────────────────── */

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, SentinelWfpInit)
#pragma alloc_text(PAGE, SentinelWfpStop)
#endif

/* ── Rate-limiting state ─────────────────────────────────────────────────── */

/*
 * Simple per-PID rate limiter using a fixed hash table.
 * Each bucket stores a PID and a counter. Collisions are handled by
 * overwriting (acceptable — we only want approximate rate limiting).
 */

#define WFP_RATE_BUCKETS    64

typedef struct _WFP_RATE_ENTRY {
    volatile LONG   Count;
    volatile ULONG  Pid;
} WFP_RATE_ENTRY;

static WFP_RATE_ENTRY   s_RateTable[WFP_RATE_BUCKETS];
static KTIMER           s_RateTimer;
static KDPC             s_RateTimerDpc;
static BOOLEAN          s_TimerInitialized = FALSE;

/* ── Globals ─────────────────────────────────────────────────────────────── */

static HANDLE   s_EngineHandle      = NULL;
static UINT32   s_ConnectCalloutId  = 0;
static UINT32   s_RecvCalloutId     = 0;
static BOOLEAN  s_Initialized       = FALSE;

/* Reference to driver device object (needed for IoAllocateWorkItem) */
extern PDEVICE_OBJECT g_DeviceObject;

/* ── Rate-limiting helpers ───────────────────────────────────────────────── */

static VOID
WfpRateTimerDpcRoutine(
    _In_ PKDPC  Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
)
{
    ULONG i;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    /* Reset all rate counters every second */
    for (i = 0; i < WFP_RATE_BUCKETS; i++) {
        InterlockedExchange(&s_RateTable[i].Count, 0);
    }
}

/*
 * Returns TRUE if this event should be dropped (rate exceeded).
 */
static BOOLEAN
WfpRateLimitCheck(
    _In_ ULONG ProcessId
)
{
    ULONG bucket = ProcessId % WFP_RATE_BUCKETS;
    WFP_RATE_ENTRY *entry = &s_RateTable[bucket];
    LONG count;

    /* Store PID (approximate — collisions are OK for rate limiting) */
    InterlockedExchange((volatile LONG *)&entry->Pid, (LONG)ProcessId);

    count = InterlockedIncrement(&entry->Count);
    return (count > SENTINEL_NET_MAX_EVENTS_PER_SEC) ? TRUE : FALSE;
}

/* ── Deferred work item for elevated IRQL ────────────────────────────────── */

/*
 * WFP classify callbacks on this system consistently fire at DISPATCH_LEVEL.
 * FltSendMessage requires IRQL <= APC_LEVEL.  Solution: extract the network
 * metadata at DISPATCH_LEVEL (safe — all data is non-paged), then queue a
 * work item that calls SentinelCommsSend at PASSIVE_LEVEL.
 *
 * At PASSIVE_LEVEL we skip the work item and send directly for lower latency.
 */

typedef struct _WFP_WORK_CONTEXT {
    PIO_WORKITEM        WorkItem;
    SENTINEL_EVENT      Event;
} WFP_WORK_CONTEXT;

static VOID
WfpSendWorkItem(
    _In_     PDEVICE_OBJECT DeviceObject,
    _In_opt_ PVOID          Context
)
{
    WFP_WORK_CONTEXT *ctx = (WFP_WORK_CONTEXT *)Context;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (ctx) {
        SentinelCommsSend(&ctx->Event);
        IoFreeWorkItem(ctx->WorkItem);
        ExFreePoolWithTag(ctx, SENTINEL_TAG_NETWORK);
    }
}

/* ── Classify helpers ────────────────────────────────────────────────────── */

/*
 * Common classify logic for both connect and recv/accept layers.
 * Extracts connection metadata and emits a SENTINEL_NETWORK_EVENT.
 *
 * IRQL handling: Classify can fire at any IRQL (PASSIVE or DISPATCH).
 * We extract all metadata at the current IRQL (safe — WFP data is non-paged).
 * If IRQL <= PASSIVE_LEVEL, we send directly.  Otherwise we queue a work
 * item that sends at PASSIVE_LEVEL.
 */
static VOID
WfpClassifyCommon(
    _In_ const FWPS_INCOMING_VALUES0          *inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0 *inMetaValues,
    _Inout_ FWPS_CLASSIFY_OUT0                *classifyOut,
    _In_ SENTINEL_NET_DIRECTION                direction,
    _In_ ULONG                                 localAddrIndex,
    _In_ ULONG                                 localPortIndex,
    _In_ ULONG                                 remoteAddrIndex,
    _In_ ULONG                                 remotePortIndex,
    _In_ ULONG                                 protocolIndex
)
{
    ULONG            pid   = 0;
    KIRQL            irql;
    SENTINEL_EVENT  *event = NULL;

    /* Always permit traffic — inspection only */
    classifyOut->actionType = FWP_ACTION_CONTINUE;

    /* Bail out if driver is shutting down */
    if (!s_Initialized) {
        return;
    }

    /* Extract PID from metadata */
    if (FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_PROCESS_ID)) {
        pid = (ULONG)inMetaValues->processId;
    }

    /* Rate limit */
    if (WfpRateLimitCheck(pid)) {
        return;
    }

    irql = KeGetCurrentIrql();

    if (irql <= PASSIVE_LEVEL) {
        /*
         * PASSIVE_LEVEL — send directly (lowest latency).
         */
        event = (SENTINEL_EVENT *)ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            sizeof(SENTINEL_EVENT),
            SENTINEL_TAG_NETWORK
        );
        if (!event) {
            return;
        }

        RtlZeroMemory(event, sizeof(SENTINEL_EVENT));

        /* Pseudo-GUID (avoids ExUuidCreate IRQL dependency) */
        {
            LARGE_INTEGER pc;
            static volatile LONG s_seqNum = 0;
            pc = KeQueryPerformanceCounter(NULL);
            event->EventId.Data1 = pid;
            event->EventId.Data2 = (USHORT)KeGetCurrentProcessorNumberEx(NULL);
            event->EventId.Data3 = (USHORT)InterlockedIncrement(&s_seqNum);
            *(LONGLONG *)event->EventId.Data4 = pc.QuadPart;
        }
        KeQuerySystemTimePrecise(&event->Timestamp);
        event->Source   = SentinelSourceDriverNetwork;
        event->Severity = SentinelSeverityInformational;
        event->ProcessCtx.ProcessId = pid;

        event->Payload.Network.Direction = direction;
        event->Payload.Network.ProcessId = pid;
        event->Payload.Network.Protocol =
            inFixedValues->incomingValue[protocolIndex].value.uint8;
        event->Payload.Network.LocalAddr =
            inFixedValues->incomingValue[localAddrIndex].value.uint32;
        event->Payload.Network.LocalPort =
            inFixedValues->incomingValue[localPortIndex].value.uint16;
        event->Payload.Network.RemoteAddr =
            inFixedValues->incomingValue[remoteAddrIndex].value.uint32;
        event->Payload.Network.RemotePort =
            inFixedValues->incomingValue[remotePortIndex].value.uint16;

        SentinelCommsSend(event);
        ExFreePoolWithTag(event, SENTINEL_TAG_NETWORK);

    } else {
        /*
         * DISPATCH_LEVEL — defer send via IoQueueWorkItem.
         * ExAllocatePool2 with POOL_FLAG_NON_PAGED is safe at DISPATCH.
         * IoAllocateWorkItem / IoQueueWorkItem are safe at <= DISPATCH.
         */
        WFP_WORK_CONTEXT *ctx;
        PIO_WORKITEM      workItem;

        if (!g_DeviceObject) {
            return;
        }

        workItem = IoAllocateWorkItem(g_DeviceObject);
        if (!workItem) {
            return;
        }

        ctx = (WFP_WORK_CONTEXT *)ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            sizeof(WFP_WORK_CONTEXT),
            SENTINEL_TAG_NETWORK
        );
        if (!ctx) {
            IoFreeWorkItem(workItem);
            return;
        }

        RtlZeroMemory(ctx, sizeof(WFP_WORK_CONTEXT));
        ctx->WorkItem = workItem;

        /* Pseudo-GUID */
        {
            LARGE_INTEGER pc;
            static volatile LONG s_seqNum2 = 0;
            pc = KeQueryPerformanceCounter(NULL);
            ctx->Event.EventId.Data1 = pid;
            ctx->Event.EventId.Data2 = (USHORT)KeGetCurrentProcessorNumberEx(NULL);
            ctx->Event.EventId.Data3 = (USHORT)InterlockedIncrement(&s_seqNum2);
            *(LONGLONG *)ctx->Event.EventId.Data4 = pc.QuadPart;
        }
        KeQuerySystemTimePrecise(&ctx->Event.Timestamp);
        ctx->Event.Source   = SentinelSourceDriverNetwork;
        ctx->Event.Severity = SentinelSeverityInformational;
        ctx->Event.ProcessCtx.ProcessId = pid;

        ctx->Event.Payload.Network.Direction = direction;
        ctx->Event.Payload.Network.ProcessId = pid;
        ctx->Event.Payload.Network.Protocol =
            inFixedValues->incomingValue[protocolIndex].value.uint8;
        ctx->Event.Payload.Network.LocalAddr =
            inFixedValues->incomingValue[localAddrIndex].value.uint32;
        ctx->Event.Payload.Network.LocalPort =
            inFixedValues->incomingValue[localPortIndex].value.uint16;
        ctx->Event.Payload.Network.RemoteAddr =
            inFixedValues->incomingValue[remoteAddrIndex].value.uint32;
        ctx->Event.Payload.Network.RemotePort =
            inFixedValues->incomingValue[remotePortIndex].value.uint16;

        IoQueueWorkItem(workItem, WfpSendWorkItem, DelayedWorkQueue, ctx);
    }
}

/* ── WFP classify callbacks ──────────────────────────────────────────────── */

static VOID NTAPI
SentinelClassifyConnect(
    _In_    const FWPS_INCOMING_VALUES0          *inFixedValues,
    _In_    const FWPS_INCOMING_METADATA_VALUES0 *inMetaValues,
    _Inout_opt_ void                             *layerData,
    _In_    const FWPS_FILTER0                   *filter,
    _In_    UINT64                                flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0                   *classifyOut
)
{
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    WfpClassifyCommon(
        inFixedValues,
        inMetaValues,
        classifyOut,
        SentinelNetOutbound,
        FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS,
        FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT,
        FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS,
        FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT,
        FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL
    );
}

static VOID NTAPI
SentinelClassifyRecv(
    _In_    const FWPS_INCOMING_VALUES0          *inFixedValues,
    _In_    const FWPS_INCOMING_METADATA_VALUES0 *inMetaValues,
    _Inout_opt_ void                             *layerData,
    _In_    const FWPS_FILTER0                   *filter,
    _In_    UINT64                                flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0                   *classifyOut
)
{
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    WfpClassifyCommon(
        inFixedValues,
        inMetaValues,
        classifyOut,
        SentinelNetInbound,
        FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_ADDRESS,
        FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_PORT,
        FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_ADDRESS,
        FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_PORT,
        FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_PROTOCOL
    );
}

/* ── WFP notify callbacks (required but unused) ──────────────────────────── */

static NTSTATUS NTAPI
SentinelNotifyConnect(
    _In_    FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_    const GUID              *filterKey,
    _Inout_ FWPS_FILTER0            *filter
)
{
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI
SentinelNotifyRecv(
    _In_    FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_    const GUID              *filterKey,
    _Inout_ FWPS_FILTER0            *filter
)
{
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

/* ── SentinelWfpInit ─────────────────────────────────────────────────────── */

NTSTATUS
SentinelWfpInit(
    _In_ PDEVICE_OBJECT DeviceObject
)
{
    NTSTATUS        status;
    FWPS_CALLOUT0   sCallout       = { 0 };
    FWPM_CALLOUT0   mCallout       = { 0 };
    FWPM_SUBLAYER0  subLayer       = { 0 };
    FWPM_FILTER0    filter         = { 0 };
    FWPM_DISPLAY_DATA0 displayData = { 0 };
    UINT64          filterId       = 0;

    PAGED_CODE();

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "SentinelEDR: WFP init starting\n"));

    /* ── Step 1: Open BFE engine session ──────────────────────────────── */

    status = FwpmEngineOpen0(
        NULL,               /* local machine */
        RPC_C_AUTHN_WINNT,
        NULL,               /* auth identity */
        NULL,               /* session */
        &s_EngineHandle
    );
    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "SentinelEDR: FwpmEngineOpen0 failed 0x%08X\n", status));
        return status;
    }

    /* ── Step 2: Begin transaction ────────────────────────────────────── */

    status = FwpmTransactionBegin0(s_EngineHandle, 0);
    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "SentinelEDR: FwpmTransactionBegin0 failed 0x%08X\n", status));
        goto cleanup_engine;
    }

    /* ── Step 3: Register + add outbound callout ──────────────────────── */

    sCallout.calloutKey           = SENTINEL_WFP_CALLOUT_CONNECT_V4;
    sCallout.classifyFn           = SentinelClassifyConnect;
    sCallout.notifyFn             = SentinelNotifyConnect;
    sCallout.flowDeleteFn         = NULL;

    status = FwpsCalloutRegister0(DeviceObject, &sCallout, &s_ConnectCalloutId);
    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "SentinelEDR: FwpsCalloutRegister0 (connect) failed 0x%08X\n", status));
        goto abort_txn;
    }

    displayData.name        = L"SentinelEDR ALE Connect v4";
    displayData.description = L"Monitors outbound IPv4 connections";

    mCallout.calloutKey       = SENTINEL_WFP_CALLOUT_CONNECT_V4;
    mCallout.displayData      = displayData;
    mCallout.applicableLayer  = FWPM_LAYER_ALE_AUTH_CONNECT_V4;

    status = FwpmCalloutAdd0(s_EngineHandle, &mCallout, NULL, NULL);
    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "SentinelEDR: FwpmCalloutAdd0 (connect) failed 0x%08X\n", status));
        goto abort_txn;
    }

    /* ── Step 4: Register + add inbound callout ───────────────────────── */

    RtlZeroMemory(&sCallout, sizeof(sCallout));
    sCallout.calloutKey           = SENTINEL_WFP_CALLOUT_RECV_V4;
    sCallout.classifyFn           = SentinelClassifyRecv;
    sCallout.notifyFn             = SentinelNotifyRecv;
    sCallout.flowDeleteFn         = NULL;

    status = FwpsCalloutRegister0(DeviceObject, &sCallout, &s_RecvCalloutId);
    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "SentinelEDR: FwpsCalloutRegister0 (recv) failed 0x%08X\n", status));
        goto abort_txn;
    }

    displayData.name        = L"SentinelEDR ALE Recv/Accept v4";
    displayData.description = L"Monitors inbound IPv4 connections";

    RtlZeroMemory(&mCallout, sizeof(mCallout));
    mCallout.calloutKey       = SENTINEL_WFP_CALLOUT_RECV_V4;
    mCallout.displayData      = displayData;
    mCallout.applicableLayer  = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4;

    status = FwpmCalloutAdd0(s_EngineHandle, &mCallout, NULL, NULL);
    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "SentinelEDR: FwpmCalloutAdd0 (recv) failed 0x%08X\n", status));
        goto abort_txn;
    }

    /* ── Step 5: Add sublayer ─────────────────────────────────────────── */

    subLayer.subLayerKey         = SENTINEL_WFP_SUBLAYER_GUID;
    displayData.name             = L"SentinelEDR Sublayer";
    displayData.description      = L"SentinelEDR network inspection sublayer";
    subLayer.displayData         = displayData;
    subLayer.flags               = 0;
    subLayer.weight              = 0x8000;  /* Mid-range weight */

    status = FwpmSubLayerAdd0(s_EngineHandle, &subLayer, NULL);
    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "SentinelEDR: FwpmSubLayerAdd0 failed 0x%08X\n", status));
        goto abort_txn;
    }

    /* ── Step 6: Add outbound filter ──────────────────────────────────── */

    RtlZeroMemory(&filter, sizeof(filter));
    filter.filterKey            = SENTINEL_WFP_FILTER_CONNECT_V4;
    displayData.name            = L"SentinelEDR Connect Filter v4";
    displayData.description     = L"Inspection filter for outbound IPv4";
    filter.displayData          = displayData;
    filter.layerKey             = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.subLayerKey          = SENTINEL_WFP_SUBLAYER_GUID;
    filter.action.type          = FWP_ACTION_CALLOUT_INSPECTION;
    filter.action.calloutKey    = SENTINEL_WFP_CALLOUT_CONNECT_V4;
    filter.weight.type          = FWP_EMPTY;
    filter.numFilterConditions  = 0;    /* Match all traffic */

    status = FwpmFilterAdd0(s_EngineHandle, &filter, NULL, &filterId);
    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "SentinelEDR: FwpmFilterAdd0 (connect) failed 0x%08X\n", status));
        goto abort_txn;
    }

    /* ── Step 7: Add inbound filter ───────────────────────────────────── */

    RtlZeroMemory(&filter, sizeof(filter));
    filter.filterKey            = SENTINEL_WFP_FILTER_RECV_V4;
    displayData.name            = L"SentinelEDR Recv Filter v4";
    displayData.description     = L"Inspection filter for inbound IPv4";
    filter.displayData          = displayData;
    filter.layerKey             = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4;
    filter.subLayerKey          = SENTINEL_WFP_SUBLAYER_GUID;
    filter.action.type          = FWP_ACTION_CALLOUT_INSPECTION;
    filter.action.calloutKey    = SENTINEL_WFP_CALLOUT_RECV_V4;
    filter.weight.type          = FWP_EMPTY;
    filter.numFilterConditions  = 0;    /* Match all traffic */

    status = FwpmFilterAdd0(s_EngineHandle, &filter, NULL, &filterId);
    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "SentinelEDR: FwpmFilterAdd0 (recv) failed 0x%08X\n", status));
        goto abort_txn;
    }

    /* ── Step 8: Commit transaction ───────────────────────────────────── */

    status = FwpmTransactionCommit0(s_EngineHandle);
    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "SentinelEDR: FwpmTransactionCommit0 failed 0x%08X\n", status));
        goto cleanup_engine;
    }

    /* ── Step 9: Start rate-limit timer ───────────────────────────────── */

    RtlZeroMemory(s_RateTable, sizeof(s_RateTable));
    KeInitializeDpc(&s_RateTimerDpc, WfpRateTimerDpcRoutine, NULL);
    KeInitializeTimerEx(&s_RateTimer, SynchronizationTimer);

    {
        LARGE_INTEGER dueTime;
        dueTime.QuadPart = -10000000LL;    /* 1 second relative */

        KeSetTimerEx(
            &s_RateTimer,
            dueTime,
            1000,                           /* 1 second periodic */
            &s_RateTimerDpc
        );
    }

    s_TimerInitialized = TRUE;
    s_Initialized = TRUE;

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "SentinelEDR: WFP callouts registered (connect=%u, recv=%u)\n",
        s_ConnectCalloutId, s_RecvCalloutId));

    return STATUS_SUCCESS;

    /* ── Error paths ──────────────────────────────────────────────────── */

abort_txn:
    FwpmTransactionAbort0(s_EngineHandle);

    /* Unregister any callouts that were registered before the failure */
    if (s_ConnectCalloutId) {
        FwpsCalloutUnregisterById0(s_ConnectCalloutId);
        s_ConnectCalloutId = 0;
    }
    if (s_RecvCalloutId) {
        FwpsCalloutUnregisterById0(s_RecvCalloutId);
        s_RecvCalloutId = 0;
    }

cleanup_engine:
    if (s_EngineHandle) {
        FwpmEngineClose0(s_EngineHandle);
        s_EngineHandle = NULL;
    }

    return status;
}

/* ── SentinelWfpStop ─────────────────────────────────────────────────────── */

VOID
SentinelWfpStop(void)
{
    PAGED_CODE();

    if (!s_Initialized) {
        return;
    }

    /*
     * Signal classify functions to bail out immediately.
     * This must happen BEFORE we tear down any WFP objects so that
     * any in-flight classify calls see the flag and exit early.
     */
    s_Initialized = FALSE;

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "SentinelEDR: WFP cleanup starting\n"));

    /* Stop rate-limit timer */
    if (s_TimerInitialized) {
        KeCancelTimer(&s_RateTimer);
        KeFlushQueuedDpcs();
        s_TimerInitialized = FALSE;
    }

    /*
     * Close the engine handle first — this removes all WFP objects
     * (sublayer, filters, management callouts) that were added in
     * the session.
     */
    if (s_EngineHandle) {
        FwpmEngineClose0(s_EngineHandle);
        s_EngineHandle = NULL;
    }

    /*
     * Unregister runtime callouts (FwpsCalloutRegister).
     * Must happen after engine close to avoid classify calls referencing
     * removed engine objects.
     *
     * FwpsCalloutUnregisterById0 returns STATUS_DEVICE_BUSY if a classify
     * invocation is still in progress. We must retry until it succeeds
     * to prevent a use-after-free BSOD when the driver image unloads.
     */
    if (s_ConnectCalloutId) {
        NTSTATUS unregStatus;
        ULONG retries = 0;
        do {
            unregStatus = FwpsCalloutUnregisterById0(s_ConnectCalloutId);
            if (unregStatus == STATUS_DEVICE_BUSY) {
                LARGE_INTEGER delay;
                delay.QuadPart = -500000LL;  /* 50ms */
                KeDelayExecutionThread(KernelMode, FALSE, &delay);
            }
            retries++;
        } while (unregStatus == STATUS_DEVICE_BUSY && retries < 50);
        s_ConnectCalloutId = 0;
    }
    if (s_RecvCalloutId) {
        NTSTATUS unregStatus;
        ULONG retries = 0;
        do {
            unregStatus = FwpsCalloutUnregisterById0(s_RecvCalloutId);
            if (unregStatus == STATUS_DEVICE_BUSY) {
                LARGE_INTEGER delay;
                delay.QuadPart = -500000LL;  /* 50ms */
                KeDelayExecutionThread(KernelMode, FALSE, &delay);
            }
            retries++;
        } while (unregStatus == STATUS_DEVICE_BUSY && retries < 50);
        s_RecvCalloutId = 0;
    }

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "SentinelEDR: WFP cleanup complete\n"));
}
