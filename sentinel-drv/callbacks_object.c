/*
 * sentinel-drv/callbacks_object.c
 * Object handle callback implementation (Ch. 4 — ObRegisterCallbacks).
 *
 * Monitors OB_OPERATION_HANDLE_CREATE and OB_OPERATION_HANDLE_DUPLICATE
 * for Process and Thread object types. Only emits events when the target
 * is a protected process (lsass.exe, csrss.exe, services.exe) to avoid
 * event flooding.
 *
 * This is observe-only — we do NOT strip access rights. The callback
 * returns OB_PREOP_SUCCESS without modifying DesiredAccess.
 *
 * IRQL: ObRegisterCallbacks callback runs at PASSIVE_LEVEL.
 */

#include <fltKernel.h>
#include <ntstrsafe.h>

#include "callbacks_object.h"
#include "constants.h"
#include "telemetry.h"
#include "comms.h"

/* ── Undocumented but stable kernel APIs ────────────────────────────────── */

NTKERNELAPI
PCHAR
PsGetProcessImageFileName(
    _In_ PEPROCESS Process
);

NTKERNELAPI
HANDLE
PsGetProcessInheritedFromUniqueProcessId(
    _In_ PEPROCESS Process
);

NTKERNELAPI
NTSTATUS
PsGetProcessSessionId(
    _In_  PEPROCESS Process,
    _Out_ PULONG    SessionId
);

/* ── Section placement ──────────────────────────────────────────────────── */

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, SentinelObjectCallbackInit)
#pragma alloc_text(PAGE, SentinelObjectCallbackStop)
#endif

/* ── State ──────────────────────────────────────────────────────────────── */

static BOOLEAN  g_ObjectCallbackRegistered = FALSE;
static PVOID    g_ObRegistrationHandle     = NULL;

/* ── Protected process list (ASCII — matches PsGetProcessImageFileName) ── */

static const CHAR* g_ProtectedProcesses[] = {
    "lsass.exe",
    "csrss.exe",
    "services.exe"
};

#define PROTECTED_PROCESS_COUNT  (sizeof(g_ProtectedProcesses) / sizeof(g_ProtectedProcesses[0]))

/* ── Forward declarations ───────────────────────────────────────────────── */

static OB_PREOP_CALLBACK_STATUS
SentinelObjectPreCallback(
    _In_    PVOID                          RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION  OperationInfo
);

static BOOLEAN
SentinelIsProtectedProcess(
    _In_ PEPROCESS Process
);

static VOID
SentinelFillProcessCtxForObject(
    _Out_ SENTINEL_PROCESS_CTX* Ctx,
    _In_  HANDLE                ProcessId
);

/* ── SentinelObjectCallbackInit ─────────────────────────────────────────── */

NTSTATUS
SentinelObjectCallbackInit(VOID)
{
    NTSTATUS                    status;
    OB_OPERATION_REGISTRATION   opReg[2];
    OB_CALLBACK_REGISTRATION    cbReg;
    UNICODE_STRING              altitude;

    PAGED_CODE();

    if (g_ObjectCallbackRegistered) {
        return STATUS_SUCCESS;
    }

    RtlInitUnicodeString(&altitude, SENTINEL_OB_ALTITUDE);

    /* Operation registration 0: Process objects */
    RtlZeroMemory(&opReg[0], sizeof(OB_OPERATION_REGISTRATION));
    opReg[0].ObjectType   = PsProcessType;
    opReg[0].Operations   = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    opReg[0].PreOperation = SentinelObjectPreCallback;
    opReg[0].PostOperation = NULL;

    /* Operation registration 1: Thread objects */
    RtlZeroMemory(&opReg[1], sizeof(OB_OPERATION_REGISTRATION));
    opReg[1].ObjectType   = PsThreadType;
    opReg[1].Operations   = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    opReg[1].PreOperation = SentinelObjectPreCallback;
    opReg[1].PostOperation = NULL;

    /* Callback registration */
    RtlZeroMemory(&cbReg, sizeof(OB_CALLBACK_REGISTRATION));
    cbReg.Version                    = OB_FLT_REGISTRATION_VERSION;
    cbReg.OperationRegistrationCount = 2;
    cbReg.Altitude                   = altitude;
    cbReg.RegistrationContext        = NULL;
    cbReg.OperationRegistration      = opReg;

    status = ObRegisterCallbacks(&cbReg, &g_ObRegistrationHandle);
    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "SentinelEDR: ObRegisterCallbacks failed 0x%08X\n", status));
        return status;
    }

    g_ObjectCallbackRegistered = TRUE;

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "SentinelEDR: Object handle callbacks registered (altitude %wZ)\n",
        &altitude));

    return STATUS_SUCCESS;
}

/* ── SentinelObjectCallbackStop ─────────────────────────────────────────── */

VOID
SentinelObjectCallbackStop(VOID)
{
    PAGED_CODE();

    if (!g_ObjectCallbackRegistered) {
        return;
    }

    ObUnRegisterCallbacks(g_ObRegistrationHandle);
    g_ObRegistrationHandle     = NULL;
    g_ObjectCallbackRegistered = FALSE;

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "SentinelEDR: Object handle callbacks unregistered\n"));
}

/* ── Protected process check ────────────────────────────────────────────── */

static BOOLEAN
SentinelIsProtectedProcess(
    _In_ PEPROCESS Process
)
{
    PCHAR   imageName;
    ULONG   i;

    imageName = PsGetProcessImageFileName(Process);
    if (!imageName || imageName[0] == '\0') {
        return FALSE;
    }

    for (i = 0; i < PROTECTED_PROCESS_COUNT; i++) {
        if (_stricmp(imageName, g_ProtectedProcesses[i]) == 0) {
            return TRUE;
        }
    }

    return FALSE;
}

/* ── Object pre-operation callback ──────────────────────────────────────── */

static OB_PREOP_CALLBACK_STATUS
SentinelObjectPreCallback(
    _In_    PVOID                          RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION  OperationInfo
)
{
    SENTINEL_EVENT *event;
    PEPROCESS       targetProcess = NULL;
    HANDLE          sourcePid;
    HANDLE          sourceTid;
    HANDLE          targetPid;
    BOOLEAN         isProcessType;

    UNREFERENCED_PARAMETER(RegistrationContext);

    /* Determine object type */
    isProcessType = (OperationInfo->ObjectType == *PsProcessType);

    /* Get the target process */
    if (isProcessType) {
        targetProcess = (PEPROCESS)OperationInfo->Object;
    } else {
        /* Thread type: get the owning process */
        targetProcess = IoThreadToProcess((PETHREAD)OperationInfo->Object);
    }

    if (!targetProcess) {
        return OB_PREOP_SUCCESS;
    }

    /* ── Filter: only emit events for protected processes ──────────────── */

    if (!SentinelIsProtectedProcess(targetProcess)) {
        return OB_PREOP_SUCCESS;
    }

    /* Filter: skip self-access (reduces noise) */
    sourcePid = PsGetCurrentProcessId();
    targetPid = PsGetProcessId(targetProcess);

    if (sourcePid == targetPid) {
        return OB_PREOP_SUCCESS;
    }

    /* Filter: skip kernel (System/Idle) accessing protected processes */
    if ((ULONG_PTR)sourcePid <= 4) {
        return OB_PREOP_SUCCESS;
    }

    /* ── Emit telemetry event ──────────────────────────────────────────── */

    event = (SENTINEL_EVENT *)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(SENTINEL_EVENT), SENTINEL_TAG_EVENT);
    if (!event) {
        return OB_PREOP_SUCCESS;
    }

    __try {
        sourceTid = PsGetCurrentThreadId();

        RtlZeroMemory(event, sizeof(SENTINEL_EVENT));
        ExUuidCreate(&event->EventId);
        KeQuerySystemTimePrecise(&event->Timestamp);
        event->Source   = SentinelSourceDriverObject;
        event->Severity = SentinelSeverityMedium;

        /* Fill process context (the SOURCE — who is opening the handle) */
        SentinelFillProcessCtxForObject(&event->ProcessCtx, sourcePid);

        /* Fill object event payload */
        event->Payload.Object.Operation =
            (OperationInfo->Operation == OB_OPERATION_HANDLE_CREATE)
                ? SentinelObjOpCreate
                : SentinelObjOpDuplicate;

        event->Payload.Object.ObjectType =
            isProcessType ? SentinelObjTypeProcess : SentinelObjTypeThread;

        event->Payload.Object.SourceProcessId = (ULONG)(ULONG_PTR)sourcePid;
        event->Payload.Object.SourceThreadId  = (ULONG)(ULONG_PTR)sourceTid;
        event->Payload.Object.TargetProcessId = (ULONG)(ULONG_PTR)targetPid;

        /* Target image path (full NT path) */
        {
            PUNICODE_STRING imageName = NULL;
            if (NT_SUCCESS(SeLocateProcessImageName(targetProcess, &imageName))) {
                if (imageName && imageName->Buffer && imageName->Length > 0) {
                    RtlStringCchCopyNW(
                        event->Payload.Object.TargetImagePath,
                        SENTINEL_MAX_PATH,
                        imageName->Buffer,
                        imageName->Length / sizeof(WCHAR));
                }
                if (imageName) {
                    ExFreePool(imageName);
                }
            }
        }

        /* Access masks */
        if (OperationInfo->Operation == OB_OPERATION_HANDLE_CREATE) {
            event->Payload.Object.DesiredAccess =
                (ULONG)OperationInfo->Parameters->CreateHandleInformation.DesiredAccess;
            event->Payload.Object.GrantedAccess =
                (ULONG)OperationInfo->Parameters->CreateHandleInformation.OriginalDesiredAccess;
        } else {
            event->Payload.Object.DesiredAccess =
                (ULONG)OperationInfo->Parameters->DuplicateHandleInformation.DesiredAccess;
            event->Payload.Object.GrantedAccess =
                (ULONG)OperationInfo->Parameters->DuplicateHandleInformation.OriginalDesiredAccess;
        }

        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
            "SentinelEDR: Object %s %s PID=%lu -> PID=%lu Access=0x%X\n",
            isProcessType ? "Process" : "Thread",
            (OperationInfo->Operation == OB_OPERATION_HANDLE_CREATE) ? "CREATE" : "DUPLICATE",
            (ULONG)(ULONG_PTR)sourcePid,
            (ULONG)(ULONG_PTR)targetPid,
            event->Payload.Object.DesiredAccess));

        SentinelCommsSend(event);

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "SentinelEDR: Exception 0x%08X in object callback PID=%lu -> PID=%lu\n",
            GetExceptionCode(),
            (ULONG)(ULONG_PTR)sourcePid,
            (ULONG)(ULONG_PTR)targetPid));
    }

    ExFreePoolWithTag(event, SENTINEL_TAG_EVENT);

    /* Observe only — do not modify access */
    return OB_PREOP_SUCCESS;
}

/* ── Helper: fill process context for the source process ────────────────── */

static VOID
SentinelFillProcessCtxForObject(
    _Out_ SENTINEL_PROCESS_CTX* Ctx,
    _In_  HANDLE                ProcessId
)
{
    PEPROCESS       process = NULL;
    NTSTATUS        status;
    PUNICODE_STRING imageName = NULL;

    RtlZeroMemory(Ctx, sizeof(SENTINEL_PROCESS_CTX));

    Ctx->ProcessId = (ULONG)(ULONG_PTR)ProcessId;
    Ctx->ThreadId  = (ULONG)(ULONG_PTR)PsGetCurrentThreadId();

    /* Look up the source process */
    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status) || !process) {
        return;
    }

    /* Parent PID */
    Ctx->ParentProcessId = (ULONG)(ULONG_PTR)
        PsGetProcessInheritedFromUniqueProcessId(process);

    /* Session ID */
    {
        ULONG sessionId = 0;
        NTSTATUS sessionStatus = PsGetProcessSessionId(process, &sessionId);
        Ctx->SessionId = NT_SUCCESS(sessionStatus) ? sessionId : 0;
    }

    KeQuerySystemTimePrecise(&Ctx->ProcessCreateTime);

    /* Image path */
    if (NT_SUCCESS(SeLocateProcessImageName(process, &imageName))) {
        if (imageName && imageName->Buffer && imageName->Length > 0) {
            RtlStringCchCopyNW(
                Ctx->ImagePath,
                SENTINEL_MAX_PATH,
                imageName->Buffer,
                imageName->Length / sizeof(WCHAR)
            );
        }
        if (imageName) {
            ExFreePool(imageName);
        }
    }

    ObDereferenceObject(process);
}
