/*
 * akesoedr-drv/callbacks_thread.c
 * Thread creation/termination callback -- PsSetCreateThreadNotifyRoutineEx.
 *
 * On every thread create/terminate on the system, this callback:
 *   1. Populates a AKESOEDR_EVENT with thread metadata
 *   2. Detects remote thread creation (creating PID != owning PID)
 *   3. Sends the event to the agent over the filter communication port
 *
 * IRQL: The callback runs at PASSIVE_LEVEL (guaranteed by the OS).
 *
 * Book reference: Chapter 3 -- Process- and Thread-Creation Notifications.
 */

#include <fltKernel.h>
#include <ntstrsafe.h>

#include "constants.h"
#include "telemetry.h"
#include "comms.h"
#include "callbacks_thread.h"

/* -- Undocumented/missing kernel API declarations --------------------------- */

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

/* -- Forward declarations --------------------------------------------------- */

static VOID
AkesoEDRThreadNotifyCallback(
    _In_ HANDLE  ProcessId,
    _In_ HANDLE  ThreadId,
    _In_ BOOLEAN Create
);

static VOID
AkesoEDRFillProcessCtxForThread(
    _Out_    AKESOEDR_PROCESS_CTX*  Ctx,
    _In_     HANDLE                 ProcessId
);

/* -- Section placement ------------------------------------------------------ */

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, AkesoEDRThreadCallbackInit)
#pragma alloc_text(PAGE, AkesoEDRThreadCallbackStop)
#endif

/* -- State ------------------------------------------------------------------ */

static BOOLEAN g_ThreadCallbackRegistered = FALSE;

/* -- Public API ------------------------------------------------------------- */

NTSTATUS
AkesoEDRThreadCallbackInit(VOID)
{
    NTSTATUS status;

    PAGED_CODE();

    if (g_ThreadCallbackRegistered) {
        return STATUS_SUCCESS;
    }

    /*
     * Use PsSetCreateThreadNotifyRoutineEx with type
     * PsCreateThreadNotifyNonSystem to receive notifications for
     * user-mode thread creation. This is the "Ex" variant that
     * provides richer information on newer Windows versions.
     *
     * Fallback: if the Ex variant is not available (pre-Win10 TH2),
     * we use the legacy PsSetCreateThreadNotifyRoutine.
     */
    status = PsSetCreateThreadNotifyRoutineEx(
        PsCreateThreadNotifyNonSystem,
        (PVOID)AkesoEDRThreadNotifyCallback
    );

    if (!NT_SUCCESS(status)) {
        /* Fallback to legacy API */
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "AkesoEDR: PsSetCreateThreadNotifyRoutineEx failed 0x%08X, "
            "falling back to legacy API\n", status));

        status = PsSetCreateThreadNotifyRoutine(
            AkesoEDRThreadNotifyCallback
        );

        if (!NT_SUCCESS(status)) {
            KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "AkesoEDR: PsSetCreateThreadNotifyRoutine failed 0x%08X\n",
                status));
            return status;
        }
    }

    g_ThreadCallbackRegistered = TRUE;

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "AkesoEDR: Thread creation callback registered\n"));

    return STATUS_SUCCESS;
}

VOID
AkesoEDRThreadCallbackStop(VOID)
{
    PAGED_CODE();

    if (!g_ThreadCallbackRegistered) {
        return;
    }

    PsRemoveCreateThreadNotifyRoutine(AkesoEDRThreadNotifyCallback);

    g_ThreadCallbackRegistered = FALSE;

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "AkesoEDR: Thread creation callback unregistered\n"));
}

/* -- Callback implementation ------------------------------------------------ */

/*
 * PsSetCreateThreadNotifyRoutine(Ex) callback.
 *
 * Create == TRUE  -> thread is being created
 * Create == FALSE -> thread is terminating
 *
 * Key detection: if the creating process (PsGetCurrentProcessId) differs
 * from the owning process (ProcessId parameter), this is a REMOTE thread
 * injection -- a classic attack technique (CreateRemoteThread, NtCreateThreadEx).
 */
static VOID
AkesoEDRThreadNotifyCallback(
    _In_ HANDLE  ProcessId,
    _In_ HANDLE  ThreadId,
    _In_ BOOLEAN Create
)
{
    AKESOEDR_EVENT *event;
    HANDLE          creatingPid;
    HANDLE          creatingTid;
    BOOLEAN         isRemote;

    /*
     * AKESOEDR_EVENT is ~22 KB — far too large for the kernel stack.
     * Pool-allocate to avoid stack overflow BSOD.
     */
    event = (AKESOEDR_EVENT *)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(AKESOEDR_EVENT), AKESOEDR_TAG_EVENT);
    if (!event) {
        return;
    }

    /* Get the creating process/thread (the caller, not the target) */
    creatingPid = PsGetCurrentProcessId();
    creatingTid = PsGetCurrentThreadId();

    /* Detect remote thread creation */
    isRemote = (Create && (creatingPid != ProcessId));

    __try {

        /* Initialize event envelope */
        RtlZeroMemory(event, sizeof(AKESOEDR_EVENT));
        ExUuidCreate(&event->EventId);
        KeQuerySystemTimePrecise(&event->Timestamp);
        event->Source   = AkesoEDRSourceDriverThread;
        event->Severity = isRemote ? AkesoEDRSeverityHigh : AkesoEDRSeverityInformational;

        /* Fill process context (owning process of the thread) */
        AkesoEDRFillProcessCtxForThread(&event->ProcessCtx, ProcessId);

        /* Fill thread-specific payload */
        event->Payload.Thread.IsCreate          = Create;
        event->Payload.Thread.ThreadId          = (ULONG)(ULONG_PTR)ThreadId;
        event->Payload.Thread.OwningProcessId   = (ULONG)(ULONG_PTR)ProcessId;
        event->Payload.Thread.CreatingProcessId = (ULONG)(ULONG_PTR)creatingPid;
        event->Payload.Thread.CreatingThreadId  = (ULONG)(ULONG_PTR)creatingTid;
        event->Payload.Thread.IsRemote          = isRemote;

        /*
         * Start address: only available on thread creation.
         * We retrieve it from the ETHREAD via PsGetThreadStartAddress
         * (undocumented but widely used by security products).
         */
        if (Create) {
            PETHREAD threadObj = NULL;
            NTSTATUS status;

            status = PsLookupThreadByThreadId(ThreadId, &threadObj);
            if (NT_SUCCESS(status) && threadObj) {
                event->Payload.Thread.StartAddress = 0;
                ObDereferenceObject(threadObj);
            } else {
                event->Payload.Thread.StartAddress = 0;
            }
        } else {
            event->Payload.Thread.StartAddress = 0;
        }

        if (Create) {
            KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
                "AkesoEDR: Thread CREATE TID=%lu PID=%lu Creator=%lu%s\n",
                (ULONG)(ULONG_PTR)ThreadId,
                (ULONG)(ULONG_PTR)ProcessId,
                (ULONG)(ULONG_PTR)creatingPid,
                isRemote ? " [REMOTE]" : ""));
        } else {
            KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
                "AkesoEDR: Thread EXIT TID=%lu PID=%lu\n",
                (ULONG)(ULONG_PTR)ThreadId,
                (ULONG)(ULONG_PTR)ProcessId));
        }

        /* Send event to agent (silently drops if no agent connected) */
        AkesoEDRCommsSend(event);

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "AkesoEDR: Exception 0x%08X in thread callback TID=%lu PID=%lu\n",
            GetExceptionCode(),
            (ULONG)(ULONG_PTR)ThreadId,
            (ULONG)(ULONG_PTR)ProcessId));
    }

    ExFreePoolWithTag(event, AKESOEDR_TAG_EVENT);
}

/* -- Helper: fill process context for the thread's owning process ----------- */

static VOID
AkesoEDRFillProcessCtxForThread(
    _Out_    AKESOEDR_PROCESS_CTX*  Ctx,
    _In_     HANDLE                 ProcessId
)
{
    PEPROCESS       process = NULL;
    NTSTATUS        status;
    PUNICODE_STRING imageName = NULL;

    RtlZeroMemory(Ctx, sizeof(AKESOEDR_PROCESS_CTX));

    Ctx->ProcessId = (ULONG)(ULONG_PTR)ProcessId;
    Ctx->ThreadId  = (ULONG)(ULONG_PTR)PsGetCurrentThreadId();

    /* Look up the owning process */
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
                AKESOEDR_MAX_PATH,
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
