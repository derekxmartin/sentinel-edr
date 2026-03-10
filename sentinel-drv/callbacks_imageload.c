/*
 * sentinel-drv/callbacks_imageload.c
 * Image-load callback implementation (Ch. 5 — PsSetLoadImageNotifyRoutineEx).
 *
 * On every image (EXE, DLL, driver) load on the system, this callback:
 *   1. Populates a SENTINEL_EVENT with image metadata
 *   2. Determines signing status via IMAGE_INFO signature fields
 *   3. Sends the event to the agent over the filter communication port
 *
 * Noise reduction: kernel-mode image loads (drivers) are skipped by default
 * since we primarily care about user-mode DLL/EXE loads for detection.
 *
 * IRQL: The callback runs at PASSIVE_LEVEL (guaranteed by the OS).
 *
 * Book reference: Chapter 5 — Image-Load and Registry Notifications.
 */

#include <fltKernel.h>
#include <ntimage.h>
#include <ntstrsafe.h>

#include "callbacks_imageload.h"
#include "constants.h"
#include "telemetry.h"
#include "comms.h"

/* ── Undocumented but stable kernel APIs ────────────────────────────────── */

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

/* ── Signature level constants (ntddk.h may not define all of these) ───── */

#ifndef SE_SIGNING_LEVEL_UNSIGNED
#define SE_SIGNING_LEVEL_UNSIGNED       0x00
#endif

#ifndef SE_SIGNING_LEVEL_AUTHENTICODE
#define SE_SIGNING_LEVEL_AUTHENTICODE   0x04
#endif

/* ── PE certificate check helper declaration ────────────────────────────── */

static BOOLEAN
SentinelCheckImageSigned(
    _In_ PIMAGE_INFO ImageInfo,
    _Out_ PBOOLEAN   IsValid
);

/* ── Forward declarations ───────────────────────────────────────────────── */

static VOID
SentinelImageLoadCallback(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_     HANDLE          ProcessId,
    _In_     PIMAGE_INFO     ImageInfo
);

static VOID
SentinelFillProcessCtxForImageLoad(
    _Out_ SENTINEL_PROCESS_CTX* Ctx,
    _In_  HANDLE                ProcessId
);

/* ── Section placement ──────────────────────────────────────────────────── */

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, SentinelImageLoadCallbackInit)
#pragma alloc_text(PAGE, SentinelImageLoadCallbackStop)
#endif

/* ── State ──────────────────────────────────────────────────────────────── */

static BOOLEAN g_ImageLoadCallbackRegistered = FALSE;

/* ── Public API ─────────────────────────────────────────────────────────── */

NTSTATUS
SentinelImageLoadCallbackInit(VOID)
{
    NTSTATUS status;

    PAGED_CODE();

    if (g_ImageLoadCallbackRegistered) {
        return STATUS_SUCCESS;
    }

    /*
     * PsSetLoadImageNotifyRoutineEx accepts a Flags parameter.
     * Flag 0 = standard behavior (notify for all image loads).
     * If the Ex variant is unavailable (pre-Win10 1709), fall back
     * to PsSetLoadImageNotifyRoutine.
     */
    status = PsSetLoadImageNotifyRoutineEx(
        SentinelImageLoadCallback,
        0       /* Flags — standard behavior */
    );

    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "SentinelPOC: PsSetLoadImageNotifyRoutineEx failed 0x%08X, "
            "falling back to legacy API\n", status));

        status = PsSetLoadImageNotifyRoutine(SentinelImageLoadCallback);

        if (!NT_SUCCESS(status)) {
            KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "SentinelPOC: PsSetLoadImageNotifyRoutine failed 0x%08X\n",
                status));
            return status;
        }
    }

    g_ImageLoadCallbackRegistered = TRUE;

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "SentinelPOC: Image-load callback registered\n"));

    return STATUS_SUCCESS;
}

VOID
SentinelImageLoadCallbackStop(VOID)
{
    PAGED_CODE();

    if (!g_ImageLoadCallbackRegistered) {
        return;
    }

    PsRemoveLoadImageNotifyRoutine(SentinelImageLoadCallback);

    g_ImageLoadCallbackRegistered = FALSE;

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "SentinelPOC: Image-load callback unregistered\n"));
}

/* ── Callback implementation ────────────────────────────────────────────── */

/*
 * PsSetLoadImageNotifyRoutine(Ex) callback.
 *
 * Called for every image load (EXE, DLL, driver) system-wide.
 *
 * ProcessId == 0 means a kernel-mode driver is being loaded.
 * ImageInfo->SystemModeImage indicates the image is mapped into
 * kernel address space.
 *
 * Signing status: On Win10+, IMAGE_INFO contains ImageSignatureLevel
 * and ImageSignatureType as bit fields. We use these to determine
 * whether the image is signed and whether the signature is valid.
 */
static VOID
SentinelImageLoadCallback(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_     HANDLE          ProcessId,
    _In_     PIMAGE_INFO     ImageInfo
)
{
    SENTINEL_EVENT *event;

    if (!ImageInfo) {
        return;
    }

    /*
     * Skip kernel-mode image loads (drivers) to reduce noise.
     * We primarily care about user-mode DLL/EXE loads for
     * detection purposes (credential dumping DLLs, injection, etc.).
     */
    if (ImageInfo->SystemModeImage) {
        return;
    }

    /* Skip PID 0 (system/idle) loads */
    if ((ULONG_PTR)ProcessId == 0) {
        return;
    }

    /* ── Allocate and fill event ────────────────────────────────────────── */

    event = (SENTINEL_EVENT *)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(SENTINEL_EVENT), SENTINEL_TAG_EVENT);
    if (!event) {
        return;
    }

    __try {
        RtlZeroMemory(event, sizeof(SENTINEL_EVENT));
        ExUuidCreate(&event->EventId);
        KeQuerySystemTimePrecise(&event->Timestamp);
        event->Source   = SentinelSourceDriverImageLoad;
        event->Severity = SentinelSeverityInformational;

        /* Fill process context for the loading process */
        SentinelFillProcessCtxForImageLoad(&event->ProcessCtx, ProcessId);

        /* Fill image-load payload */
        event->Payload.ImageLoad.ProcessId = (ULONG)(ULONG_PTR)ProcessId;

        /* Image path */
        if (FullImageName && FullImageName->Buffer && FullImageName->Length > 0) {
            RtlStringCchCopyNW(
                event->Payload.ImageLoad.ImagePath,
                SENTINEL_MAX_PATH,
                FullImageName->Buffer,
                FullImageName->Length / sizeof(WCHAR));
        }

        /* Image base and size */
        event->Payload.ImageLoad.ImageBase = (ULONG_PTR)ImageInfo->ImageBase;
        event->Payload.ImageLoad.ImageSize = ImageInfo->ImageSize;

        /* Kernel vs user mode */
        event->Payload.ImageLoad.IsKernelImage = ImageInfo->SystemModeImage;

        /*
         * Signing status: try IMAGE_INFO bit fields first (Win10+),
         * fall back to PE certificate directory check via IMAGE_INFO_EX.
         */
        {
            BOOLEAN isSigned = FALSE;
            BOOLEAN isValid  = FALSE;
            ULONG sigLevel = ImageInfo->ImageSignatureLevel;

            if (sigLevel > SE_SIGNING_LEVEL_UNSIGNED) {
                /* Kernel populated the signature level — use it */
                isSigned = TRUE;
                isValid  = (sigLevel >= SE_SIGNING_LEVEL_AUTHENTICODE);
            } else {
                /*
                 * Signature level is 0 — common on test-signing-enabled
                 * VMs or older Win10 builds. Fall back to checking the PE
                 * IMAGE_DIRECTORY_ENTRY_SECURITY via the file object.
                 */
                isSigned = SentinelCheckImageSigned(ImageInfo, &isValid);
            }

            event->Payload.ImageLoad.IsSigned = isSigned;
            event->Payload.ImageLoad.IsSignatureValid = isValid;
        }

        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
            "SentinelPOC: ImageLoad PID=%lu Base=0x%p Size=0x%IX Signed=%d %wZ\n",
            (ULONG)(ULONG_PTR)ProcessId,
            ImageInfo->ImageBase,
            ImageInfo->ImageSize,
            event->Payload.ImageLoad.IsSigned,
            FullImageName));

        SentinelCommsSend(event);

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "SentinelPOC: Exception 0x%08X in image-load callback PID=%lu\n",
            GetExceptionCode(),
            (ULONG)(ULONG_PTR)ProcessId));
    }

    ExFreePoolWithTag(event, SENTINEL_TAG_EVENT);
}

/* ── Helper: check PE Authenticode signature via file object ────────────── */

/*
 * SentinelCheckImageSigned
 *
 * When IMAGE_INFO.ImageSignatureLevel is not populated (common on
 * test-signing-enabled VMs), we fall back to reading the PE header's
 * IMAGE_DIRECTORY_ENTRY_SECURITY to check if an Authenticode
 * certificate table is present.
 *
 * This requires IMAGE_INFO_EX (ExtendedInfoPresent == TRUE) to get
 * the FileObject, then reads the PE header from the mapped image.
 *
 * Returns TRUE if signed (has certificate table), FALSE otherwise.
 * Sets *IsValid to TRUE if certificate table size > 0 (basic check).
 */
static BOOLEAN
SentinelCheckImageSigned(
    _In_ PIMAGE_INFO ImageInfo,
    _Out_ PBOOLEAN   IsValid
)
{
    PIMAGE_DOS_HEADER       dosHeader;
    PIMAGE_NT_HEADERS       ntHeaders;
    IMAGE_DATA_DIRECTORY    securityDir;

    *IsValid = FALSE;

    if (!ImageInfo->ImageBase) {
        return FALSE;
    }

    __try {
        dosHeader = (PIMAGE_DOS_HEADER)ImageInfo->ImageBase;

        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            return FALSE;
        }

        ntHeaders = (PIMAGE_NT_HEADERS)(
            (PUCHAR)ImageInfo->ImageBase + dosHeader->e_lfanew);

        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            return FALSE;
        }

        /*
         * IMAGE_DIRECTORY_ENTRY_SECURITY = 4
         * Check if the certificate table data directory is populated.
         */
        if (ntHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            PIMAGE_NT_HEADERS64 nt64 = (PIMAGE_NT_HEADERS64)ntHeaders;

            if (nt64->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_SECURITY) {
                return FALSE;
            }

            securityDir = nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
        } else if (ntHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            PIMAGE_NT_HEADERS32 nt32 = (PIMAGE_NT_HEADERS32)ntHeaders;

            if (nt32->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_SECURITY) {
                return FALSE;
            }

            securityDir = nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
        } else {
            return FALSE;
        }

        /*
         * If VirtualAddress and Size are nonzero, the PE has an
         * embedded Authenticode certificate table. This is a basic
         * presence check — not a full signature verification.
         */
        if (securityDir.VirtualAddress != 0 && securityDir.Size > 0) {
            *IsValid = TRUE;  /* Has certificate — assume valid for POC */
            return TRUE;
        }

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "SentinelPOC: Exception checking PE signature: 0x%08X\n",
            GetExceptionCode()));
    }

    return FALSE;
}

/* ── Helper: fill process context for the loading process ──────────────── */

static VOID
SentinelFillProcessCtxForImageLoad(
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

    /* Look up the process */
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
