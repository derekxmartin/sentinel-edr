/*
 * akesoedr-drv/minifilter.h
 * Filesystem minifilter I/O callbacks.
 *
 * Pre-operation callbacks filter out excluded paths and noise.
 * Post-operation callbacks emit AKESOEDR_FILE_EVENT telemetry
 * for successful file create, write, rename, and delete operations.
 *
 * P5-T1: Minifilter Registration & I/O Callbacks.
 */

#ifndef AKESOEDR_MINIFILTER_H
#define AKESOEDR_MINIFILTER_H

#include <fltKernel.h>
#include "telemetry.h"

/* ── Shared helpers (used by file_hash.c, minifilter_pipes.c) ─────────────── */

BOOLEAN
AkesoEDRMinifilterShouldSkipPreOp(
    _In_ PFLT_CALLBACK_DATA Data
);

void
AkesoEDRMinifilterFillProcessCtx(
    _Out_ AKESOEDR_PROCESS_CTX *Ctx,
    _In_  PFLT_CALLBACK_DATA    Data
);

void
AkesoEDRMinifilterEmitFileEvent(
    _In_ PFLT_CALLBACK_DATA    Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ AKESOEDR_FILE_OP      Operation
);

/* ── IRP_MJ_CREATE ──────────────────────────────────────────────────────── */

FLT_PREOP_CALLBACK_STATUS
AkesoEDRPreCreate(
    _Inout_ PFLT_CALLBACK_DATA          Data,
    _In_    PCFLT_RELATED_OBJECTS        FltObjects,
    _Out_ PVOID *CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS
AkesoEDRPostCreate(
    _Inout_  PFLT_CALLBACK_DATA         Data,
    _In_     PCFLT_RELATED_OBJECTS       FltObjects,
    _In_opt_ PVOID                       CompletionContext,
    _In_     FLT_POST_OPERATION_FLAGS    Flags
);

/* ── IRP_MJ_WRITE ───────────────────────────────────────────────────────── */

FLT_PREOP_CALLBACK_STATUS
AkesoEDRPreWrite(
    _Inout_ PFLT_CALLBACK_DATA          Data,
    _In_    PCFLT_RELATED_OBJECTS        FltObjects,
    _Out_ PVOID *CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS
AkesoEDRPostWrite(
    _Inout_  PFLT_CALLBACK_DATA         Data,
    _In_     PCFLT_RELATED_OBJECTS       FltObjects,
    _In_opt_ PVOID                       CompletionContext,
    _In_     FLT_POST_OPERATION_FLAGS    Flags
);

/* ── IRP_MJ_SET_INFORMATION (rename / delete / metadata) ────────────────── */

FLT_PREOP_CALLBACK_STATUS
AkesoEDRPreSetInfo(
    _Inout_ PFLT_CALLBACK_DATA          Data,
    _In_    PCFLT_RELATED_OBJECTS        FltObjects,
    _Out_ PVOID *CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS
AkesoEDRPostSetInfo(
    _Inout_  PFLT_CALLBACK_DATA         Data,
    _In_     PCFLT_RELATED_OBJECTS       FltObjects,
    _In_opt_ PVOID                       CompletionContext,
    _In_     FLT_POST_OPERATION_FLAGS    Flags
);

#endif /* AKESOEDR_MINIFILTER_H */
