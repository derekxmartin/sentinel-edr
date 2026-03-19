/*
 * akesoedr-drv/minifilter_pipes.h
 * Named pipe creation monitoring.
 *
 * Pipe events arrive via two IRP paths:
 *   - IRP_MJ_CREATE on NPFS (\Device\NamedPipe\...) for client connections
 *   - IRP_MJ_CREATE_NAMED_PIPE for server-side pipe creation
 *     (NtCreateNamedPipeFile, used by CreateNamedPipe / NamedPipeServerStream)
 *
 * PostCreate detects client opens by path prefix check.
 * Pre/PostCreateNamedPipe handles server-side creation directly.
 *
 * P5-T3: Named Pipe Monitoring.
 */

#ifndef AKESOEDR_MINIFILTER_PIPES_H
#define AKESOEDR_MINIFILTER_PIPES_H

#include <fltKernel.h>

/*
 * Check if a file path refers to a named pipe (\Device\NamedPipe\...).
 * Called from PostCreate to decide whether to emit a pipe event.
 */
BOOLEAN
AkesoEDRPipeIsNamedPipePath(
    _In_ const UNICODE_STRING *FilePath
);

/*
 * Emit a AKESOEDR_PIPE_EVENT for a named pipe creation or open.
 * Called from PostCreate (client) and PostCreateNamedPipe (server).
 */
VOID
AkesoEDRPipeEmitEvent(
    _In_ PFLT_CALLBACK_DATA    Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects
);

/*
 * IRP_MJ_CREATE_NAMED_PIPE callbacks — server-side pipe creation.
 * NtCreateNamedPipeFile dispatches this IRP when a process creates
 * a new named pipe instance.
 */
FLT_PREOP_CALLBACK_STATUS
AkesoEDRPreCreateNamedPipe(
    _Inout_ PFLT_CALLBACK_DATA          Data,
    _In_    PCFLT_RELATED_OBJECTS        FltObjects,
    _Out_   PVOID                       *CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS
AkesoEDRPostCreateNamedPipe(
    _Inout_  PFLT_CALLBACK_DATA         Data,
    _In_     PCFLT_RELATED_OBJECTS       FltObjects,
    _In_opt_ PVOID                       CompletionContext,
    _In_     FLT_POST_OPERATION_FLAGS    Flags
);

#endif /* AKESOEDR_MINIFILTER_PIPES_H */
