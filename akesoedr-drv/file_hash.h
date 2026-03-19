/*
 * akesoedr-drv/file_hash.h
 * Asynchronous SHA-256 file hashing for minifilter post-create events.
 *
 * Hash computation is deferred to a kernel work item so the I/O path
 * is not blocked.  The BCrypt algorithm provider is opened once at
 * driver init and reused for all hash operations.
 *
 * P5-T2: File Hashing.
 * Book reference: Chapter 6 — Filesystem Minifilter Drivers.
 */

#ifndef AKESOEDR_FILE_HASH_H
#define AKESOEDR_FILE_HASH_H

#include <fltKernel.h>
#include "telemetry.h"

/* ── Lifecycle ──────────────────────────────────────────────────────────── */

/*
 * Open the BCrypt SHA-256 algorithm provider.
 * Called from DriverEntry after minifilter registration.
 */
NTSTATUS AkesoEDRFileHashInit(VOID);

/*
 * Drain in-flight work items and close the algorithm provider.
 * Called from AkesoEDRFilterUnload / DriverUnload.
 */
VOID AkesoEDRFileHashStop(VOID);

/* ── Async hash + event emission ────────────────────────────────────────── */

/*
 * Queue an asynchronous work item to hash the file and emit the event.
 * Called from AkesoEDRPostCreate for content-modifying creates
 * (FILE_CREATED, FILE_OVERWRITTEN, FILE_SUPERSEDED).
 *
 * On failure (pool exhaustion, etc.), falls back to synchronous
 * event emission without hash.
 */
VOID
AkesoEDRFileHashQueueWorkItem(
    _In_ PFLT_CALLBACK_DATA    Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ AKESOEDR_FILE_OP      Operation
);

#endif /* AKESOEDR_FILE_HASH_H */
