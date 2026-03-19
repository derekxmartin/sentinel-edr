/*
 * akesoedr-drv/callbacks_imageload.h
 * Image-load callback registration (Ch. 5 — PsSetLoadImageNotifyRoutineEx).
 */

#ifndef AKESOEDR_CALLBACKS_IMAGELOAD_H
#define AKESOEDR_CALLBACKS_IMAGELOAD_H

#include <fltKernel.h>

/*
 * AkesoEDRImageLoadCallbackInit
 *   Register image-load notification callback.
 *   Must be called at PASSIVE_LEVEL (e.g., from DriverEntry).
 */
NTSTATUS
AkesoEDRImageLoadCallbackInit(VOID);

/*
 * AkesoEDRImageLoadCallbackStop
 *   Unregister image-load notification callback.
 *   Must be called at PASSIVE_LEVEL (e.g., from DriverUnload).
 */
VOID
AkesoEDRImageLoadCallbackStop(VOID);

#endif /* AKESOEDR_CALLBACKS_IMAGELOAD_H */
