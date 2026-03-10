/*
 * sentinel-drv/callbacks_imageload.h
 * Image-load callback registration (Ch. 5 — PsSetLoadImageNotifyRoutineEx).
 */

#ifndef SENTINEL_CALLBACKS_IMAGELOAD_H
#define SENTINEL_CALLBACKS_IMAGELOAD_H

#include <fltKernel.h>

/*
 * SentinelImageLoadCallbackInit
 *   Register image-load notification callback.
 *   Must be called at PASSIVE_LEVEL (e.g., from DriverEntry).
 */
NTSTATUS
SentinelImageLoadCallbackInit(VOID);

/*
 * SentinelImageLoadCallbackStop
 *   Unregister image-load notification callback.
 *   Must be called at PASSIVE_LEVEL (e.g., from DriverUnload).
 */
VOID
SentinelImageLoadCallbackStop(VOID);

#endif /* SENTINEL_CALLBACKS_IMAGELOAD_H */
