/*
 * sentinel-drv/callbacks_thread.h
 * Thread creation/termination callback registration.
 *
 * Uses PsSetCreateThreadNotifyRoutineEx to receive notifications for
 * every thread create and terminate on the system. Flags remote thread
 * creation (creating PID != owning PID).
 *
 * Book reference: Chapter 3 -- Process- and Thread-Creation Notifications.
 */

#ifndef SENTINEL_CALLBACKS_THREAD_H
#define SENTINEL_CALLBACKS_THREAD_H

#include <fltKernel.h>

/*
 * Register the thread creation callback.
 * Call from DriverEntry after process callback is initialized.
 */
NTSTATUS
SentinelThreadCallbackInit(VOID);

/*
 * Unregister the thread creation callback.
 * Call from DriverUnload before process callback is torn down.
 * Safe to call if Init was never called or already stopped.
 */
VOID
SentinelThreadCallbackStop(VOID);

#endif /* SENTINEL_CALLBACKS_THREAD_H */
