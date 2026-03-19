/*
 * akesoedr-drv/callbacks_thread.h
 * Thread creation/termination callback registration.
 *
 * Uses PsSetCreateThreadNotifyRoutineEx to receive notifications for
 * every thread create and terminate on the system. Flags remote thread
 * creation (creating PID != owning PID).
 *
 * Book reference: Chapter 3 -- Process- and Thread-Creation Notifications.
 */

#ifndef AKESOEDR_CALLBACKS_THREAD_H
#define AKESOEDR_CALLBACKS_THREAD_H

#include <fltKernel.h>

/*
 * Register the thread creation callback.
 * Call from DriverEntry after process callback is initialized.
 */
NTSTATUS
AkesoEDRThreadCallbackInit(VOID);

/*
 * Unregister the thread creation callback.
 * Call from DriverUnload before process callback is torn down.
 * Safe to call if Init was never called or already stopped.
 */
VOID
AkesoEDRThreadCallbackStop(VOID);

#endif /* AKESOEDR_CALLBACKS_THREAD_H */
