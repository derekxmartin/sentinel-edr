/*
 * akesoedr-drv/callbacks_process.h
 * Process creation/termination callback registration.
 *
 * Uses PsSetCreateProcessNotifyRoutineEx to receive notifications for
 * every process create and terminate on the system.
 *
 * Book reference: Chapter 3 — Process- and Thread-Creation Notifications.
 */

#ifndef AKESOEDR_CALLBACKS_PROCESS_H
#define AKESOEDR_CALLBACKS_PROCESS_H

#include <fltKernel.h>

/*
 * Register the process creation callback.
 * Call from DriverEntry after comms port is initialized.
 */
NTSTATUS
AkesoEDRProcessCallbackInit(VOID);

/*
 * Unregister the process creation callback.
 * Call from DriverUnload before comms port is torn down.
 * Safe to call if Init was never called or already stopped.
 */
VOID
AkesoEDRProcessCallbackStop(VOID);

#endif /* AKESOEDR_CALLBACKS_PROCESS_H */
