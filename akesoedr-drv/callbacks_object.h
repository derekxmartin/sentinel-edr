/*
 * akesoedr-drv/callbacks_object.h
 * Object handle callback registration (Ch. 4 — ObRegisterCallbacks).
 *
 * Monitors OB_OPERATION_HANDLE_CREATE and OB_OPERATION_HANDLE_DUPLICATE
 * for Process and Thread object types, targeting protected processes
 * (lsass.exe, csrss.exe, services.exe).
 */

#ifndef AKESOEDR_CALLBACKS_OBJECT_H
#define AKESOEDR_CALLBACKS_OBJECT_H

#include <fltKernel.h>

/*
 * Register object handle callbacks via ObRegisterCallbacks.
 * Call from DriverEntry after thread callback is initialized.
 * Requires /INTEGRITYCHECK linker flag.
 */
NTSTATUS
AkesoEDRObjectCallbackInit(VOID);

/*
 * Unregister object handle callbacks.
 * Call from DriverUnload before thread/process callback teardown.
 * Safe to call if Init was never called or already stopped.
 */
VOID
AkesoEDRObjectCallbackStop(VOID);

#endif /* AKESOEDR_CALLBACKS_OBJECT_H */
