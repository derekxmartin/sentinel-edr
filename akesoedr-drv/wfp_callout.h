/*
 * akesoedr-drv/wfp_callout.h
 * Windows Filtering Platform (WFP) callout registration.
 *
 * Registers inspection-only callouts on ALE Auth Connect v4 (outbound)
 * and ALE Auth Recv/Accept v4 (inbound) layers. Classify functions
 * extract connection metadata and emit AKESOEDR_NETWORK_EVENT telemetry.
 * All traffic is permitted — callouts never block.
 *
 * Book reference: Chapter 7 — Network Filter Drivers.
 * AkesoEDR Phase 6, Task 1.
 */

#ifndef AKESOEDR_WFP_CALLOUT_H
#define AKESOEDR_WFP_CALLOUT_H

#include <fltKernel.h>

/*
 * AkesoEDRWfpInit — Register WFP callouts and filters.
 *
 * Opens a BFE session, registers callouts for outbound (Connect v4)
 * and inbound (Recv/Accept v4) ALE layers, adds sublayer and filters.
 * Must be called at PASSIVE_LEVEL after IoCreateDevice.
 *
 * @param DeviceObject  The driver's device object (required by FwpsCalloutRegister).
 * @return STATUS_SUCCESS on success, or an NTSTATUS error code.
 */
NTSTATUS
AkesoEDRWfpInit(
    _In_ PDEVICE_OBJECT DeviceObject
);

/*
 * AkesoEDRWfpStop — Unregister WFP callouts and close engine session.
 *
 * Closes the BFE engine handle (which removes sublayer, filters, and
 * management callouts) then unregisters runtime callouts. Safe to call
 * even if AkesoEDRWfpInit was never called or failed.
 *
 * Must be called at PASSIVE_LEVEL.
 */
VOID
AkesoEDRWfpStop(void);

#endif /* AKESOEDR_WFP_CALLOUT_H */
