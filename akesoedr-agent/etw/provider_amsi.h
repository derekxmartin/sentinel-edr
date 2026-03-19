/*
 * akesoedr-agent/etw/provider_amsi.h
 * Parser for Microsoft-Antimalware-Scan-Interface ETW events.
 *
 * P7-T3: AMSI + RPC + Kernel-Process ETW Providers.
 * Book reference: Chapter 8 — Event Tracing for Windows.
 */

#ifndef AKESOEDR_ETW_PROVIDER_AMSI_H
#define AKESOEDR_ETW_PROVIDER_AMSI_H

#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include "../../common/telemetry.h"

/*
 * Parse an AMSI ETW event into a AKESOEDR_EVENT.
 *
 * Handles:
 *   Event 1101 — AMSI scan result (AppName, ContentName, ScanResult,
 *                ContentSize)
 *
 * AMSI events are routed through Payload.Amsi (Source = AkesoEDRSourceAmsi),
 * NOT through Payload.Etw, because the AKESOEDR_AMSI_EVENT struct already
 * has the correct fields. This reuses the existing JSON serialization path.
 *
 * Returns true if the event was successfully parsed, false to skip.
 */
bool ParseAmsiEvent(PEVENT_RECORD pEvent, AKESOEDR_EVENT* outEvent);

#endif /* AKESOEDR_ETW_PROVIDER_AMSI_H */
