/*
 * akesoedr-agent/etw/provider_dns.h
 * Parser for Microsoft-Windows-DNS-Client ETW events.
 *
 * P7-T2: DNS + PowerShell + Kerberos ETW Providers.
 * Book reference: Chapter 8 — Event Tracing for Windows.
 */

#ifndef AKESOEDR_ETW_PROVIDER_DNS_H
#define AKESOEDR_ETW_PROVIDER_DNS_H

#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include "../../common/telemetry.h"

/*
 * Parse a DNS-Client ETW event into a AKESOEDR_EVENT.
 *
 * Handles:
 *   Event 3008 — DNS query completed (QueryName, QueryType, QueryStatus)
 *   Event 3020 — DNS cache lookup   (QueryName, QueryType)
 *
 * Returns true if the event was successfully parsed, false to skip.
 */
bool ParseDnsEvent(PEVENT_RECORD pEvent, AKESOEDR_EVENT* outEvent);

#endif /* AKESOEDR_ETW_PROVIDER_DNS_H */
