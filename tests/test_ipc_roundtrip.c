/*
 * tests/test_ipc_roundtrip.c
 * Unit test: serialize a AKESOEDR_EVENT, deserialize it, verify round-trip.
 *
 * Build: compiled as part of the tests/ CMake target.
 * Run:   test_ipc_roundtrip.exe — exits 0 on success, 1 on failure.
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <objbase.h>    /* CoCreateGuid */

#include "telemetry.h"
#include "ipc.h"
#include "ipc_serialize.h"

/* ── Test helpers ────────────────────────────────────────────────────────── */

static int g_tests_run    = 0;
static int g_tests_passed = 0;

#define TEST_ASSERT(cond, msg)                                      \
    do {                                                            \
        g_tests_run++;                                              \
        if (!(cond)) {                                              \
            printf("  FAIL: %s (line %d)\n", (msg), __LINE__);     \
            return 1;                                               \
        } else {                                                    \
            g_tests_passed++;                                       \
        }                                                           \
    } while (0)

/* ── Test: header init and validate ──────────────────────────────────────── */

static int test_header_init_validate(void)
{
    AKESOEDR_IPC_HEADER hdr;
    AKESOEDR_SERIALIZE_STATUS status;

    printf("[test_header_init_validate]\n");

    AkesoEDRIpcHeaderInit(&hdr, AkesoEDRMsgEvent, 1234, 42);

    TEST_ASSERT(hdr.Magic == AKESOEDR_IPC_MAGIC,    "magic matches");
    TEST_ASSERT(hdr.Version == AKESOEDR_IPC_VERSION, "version matches");
    TEST_ASSERT(hdr.Type == AkesoEDRMsgEvent,       "type matches");
    TEST_ASSERT(hdr.PayloadSize == 1234,            "payload size matches");
    TEST_ASSERT(hdr.SequenceNum == 42,              "sequence num matches");

    status = AkesoEDRIpcHeaderValidate(&hdr);
    TEST_ASSERT(status == AkesoEDRSerializeOk, "header validates ok");

    /* Bad magic */
    hdr.Magic = 0xDEADBEEF;
    status = AkesoEDRIpcHeaderValidate(&hdr);
    TEST_ASSERT(status == AkesoEDRSerializeBadMagic, "bad magic detected");

    /* Restore and test bad version */
    hdr.Magic = AKESOEDR_IPC_MAGIC;
    hdr.Version = 999;
    status = AkesoEDRIpcHeaderValidate(&hdr);
    TEST_ASSERT(status == AkesoEDRSerializeBadVersion, "bad version detected");

    printf("  OK\n");
    return 0;
}

/* ── Test: frame write and read ──────────────────────────────────────────── */

static int test_frame_write_read(void)
{
    BYTE buffer[256];
    BYTE payload[] = { 0x41, 0x42, 0x43, 0x44 };
    BYTE out[256];
    UINT32 bytesWritten = 0;
    UINT32 bytesRead = 0;
    AKESOEDR_SERIALIZE_STATUS status;

    printf("[test_frame_write_read]\n");

    /* Write a simple frame */
    status = AkesoEDRIpcWriteFrame(buffer, sizeof(buffer), payload, sizeof(payload), &bytesWritten);
    TEST_ASSERT(status == AkesoEDRSerializeOk, "write frame succeeds");
    TEST_ASSERT(bytesWritten == sizeof(UINT32) + sizeof(payload), "correct bytes written");

    /* Verify length prefix */
    TEST_ASSERT(*(UINT32*)buffer == sizeof(payload), "length prefix correct");

    /* Read it back */
    status = AkesoEDRIpcReadFrame(buffer, bytesWritten, out, sizeof(out), &bytesRead);
    TEST_ASSERT(status == AkesoEDRSerializeOk, "read frame succeeds");
    TEST_ASSERT(bytesRead == bytesWritten, "same bytes read as written");
    TEST_ASSERT(memcmp(out, payload, sizeof(payload)) == 0, "payload round-trips");

    /* Test buffer too small */
    status = AkesoEDRIpcWriteFrame(buffer, 2, payload, sizeof(payload), &bytesWritten);
    TEST_ASSERT(status == AkesoEDRSerializeBufferTooSmall, "buffer too small detected");

    /* Test incomplete read */
    status = AkesoEDRIpcReadFrame(buffer, 2, out, sizeof(out), &bytesRead);
    TEST_ASSERT(status == AkesoEDRSerializeIncomplete, "incomplete frame detected");

    printf("  OK\n");
    return 0;
}

/* ── Test: handshake build ───────────────────────────────────────────────── */

static int test_handshake(void)
{
    AKESOEDR_IPC_HANDSHAKE hs;
    AKESOEDR_IPC_HANDSHAKE_REPLY reply;
    AKESOEDR_SERIALIZE_STATUS status;

    printf("[test_handshake]\n");

    AkesoEDRIpcBuildHandshake(&hs, AkesoEDRClientHookDll, 1234, 0);

    TEST_ASSERT(hs.Header.Magic == AKESOEDR_IPC_MAGIC, "handshake magic");
    TEST_ASSERT(hs.Header.Type == AkesoEDRMsgHandshake, "handshake type");
    TEST_ASSERT(hs.ClientType == (UINT32)AkesoEDRClientHookDll, "client type");
    TEST_ASSERT(hs.ClientPid == 1234, "client PID");

    status = AkesoEDRIpcHeaderValidate(&hs.Header);
    TEST_ASSERT(status == AkesoEDRSerializeOk, "handshake header valid");

    AkesoEDRIpcBuildHandshakeReply(&reply, AkesoEDRHandshakeOk, 5678, 0);

    TEST_ASSERT(reply.Header.Type == AkesoEDRMsgHandshakeReply, "reply type");
    TEST_ASSERT(reply.Status == (UINT32)AkesoEDRHandshakeOk, "reply status");
    TEST_ASSERT(reply.ServerPid == 5678, "server PID");

    printf("  OK\n");
    return 0;
}

/* ── Test: event serialization round-trip ────────────────────────────────── */

static int test_event_roundtrip(void)
{
    AKESOEDR_EVENT          original;
    AKESOEDR_EVENT          restored;
    BYTE                    buffer[64 * 1024];
    UINT32                  bytesWritten = 0;
    UINT32                  bytesRead = 0;
    AKESOEDR_SERIALIZE_STATUS status;

    printf("[test_event_roundtrip]\n");

    /* Build a process-create event */
    AkesoEDREventInit(&original, AkesoEDRSourceDriverProcess, AkesoEDRSeverityMedium);

    original.ProcessCtx.ProcessId       = 4444;
    original.ProcessCtx.ParentProcessId = 1111;
    original.ProcessCtx.ThreadId        = 5555;
    original.ProcessCtx.SessionId       = 1;
    original.ProcessCtx.IntegrityLevel  = 0x2000;   /* SECURITY_MANDATORY_MEDIUM_RID */
    original.ProcessCtx.IsElevated      = FALSE;
    wcscpy_s(original.ProcessCtx.ImagePath, AKESOEDR_MAX_PATH,
             L"C:\\Windows\\System32\\notepad.exe");
    wcscpy_s(original.ProcessCtx.CommandLine, AKESOEDR_MAX_CMDLINE,
             L"notepad.exe C:\\test.txt");
    wcscpy_s(original.ProcessCtx.UserSid, AKESOEDR_MAX_SID_STRING,
             L"S-1-5-21-123456789-1-1000");

    original.Payload.Process.IsCreate         = TRUE;
    original.Payload.Process.NewProcessId     = 4444;
    original.Payload.Process.ParentProcessId  = 1111;
    original.Payload.Process.CreatingThreadId = 2222;
    original.Payload.Process.IntegrityLevel   = 0x2000;
    original.Payload.Process.IsElevated       = FALSE;
    original.Payload.Process.ExitStatus       = 0;
    wcscpy_s(original.Payload.Process.ImagePath, AKESOEDR_MAX_PATH,
             L"C:\\Windows\\System32\\notepad.exe");
    wcscpy_s(original.Payload.Process.CommandLine, AKESOEDR_MAX_CMDLINE,
             L"notepad.exe C:\\test.txt");
    wcscpy_s(original.Payload.Process.UserSid, AKESOEDR_MAX_SID_STRING,
             L"S-1-5-21-123456789-1-1000");

    /* Serialize */
    status = AkesoEDRIpcSerializeEvent(buffer, sizeof(buffer), &original, 1, &bytesWritten);
    TEST_ASSERT(status == AkesoEDRSerializeOk, "serialize succeeds");
    TEST_ASSERT(bytesWritten > 0, "bytes written > 0");

    printf("  Serialized event: %u bytes (frame overhead: %u bytes)\n",
           bytesWritten, (UINT32)(bytesWritten - sizeof(AKESOEDR_EVENT)));

    /* Deserialize */
    ZeroMemory(&restored, sizeof(restored));
    status = AkesoEDRIpcDeserializeEvent(buffer, bytesWritten, &restored, &bytesRead);
    TEST_ASSERT(status == AkesoEDRSerializeOk, "deserialize succeeds");
    TEST_ASSERT(bytesRead == bytesWritten, "consumed all bytes");

    /* Verify envelope fields */
    TEST_ASSERT(IsEqualGUID(&original.EventId, &restored.EventId),
                "event ID round-trips");
    TEST_ASSERT(original.Timestamp.QuadPart == restored.Timestamp.QuadPart,
                "timestamp round-trips");
    TEST_ASSERT(original.Source == restored.Source,
                "source round-trips");
    TEST_ASSERT(original.Severity == restored.Severity,
                "severity round-trips");

    /* Verify process context */
    TEST_ASSERT(original.ProcessCtx.ProcessId == restored.ProcessCtx.ProcessId,
                "PID round-trips");
    TEST_ASSERT(original.ProcessCtx.ParentProcessId == restored.ProcessCtx.ParentProcessId,
                "PPID round-trips");
    TEST_ASSERT(original.ProcessCtx.IntegrityLevel == restored.ProcessCtx.IntegrityLevel,
                "integrity level round-trips");
    TEST_ASSERT(wcscmp(original.ProcessCtx.ImagePath,
                       restored.ProcessCtx.ImagePath) == 0,
                "image path round-trips");
    TEST_ASSERT(wcscmp(original.ProcessCtx.CommandLine,
                       restored.ProcessCtx.CommandLine) == 0,
                "command line round-trips");
    TEST_ASSERT(wcscmp(original.ProcessCtx.UserSid,
                       restored.ProcessCtx.UserSid) == 0,
                "user SID round-trips");

    /* Verify payload */
    TEST_ASSERT(original.Payload.Process.IsCreate == restored.Payload.Process.IsCreate,
                "process IsCreate round-trips");
    TEST_ASSERT(original.Payload.Process.NewProcessId == restored.Payload.Process.NewProcessId,
                "process NewProcessId round-trips");
    TEST_ASSERT(original.Payload.Process.CreatingThreadId == restored.Payload.Process.CreatingThreadId,
                "process CreatingThreadId round-trips");
    TEST_ASSERT(wcscmp(original.Payload.Process.ImagePath,
                       restored.Payload.Process.ImagePath) == 0,
                "process payload image path round-trips");

    /* Verify full binary equality */
    TEST_ASSERT(memcmp(&original, &restored, sizeof(AKESOEDR_EVENT)) == 0,
                "full struct binary equality");

    printf("  OK\n");
    return 0;
}

/* ── Test: buffer too small for event ────────────────────────────────────── */

static int test_event_buffer_too_small(void)
{
    AKESOEDR_EVENT event;
    BYTE tiny[64];
    UINT32 bytesWritten = 0;
    AKESOEDR_SERIALIZE_STATUS status;

    printf("[test_event_buffer_too_small]\n");

    AkesoEDREventInit(&event, AkesoEDRSourceDriverProcess, AkesoEDRSeverityLow);

    status = AkesoEDRIpcSerializeEvent(tiny, sizeof(tiny), &event, 0, &bytesWritten);
    TEST_ASSERT(status == AkesoEDRSerializeBufferTooSmall, "tiny buffer rejected");
    TEST_ASSERT(bytesWritten == 0, "no bytes written on failure");

    printf("  OK\n");
    return 0;
}

/* ── Main ────────────────────────────────────────────────────────────────── */

int main(void)
{
    int failed = 0;

    printf("=== AkesoEDR IPC Round-Trip Tests ===\n\n");

    failed += test_header_init_validate();
    failed += test_frame_write_read();
    failed += test_handshake();
    failed += test_event_roundtrip();
    failed += test_event_buffer_too_small();

    printf("\n=== Results: %d/%d passed ===\n", g_tests_passed, g_tests_run);

    if (failed > 0) {
        printf("FAILED\n");
        return 1;
    }

    printf("ALL PASSED\n");
    return 0;
}
