/*
 * common/ipc_serialize.h
 * Serialization helpers for AkesoEDR IPC protocol.
 *
 * These functions serialize and deserialize IPC messages to/from a byte
 * buffer suitable for transmission over a named pipe or filter port.
 *
 * Wire format:
 *   [UINT32 frame_length]   ← total bytes following this field
 *   [AKESOEDR_IPC_HEADER]   ← message header (magic, version, type, etc.)
 *   [payload bytes]         ← message-type-specific payload
 *
 * All multi-byte integers are little-endian (native x64).
 *
 * Compiles in user-mode C17 and C++20.
 * Kernel-mode code uses the structs directly (no serialization needed for
 * filter port messages, which are memory-copied).
 */

#ifndef AKESOEDR_IPC_SERIALIZE_H
#define AKESOEDR_IPC_SERIALIZE_H

#include "ipc.h"

#ifndef _KERNEL_MODE

#ifdef __cplusplus
extern "C" {
#endif

/* ── Error codes ─────────────────────────────────────────────────────────── */

typedef enum _AKESOEDR_SERIALIZE_STATUS {
    AkesoEDRSerializeOk             = 0,
    AkesoEDRSerializeBufferTooSmall = 1,
    AkesoEDRSerializeBadMagic       = 2,
    AkesoEDRSerializeBadVersion     = 3,
    AkesoEDRSerializeBadLength      = 4,
    AkesoEDRSerializeBadType        = 5,
    AkesoEDRSerializeIncomplete     = 6
} AKESOEDR_SERIALIZE_STATUS;

/* ── Header helpers ──────────────────────────────────────────────────────── */

/*
 * Initialize an IPC header with magic, version, type, and payload size.
 */
static __inline void
AkesoEDRIpcHeaderInit(
    AKESOEDR_IPC_HEADER*    Header,
    AKESOEDR_IPC_MSG_TYPE   Type,
    UINT32                  PayloadSize,
    UINT32                  SequenceNum
)
{
    Header->Magic       = AKESOEDR_IPC_MAGIC;
    Header->Version     = AKESOEDR_IPC_VERSION;
    Header->Type        = (UINT16)Type;
    Header->PayloadSize = PayloadSize;
    Header->SequenceNum = SequenceNum;
}

/*
 * Validate an IPC header. Returns AkesoEDRSerializeOk on success.
 */
static __inline AKESOEDR_SERIALIZE_STATUS
AkesoEDRIpcHeaderValidate(
    const AKESOEDR_IPC_HEADER*  Header
)
{
    if (Header->Magic != AKESOEDR_IPC_MAGIC)
        return AkesoEDRSerializeBadMagic;

    if (Header->Version != AKESOEDR_IPC_VERSION)
        return AkesoEDRSerializeBadVersion;

    if (Header->Type < AkesoEDRMsgHandshake || Header->Type > AkesoEDRMsgHeartbeat)
        return AkesoEDRSerializeBadType;

    if (Header->PayloadSize > AKESOEDR_IPC_MAX_PAYLOAD)
        return AkesoEDRSerializeBadLength;

    return AkesoEDRSerializeOk;
}

/* ── Frame write (serialize to buffer) ───────────────────────────────────── */

/*
 * Write a length-prefixed frame into a buffer.
 *
 *   Buffer layout: [UINT32 frame_length] [data bytes]
 *
 *   frame_length = DataSize (i.e., the number of bytes following the prefix).
 *
 * Parameters:
 *   Buffer      - Destination buffer.
 *   BufferSize  - Total size of Buffer in bytes.
 *   Data        - Pointer to the message struct to write.
 *   DataSize    - Size of Data in bytes.
 *   BytesWritten - On success, set to total bytes written (4 + DataSize).
 *
 * Returns AkesoEDRSerializeOk on success, AkesoEDRSerializeBufferTooSmall
 * if the buffer cannot hold the frame.
 */
static __inline AKESOEDR_SERIALIZE_STATUS
AkesoEDRIpcWriteFrame(
    BYTE*       Buffer,
    UINT32      BufferSize,
    const void* Data,
    UINT32      DataSize,
    UINT32*     BytesWritten
)
{
    UINT32 totalSize = sizeof(UINT32) + DataSize;

    if (BufferSize < totalSize) {
        *BytesWritten = 0;
        return AkesoEDRSerializeBufferTooSmall;
    }

    /* Write length prefix (little-endian, native on x64) */
    *(UINT32*)Buffer = DataSize;

    /* Write payload */
    memcpy(Buffer + sizeof(UINT32), Data, DataSize);

    *BytesWritten = totalSize;
    return AkesoEDRSerializeOk;
}

/* ── Frame read (deserialize from buffer) ────────────────────────────────── */

/*
 * Read the length prefix from a buffer and validate it.
 *
 * Parameters:
 *   Buffer       - Source buffer containing at least 4 bytes.
 *   BufferSize   - Available bytes in Buffer.
 *   FrameLength  - On success, set to the payload length (bytes after prefix).
 *
 * Returns AkesoEDRSerializeOk if a complete length prefix is available and
 * the value is within bounds. Returns AkesoEDRSerializeIncomplete if fewer
 * than 4 bytes are available. Returns AkesoEDRSerializeBadLength if the
 * frame length exceeds AKESOEDR_IPC_MAX_PAYLOAD.
 */
static __inline AKESOEDR_SERIALIZE_STATUS
AkesoEDRIpcReadFrameLength(
    const BYTE* Buffer,
    UINT32      BufferSize,
    UINT32*     FrameLength
)
{
    if (BufferSize < sizeof(UINT32)) {
        *FrameLength = 0;
        return AkesoEDRSerializeIncomplete;
    }

    *FrameLength = *(const UINT32*)Buffer;

    if (*FrameLength > AKESOEDR_IPC_MAX_PAYLOAD)
        return AkesoEDRSerializeBadLength;

    return AkesoEDRSerializeOk;
}

/*
 * Read a complete frame (length prefix + payload) from a buffer.
 *
 * Parameters:
 *   Buffer      - Source buffer.
 *   BufferSize  - Available bytes in Buffer.
 *   OutData     - Destination for the payload (caller-allocated).
 *   OutDataSize - Size of OutData buffer.
 *   BytesRead   - On success, total bytes consumed (4 + payload length).
 *
 * Returns AkesoEDRSerializeOk on success.
 */
static __inline AKESOEDR_SERIALIZE_STATUS
AkesoEDRIpcReadFrame(
    const BYTE* Buffer,
    UINT32      BufferSize,
    void*       OutData,
    UINT32      OutDataSize,
    UINT32*     BytesRead
)
{
    UINT32 frameLength = 0;
    AKESOEDR_SERIALIZE_STATUS status;

    status = AkesoEDRIpcReadFrameLength(Buffer, BufferSize, &frameLength);
    if (status != AkesoEDRSerializeOk) {
        *BytesRead = 0;
        return status;
    }

    /* Check that the full frame is available in the buffer */
    if (BufferSize < sizeof(UINT32) + frameLength) {
        *BytesRead = 0;
        return AkesoEDRSerializeIncomplete;
    }

    /* Check that the output buffer is large enough */
    if (OutDataSize < frameLength) {
        *BytesRead = 0;
        return AkesoEDRSerializeBufferTooSmall;
    }

    memcpy(OutData, Buffer + sizeof(UINT32), frameLength);
    *BytesRead = sizeof(UINT32) + frameLength;
    return AkesoEDRSerializeOk;
}

/* ── Handshake helpers ───────────────────────────────────────────────────── */

/*
 * Build a handshake message ready for framing.
 */
static __inline void
AkesoEDRIpcBuildHandshake(
    AKESOEDR_IPC_HANDSHAKE* Msg,
    AKESOEDR_CLIENT_TYPE    ClientType,
    UINT32                  ClientPid,
    UINT32                  SequenceNum
)
{
    ZeroMemory(Msg, sizeof(*Msg));
    AkesoEDRIpcHeaderInit(
        &Msg->Header,
        AkesoEDRMsgHandshake,
        sizeof(AKESOEDR_IPC_HANDSHAKE) - sizeof(AKESOEDR_IPC_HEADER),
        SequenceNum
    );
    Msg->ClientType = (UINT32)ClientType;
    Msg->ClientPid  = ClientPid;
}

/*
 * Build a handshake reply message.
 */
static __inline void
AkesoEDRIpcBuildHandshakeReply(
    AKESOEDR_IPC_HANDSHAKE_REPLY*   Msg,
    AKESOEDR_HANDSHAKE_STATUS       Status,
    UINT32                          ServerPid,
    UINT32                          SequenceNum
)
{
    ZeroMemory(Msg, sizeof(*Msg));
    AkesoEDRIpcHeaderInit(
        &Msg->Header,
        AkesoEDRMsgHandshakeReply,
        sizeof(AKESOEDR_IPC_HANDSHAKE_REPLY) - sizeof(AKESOEDR_IPC_HEADER),
        SequenceNum
    );
    Msg->Status    = (UINT32)Status;
    Msg->ServerPid = ServerPid;
}

/* ── Event message helpers ───────────────────────────────────────────────── */

/*
 * Serialize a single event into a framed buffer.
 *
 * Layout: [UINT32 frame_len] [AKESOEDR_IPC_EVENT_MSG] [AKESOEDR_EVENT]
 *
 * Parameters:
 *   Buffer       - Destination buffer.
 *   BufferSize   - Size of Buffer.
 *   Event        - The event to serialize.
 *   SequenceNum  - Message sequence number.
 *   BytesWritten - Total bytes written to Buffer.
 */
static __inline AKESOEDR_SERIALIZE_STATUS
AkesoEDRIpcSerializeEvent(
    BYTE*                   Buffer,
    UINT32                  BufferSize,
    const AKESOEDR_EVENT*   Event,
    UINT32                  SequenceNum,
    UINT32*                 BytesWritten
)
{
    AKESOEDR_IPC_EVENT_MSG  msgHeader;
    UINT32                  payloadSize;
    UINT32                  totalMsgSize;
    UINT32                  totalFrameSize;

    payloadSize   = sizeof(AKESOEDR_IPC_EVENT_MSG) - sizeof(AKESOEDR_IPC_HEADER)
                  + sizeof(AKESOEDR_EVENT);
    totalMsgSize  = sizeof(AKESOEDR_IPC_EVENT_MSG) + sizeof(AKESOEDR_EVENT);
    totalFrameSize = sizeof(UINT32) + totalMsgSize;

    if (BufferSize < totalFrameSize) {
        *BytesWritten = 0;
        return AkesoEDRSerializeBufferTooSmall;
    }

    /* Build event message header */
    ZeroMemory(&msgHeader, sizeof(msgHeader));
    AkesoEDRIpcHeaderInit(
        &msgHeader.Header,
        AkesoEDRMsgEvent,
        payloadSize,
        SequenceNum
    );
    msgHeader.EventCount = 1;

    /* Write length prefix */
    *(UINT32*)Buffer = totalMsgSize;

    /* Write event message header */
    memcpy(Buffer + sizeof(UINT32), &msgHeader, sizeof(msgHeader));

    /* Write event payload */
    memcpy(Buffer + sizeof(UINT32) + sizeof(msgHeader), Event, sizeof(AKESOEDR_EVENT));

    *BytesWritten = totalFrameSize;
    return AkesoEDRSerializeOk;
}

/*
 * Deserialize a single event from a framed buffer.
 *
 * Parameters:
 *   Buffer      - Source buffer (must start with length prefix).
 *   BufferSize  - Available bytes.
 *   OutEvent    - Destination for the deserialized event.
 *   BytesRead   - Total bytes consumed from Buffer.
 */
static __inline AKESOEDR_SERIALIZE_STATUS
AkesoEDRIpcDeserializeEvent(
    const BYTE*         Buffer,
    UINT32              BufferSize,
    AKESOEDR_EVENT*     OutEvent,
    UINT32*             BytesRead
)
{
    UINT32                  frameLength = 0;
    AKESOEDR_SERIALIZE_STATUS status;
    const AKESOEDR_IPC_EVENT_MSG* msgHeader;
    const BYTE*             eventData;

    /* Read and validate frame length */
    status = AkesoEDRIpcReadFrameLength(Buffer, BufferSize, &frameLength);
    if (status != AkesoEDRSerializeOk) {
        *BytesRead = 0;
        return status;
    }

    /* Ensure the full frame is available */
    if (BufferSize < sizeof(UINT32) + frameLength) {
        *BytesRead = 0;
        return AkesoEDRSerializeIncomplete;
    }

    /* Validate minimum size for event message header */
    if (frameLength < sizeof(AKESOEDR_IPC_EVENT_MSG)) {
        *BytesRead = 0;
        return AkesoEDRSerializeBadLength;
    }

    /* Parse event message header */
    msgHeader = (const AKESOEDR_IPC_EVENT_MSG*)(Buffer + sizeof(UINT32));

    /* Validate IPC header */
    status = AkesoEDRIpcHeaderValidate(&msgHeader->Header);
    if (status != AkesoEDRSerializeOk) {
        *BytesRead = 0;
        return status;
    }

    if (msgHeader->Header.Type != AkesoEDRMsgEvent) {
        *BytesRead = 0;
        return AkesoEDRSerializeBadType;
    }

    if (msgHeader->EventCount < 1) {
        *BytesRead = 0;
        return AkesoEDRSerializeBadLength;
    }

    /* Ensure there's enough data for at least one event */
    if (frameLength < sizeof(AKESOEDR_IPC_EVENT_MSG) + sizeof(AKESOEDR_EVENT)) {
        *BytesRead = 0;
        return AkesoEDRSerializeBadLength;
    }

    /* Copy event out */
    eventData = Buffer + sizeof(UINT32) + sizeof(AKESOEDR_IPC_EVENT_MSG);
    memcpy(OutEvent, eventData, sizeof(AKESOEDR_EVENT));

    *BytesRead = sizeof(UINT32) + frameLength;
    return AkesoEDRSerializeOk;
}

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* _KERNEL_MODE */

#endif /* AKESOEDR_IPC_SERIALIZE_H */
