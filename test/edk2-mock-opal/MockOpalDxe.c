/** @file
  MockOpalDxe — TEST TOOLING ONLY (test-tooling-plan §3.3, epic #22).

  A UEFI DXE driver that emulates the canonical locked TCG Opal 2.0 SED from
  test/fixtures/opal/README.md by installing EFI_STORAGE_SECURITY_COMMAND_PROTOCOL
  on a fresh handle. The Trusted PBA locates the first protocol instance via
  LocateProtocol (see internal/transport/uefi_tamago.go), so no device path or
  block-IO stack is needed.

  Behaviour is kept byte-for-byte consistent with the native Go simulator
  (internal/opal/mocktper.go) via the shared spec and golden fixtures in
  test/fixtures/opal/: same UIDs, token encoding, ComPacket framing, status
  codes, and scripted Admin1 unlock sequence. Any unexpected or garbled request
  fails closed (error status or EFI_DEVICE_ERROR, no state change).

  Fault injection (no rebuild needed): the UEFI variable "MockOpalFault"
  (GUID a8d866f2-64a0-11f1-a8dc-56433c165986), set offline in the OVMF VARS
  store or by the harness, selects a failure mode — see README.md.

  Serial markers are written directly to COM1 (0x3F8): Driver#### options are
  dispatched by BDS before the console is connected, and Secure Boot silently
  skips unsigned drivers, so the marker is the only reliable evidence that the
  driver actually ran. Markers are deterministic and greppable by
  test/qemu/expect-serial.py.

  This is NOT product code. Product code must never depend on it.
**/

#include <Uefi.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/IoLib.h>
#include <Protocol/StorageSecurityCommand.h>

#include "Discovery0Locked.h"

//
// Wire constants — must match internal/opal/{client.go,packet.go,token.go}.
//
#define MOCK_PROTO_SECURITY   0x01    // SECURITY PROTOCOL 1 (TCG)
#define MOCK_COMID_DISCOVERY  0x0001  // Level 0 Discovery
#define MOCK_COMID_SESSION    0x07FE  // canonical base ComID
#define MOCK_TSN              0x1000  // TPer session number once authenticated

// Real firmware places SecurityProtocolSpecificData onto the SECURITY PROTOCOL
// command in the opposite byte order to the TCG ComID, so the transport pre-swaps
// it (see internal/transport/uefi_tamago.go swapComID). The mock swaps back to
// recover the logical ComID, faithfully emulating the firmware+drive.
#define MOCK_COMID(spsp)  ((UINT16)(((spsp) << 8) | ((spsp) >> 8)))

// ComPacket/Packet/SubPacket framing (TCG Core Spec §3.3; sed-opal layout).
#define COMPACKET_HDR_LEN  20
#define PACKET_HDR_LEN     24
#define SUBPACKET_HDR_LEN  12
#define FRAME_HDR_LEN      (COMPACKET_HDR_LEN + PACKET_HDR_LEN + SUBPACKET_HDR_LEN)

// Frame field byte offsets. FrameResponse (encoder) and DecodeFrame (decoder)
// must agree on these; naming them makes a desync visible at a glance, and
// disambiguates the SubPacket-length offset from DISCOVERY_LOCKING_FLAGS_OFF
// (also 52, but in the unrelated Discovery response).
#define OFF_COMID          4   // extended ComID (ComID in the high 16 bits)
#define OFF_COMPACKET_LEN  16  // ComPacket payload length
#define OFF_PKT_TSN        20  // Packet TSN
#define OFF_PKT_HSN        24  // Packet HSN
#define OFF_PKT_LEN        40  // Packet payload length
#define OFF_SUBPKT_LEN     52  // SubPacket payload length (unpadded)

// TCG stream control tokens.
#define TOK_START_LIST      0xF0
#define TOK_END_LIST        0xF1
#define TOK_START_NAME      0xF2
#define TOK_END_NAME        0xF3
#define TOK_CALL            0xF8
#define TOK_END_OF_DATA     0xF9
#define TOK_END_OF_SESSION  0xFA

// Method status codes.
#define STS_SUCCESS          0x00
#define STS_NOT_AUTHORIZED   0x01
#define STS_AUTH_LOCKED_OUT  0x12

// Locking / MBRControl table column numbers (Opal SSC).
#define COL_READ_LOCKED   7
#define COL_WRITE_LOCKED  8
#define COL_MBR_DONE      2

// Locking feature flags byte (offset within the Discovery0 response).
#define DISCOVERY_LOCKING_FLAGS_OFF  52
#define LOCKING_FLAG_LOCKED          0x04
#define LOCKING_FLAG_MBR_DONE        0x20

//
// Well-known TCG Opal UIDs — byte-identical to internal/opal/uid.go.
//
STATIC CONST UINT8  mUidSMUID[8]              = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF };
STATIC CONST UINT8  mUidMethodStartSession[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x02 };
STATIC CONST UINT8  mUidMethodSyncSession[8]  = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x03 };
STATIC CONST UINT8  mUidMethodSet[8]          = { 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x17 };
STATIC CONST UINT8  mUidAuthAdmin1[8]         = { 0x00, 0x00, 0x00, 0x09, 0x00, 0x01, 0x00, 0x01 };
STATIC CONST UINT8  mUidGlobalRange[8]        = { 0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x00, 0x01 };
STATIC CONST UINT8  mUidMBRControl[8]         = { 0x00, 0x00, 0x08, 0x03, 0x00, 0x00, 0x00, 0x01 };

// Canonical Admin1 credential (test/fixtures/opal/README.md). Test-only secret.
STATIC CONST UINT8  mAdmin1Pin[]  = { 'c', 'o', 'r', 'r', 'e', 'c', 't', ' ', 'h', 'o', 'r', 's', 'e' };

//
// Fault injection, selected by the MockOpalFault UEFI variable.
//
typedef enum {
  MockFaultNone,         // normal operation
  MockFaultAuthFail,     // every StartSession fails (wrong-PIN shape)
  MockFaultMbrDoneFail,  // MBRControl Set returns NOT_AUTHORIZED (method-status failure)
  MockFaultAfterUnlock   // GlobalRange Set succeeds; every IF-SEND afterwards
                         // fails at transport level (EFI_DEVICE_ERROR) —
                         // the partial-unlock shape
} MOCK_FAULT;

STATIC EFI_GUID  mMockOpalFaultGuid = {
  0xa8d866f2, 0x64a0, 0x11f1, { 0xa8, 0xdc, 0x56, 0x43, 0x3c, 0x16, 0x59, 0x86 }
};

//
// Device state — mirrors internal/opal/mocktper.go MockTPer.
//
STATIC BOOLEAN     mLocked  = TRUE;
STATIC BOOLEAN     mMbrDone = FALSE;
STATIC UINT32      mTsn     = 0;     // 0 = no session
STATIC UINT32      mHsn     = 0;
STATIC MOCK_FAULT  mFault   = MockFaultNone;

// Pending session response for the next IF-RECV (kept until the next IF-SEND,
// like MockTPer.resp).
#define RESP_MAX  256
STATIC UINT8  mResp[RESP_MAX];
STATIC UINTN  mRespLen = 0;

//
// COM1 serial markers (raw port I/O: dispatched before console connect).
//
#define COM1_PORT  0x3F8

STATIC
VOID
SerialStr (
  IN CONST CHAR8  *Str
  )
{
  for ( ; *Str != '\0'; Str++) {
    IoWrite8 (COM1_PORT, (UINT8)*Str);
  }
}

//
// Big-endian helpers.
//
STATIC
UINT32
Be32 (
  IN CONST UINT8  *P
  )
{
  return ((UINT32)P[0] << 24) | ((UINT32)P[1] << 16) | ((UINT32)P[2] << 8) | P[3];
}

STATIC
VOID
PutBe16 (
  OUT UINT8   *P,
  IN  UINT16  V
  )
{
  P[0] = (UINT8)(V >> 8);
  P[1] = (UINT8)V;
}

STATIC
VOID
PutBe32 (
  OUT UINT8   *P,
  IN  UINT32  V
  )
{
  P[0] = (UINT8)(V >> 24);
  P[1] = (UINT8)(V >> 16);
  P[2] = (UINT8)(V >> 8);
  P[3] = (UINT8)V;
}

//
// Token stream decoding — mirrors internal/opal/token.go tokenize(). Fails
// closed on truncation, reserved encodings, or too many tokens.
//
typedef struct {
  UINT8        Ctrl;     // control token byte, or 0 for an atom
  BOOLEAN      IsInt;
  BOOLEAN      IsBytes;
  UINT64       U;        // integer atom value
  CONST UINT8  *Data;    // byte-string atom contents (into the request buffer)
  UINTN        Len;
} MOCK_TOKEN;

#define MAX_TOKENS  64

STATIC
VOID
AtomToken (
  OUT MOCK_TOKEN   *T,
  IN  CONST UINT8  *D,
  IN  UINTN        N,
  IN  BOOLEAN      IsBytes
  )
{
  UINTN  I;

  ZeroMem (T, sizeof (*T));
  if (IsBytes) {
    T->IsBytes = TRUE;
    T->Data    = D;
    T->Len     = N;
    return;
  }

  T->IsInt = TRUE;
  for (I = 0; I < N; I++) {
    T->U = (T->U << 8) | D[I];
  }
}

STATIC
BOOLEAN
Tokenize (
  IN  CONST UINT8  *Data,
  IN  UINTN        Len,
  OUT MOCK_TOKEN   *Toks,
  OUT UINTN        *NumToks
  )
{
  UINTN  I;
  UINTN  N;
  UINT8  B0;
  UINTN  AtomLen;

  N = 0;
  for (I = 0; I < Len; ) {
    if (N >= MAX_TOKENS) {
      return FALSE;
    }
    B0 = Data[I];
    if (B0 < 0x80) {                      // tiny atom (values 0..63)
      ZeroMem (&Toks[N], sizeof (Toks[N]));
      Toks[N].IsInt = TRUE;
      Toks[N].U     = B0 & 0x3F;
      N++;
      I++;
    } else if (B0 < 0xC0) {               // short atom
      AtomLen = B0 & 0x0F;
      if (I + 1 + AtomLen > Len) {
        return FALSE;
      }
      AtomToken (&Toks[N], &Data[I + 1], AtomLen, (BOOLEAN)((B0 & 0x20) != 0));
      N++;
      I += 1 + AtomLen;
    } else if (B0 < 0xE0) {               // medium atom
      if (I + 2 > Len) {
        return FALSE;
      }
      AtomLen = (((UINTN)B0 & 0x07) << 8) | Data[I + 1];
      if (I + 2 + AtomLen > Len) {
        return FALSE;
      }
      AtomToken (&Toks[N], &Data[I + 2], AtomLen, (BOOLEAN)((B0 & 0x10) != 0));
      N++;
      I += 2 + AtomLen;
    } else if (B0 < 0xE4) {               // long atom
      if (I + 4 > Len) {
        return FALSE;
      }
      AtomLen = ((UINTN)Data[I + 1] << 16) | ((UINTN)Data[I + 2] << 8) | Data[I + 3];
      if (I + 4 + AtomLen > Len) {
        return FALSE;
      }
      AtomToken (&Toks[N], &Data[I + 4], AtomLen, (BOOLEAN)((B0 & 0x02) != 0));
      N++;
      I += 4 + AtomLen;
    } else if (B0 >= 0xF0) {              // control token
      ZeroMem (&Toks[N], sizeof (Toks[N]));
      Toks[N].Ctrl = B0;
      N++;
      I++;
    } else {                              // 0xE4..0xEF reserved
      return FALSE;
    }
  }

  *NumToks = N;
  return TRUE;
}

STATIC
BOOLEAN
IsCtrl (
  IN CONST MOCK_TOKEN  *T,
  IN UINT8             C
  )
{
  return (BOOLEAN)(T->Ctrl == C);
}

STATIC
BOOLEAN
IsUid (
  IN CONST MOCK_TOKEN  *T,
  IN CONST UINT8       *Uid
  )
{
  return (BOOLEAN)(T->IsBytes && T->Len == 8 && CompareMem (T->Data, Uid, 8) == 0);
}

//
// Token stream building — mirrors internal/opal/token.go builder. Responses
// only ever contain control tokens, small integers, and 8-byte UIDs, so short
// atoms always suffice.
//
typedef struct {
  UINT8  Buf[RESP_MAX - FRAME_HDR_LEN];
  UINTN  Len;
} MOCK_BUILDER;

STATIC
VOID
BControl (
  IN OUT MOCK_BUILDER  *B,
  IN     UINT8         Tok
  )
{
  B->Buf[B->Len++] = Tok;
}

STATIC
VOID
BUint (
  IN OUT MOCK_BUILDER  *B,
  IN     UINT64        V
  )
{
  UINT8  Be[8];
  UINTN  N;
  UINTN  I;

  if (V < 0x40) {                         // tiny atom
    B->Buf[B->Len++] = (UINT8)V;
    return;
  }

  for (I = 0; I < 8; I++) {               // minimal big-endian bytes
    Be[I] = (UINT8)(V >> (8 * (7 - I)));
  }
  for (I = 0; I < 7 && Be[I] == 0; I++) {
  }
  N = 8 - I;
  B->Buf[B->Len++] = (UINT8)(0x80 | N);   // short atom, integer
  CopyMem (&B->Buf[B->Len], &Be[I], N);
  B->Len += N;
}

STATIC
VOID
BUid (
  IN OUT MOCK_BUILDER  *B,
  IN     CONST UINT8   *Uid
  )
{
  B->Buf[B->Len++] = 0x80 | 0x20 | 8;     // short atom, byte string, length 8
  CopyMem (&B->Buf[B->Len], Uid, 8);
  B->Len += 8;
}

// ResultStream — method result with empty results, like mocktper.go:
// StartList EndList EndOfData StartList <status> 0 0 EndList.
STATIC
VOID
ResultStream (
  OUT MOCK_BUILDER  *B,
  IN  UINT64        Status
  )
{
  B->Len = 0;
  BControl (B, TOK_START_LIST);
  BControl (B, TOK_END_LIST);
  BControl (B, TOK_END_OF_DATA);
  BControl (B, TOK_START_LIST);
  BUint (B, Status);
  BUint (B, 0);
  BUint (B, 0);
  BControl (B, TOK_END_LIST);
}

// SyncSessionStream — Call SMUID SyncSession StartList HSN TSN EndList
// EndOfData StartList <status> 0 0 EndList.
STATIC
VOID
SyncSessionStream (
  OUT MOCK_BUILDER  *B,
  IN  UINT64        Status,
  IN  UINT32        Hsn,
  IN  UINT32        Tsn
  )
{
  B->Len = 0;
  BControl (B, TOK_CALL);
  BUid (B, mUidSMUID);
  BUid (B, mUidMethodSyncSession);
  BControl (B, TOK_START_LIST);
  BUint (B, Hsn);
  BUint (B, Tsn);
  BControl (B, TOK_END_LIST);
  BControl (B, TOK_END_OF_DATA);
  BControl (B, TOK_START_LIST);
  BUint (B, Status);
  BUint (B, 0);
  BUint (B, 0);
  BControl (B, TOK_END_LIST);
}

//
// Transport framing — mirrors internal/opal/{packet.go} encodePacket /
// decodePacket exactly (offsets, nested length validation, 4-byte padding).
//
STATIC
VOID
FrameResponse (
  IN CONST UINT8  *Payload,
  IN UINTN        Len
  )
{
  UINTN  Padded;

  Padded = (Len + 3) & ~(UINTN)3;
  ZeroMem (mResp, sizeof (mResp));

  // ComPacket header (offset 0): reserved(4), extendedComID(4: ComID in the
  // high 16 bits), outstanding(4), minTransfer(4), length(4).
  PutBe16 (&mResp[OFF_COMID], MOCK_COMID_SESSION);
  PutBe32 (&mResp[OFF_COMPACKET_LEN], (UINT32)(PACKET_HDR_LEN + SUBPACKET_HDR_LEN + Padded));

  // Packet header (offset 20): tsn(4), hsn(4), seq(4), reserved(2),
  // ackType(2), ack(4), length(4). Uses the *current* session state, so an
  // EndOfSession reply (state already cleared) carries zeros — like frame().
  PutBe32 (&mResp[OFF_PKT_TSN], mTsn);
  PutBe32 (&mResp[OFF_PKT_HSN], mHsn);
  PutBe32 (&mResp[OFF_PKT_LEN], (UINT32)(SUBPACKET_HDR_LEN + Padded));

  // SubPacket header (offset 44): reserved(6), kind(2)=0, length(4) unpadded.
  PutBe32 (&mResp[OFF_SUBPKT_LEN], (UINT32)Len);

  CopyMem (&mResp[FRAME_HDR_LEN], Payload, Len);
  mRespLen = FRAME_HDR_LEN + Padded;
}

STATIC
BOOLEAN
DecodeFrame (
  IN  CONST UINT8  *Data,
  IN  UINTN        Len,
  OUT CONST UINT8  **Payload,
  OUT UINTN        *PayloadLen
  )
{
  UINTN  ComLen;
  UINTN  PktLen;
  UINTN  SubLen;

  if (Len < FRAME_HDR_LEN) {
    return FALSE;                                       // short frame
  }
  ComLen = Be32 (&Data[OFF_COMPACKET_LEN]);
  if (ComLen + COMPACKET_HDR_LEN > Len) {
    return FALSE;                                       // length exceeds frame
  }
  if (ComLen == 0) {                                    // empty (bare ack)
    *Payload    = NULL;
    *PayloadLen = 0;
    return TRUE;
  }
  PktLen = Be32 (&Data[OFF_PKT_LEN]);
  if (PktLen < SUBPACKET_HDR_LEN || PACKET_HDR_LEN + PktLen > ComLen) {
    return FALSE;                                       // inconsistent packet
  }
  SubLen = Be32 (&Data[OFF_SUBPKT_LEN]);
  if (SubLen > PktLen - SUBPACKET_HDR_LEN || FRAME_HDR_LEN + SubLen > Len) {
    return FALSE;                                       // inconsistent subpacket
  }
  *Payload    = &Data[FRAME_HDR_LEN];
  *PayloadLen = SubLen;
  return TRUE;
}

//
// Method handlers — mirror MockTPer.startSession / setMethod.
//

// HandleStartSession parses StartSession (Call SMUID StartSession StartList
// HSN SPID Write [StartName name val EndName]...), validates the Admin1
// credential, and on success opens the session.
STATIC
VOID
HandleStartSession (
  IN  CONST MOCK_TOKEN  *Toks,
  IN  UINTN             NumToks,
  OUT MOCK_BUILDER      *B
  )
{
  UINT32       Hsn;
  CONST UINT8  *Pin;
  UINTN        PinLen;
  CONST UINT8  *Auth;
  UINTN        I;
  BOOLEAN      AuthOk;

  if (NumToks < 7 || !IsCtrl (&Toks[3], TOK_START_LIST) || !Toks[4].IsInt || !Toks[5].IsBytes) {
    ResultStream (B, STS_NOT_AUTHORIZED);
    return;
  }
  Hsn    = (UINT32)Toks[4].U;
  Pin    = NULL;
  PinLen = 0;
  Auth   = NULL;

  // Named arguments: HostChallenge (name 0) and HostSigningAuthority (name 3).
  for (I = 7; I + 3 < NumToks; I += 4) {
    if (!IsCtrl (&Toks[I], TOK_START_NAME)) {
      break;
    }
    if (!Toks[I + 1].IsInt || !IsCtrl (&Toks[I + 3], TOK_END_NAME)) {
      ResultStream (B, STS_NOT_AUTHORIZED);
      return;
    }
    if (Toks[I + 1].U == 0 && Toks[I + 2].IsBytes) {
      Pin    = Toks[I + 2].Data;
      PinLen = Toks[I + 2].Len;
    } else if (Toks[I + 1].U == 3 && Toks[I + 2].IsBytes && Toks[I + 2].Len == 8) {
      Auth = Toks[I + 2].Data;
    }
  }

  // Only Admin1 is provisioned; the credential must match; the auth-fail
  // fault rejects every attempt (wrong-PIN shape).
  AuthOk = (BOOLEAN)(mFault != MockFaultAuthFail &&
                     Auth != NULL && CompareMem (Auth, mUidAuthAdmin1, 8) == 0 &&
                     PinLen == sizeof (mAdmin1Pin) &&
                     Pin != NULL && CompareMem (Pin, mAdmin1Pin, PinLen) == 0);
  if (!AuthOk) {
    SerialStr ("MOCKOPAL: auth fail\r\n");
    SyncSessionStream (B, STS_AUTH_LOCKED_OUT, Hsn, 0);
    return;
  }

  mHsn = Hsn;
  mTsn = MOCK_TSN;
  SerialStr ("MOCKOPAL: auth ok\r\n");
  SyncSessionStream (B, STS_SUCCESS, mHsn, mTsn);
}

// HandleSet applies a Set to Locking_GlobalRange or MBRControl within an open
// session, walking StartName <col:int> <val:int> EndName tuples.
STATIC
VOID
HandleSet (
  IN  CONST MOCK_TOKEN  *Toks,
  IN  UINTN             NumToks,
  OUT MOCK_BUILDER      *B
  )
{
  UINTN  I;

  if (mTsn == 0) {                        // no authenticated session
    ResultStream (B, STS_NOT_AUTHORIZED);
    return;
  }
  if (NumToks < 8) {
    ResultStream (B, STS_NOT_AUTHORIZED);
    return;
  }

  if (IsUid (&Toks[1], mUidGlobalRange)) {
    for (I = 0; I + 3 < NumToks; I++) {
      if (IsCtrl (&Toks[I], TOK_START_NAME) && Toks[I + 1].IsInt && Toks[I + 2].IsInt &&
          IsCtrl (&Toks[I + 3], TOK_END_NAME) &&
          (Toks[I + 1].U == COL_READ_LOCKED || Toks[I + 1].U == COL_WRITE_LOCKED) &&
          Toks[I + 2].U == 0)
      {
        if (mLocked) {
          mLocked = FALSE;
          SerialStr ("MOCKOPAL: unlocked\r\n");
        }
      }
    }
    ResultStream (B, STS_SUCCESS);
    return;
  }

  if (IsUid (&Toks[1], mUidMBRControl)) {
    if (mFault == MockFaultMbrDoneFail) {
      SerialStr ("MOCKOPAL: mbr-refused fault\r\n");
      ResultStream (B, STS_NOT_AUTHORIZED);
      return;
    }
    for (I = 0; I + 3 < NumToks; I++) {
      if (IsCtrl (&Toks[I], TOK_START_NAME) && Toks[I + 1].IsInt && Toks[I + 2].IsInt &&
          IsCtrl (&Toks[I + 3], TOK_END_NAME) &&
          Toks[I + 1].U == COL_MBR_DONE && Toks[I + 2].U == 1)
      {
        if (!mMbrDone) {
          mMbrDone = TRUE;
          SerialStr ("MOCKOPAL: mbr-done set\r\n");
        }
      }
    }
    ResultStream (B, STS_SUCCESS);
    return;
  }

  ResultStream (B, STS_NOT_AUTHORIZED);
}

// HandlePayload interprets one session method payload and stages the framed
// response — mirrors MockTPer.handle. Anything unparseable yields a
// NOT_AUTHORIZED result so the client fails closed.
STATIC
VOID
HandlePayload (
  IN CONST UINT8  *Payload,
  IN UINTN        Len
  )
{
  MOCK_TOKEN    Toks[MAX_TOKENS];
  UINTN         NumToks;
  MOCK_BUILDER  B;
  UINT8         Eos;

  if (Len == 1 && Payload[0] == TOK_END_OF_SESSION) {
    mTsn = 0;
    mHsn = 0;
    SerialStr ("MOCKOPAL: session end\r\n");
    Eos = TOK_END_OF_SESSION;
    FrameResponse (&Eos, 1);
    return;
  }

  if (!Tokenize (Payload, Len, Toks, &NumToks) ||
      NumToks < 3 || !IsCtrl (&Toks[0], TOK_CALL) || !Toks[1].IsBytes || !Toks[2].IsBytes)
  {
    ResultStream (&B, STS_NOT_AUTHORIZED);
    FrameResponse (B.Buf, B.Len);
    return;
  }

  if (IsUid (&Toks[2], mUidMethodStartSession)) {
    HandleStartSession (Toks, NumToks, &B);
  } else if (IsUid (&Toks[2], mUidMethodSet)) {
    HandleSet (Toks, NumToks, &B);
  } else {
    ResultStream (&B, STS_NOT_AUTHORIZED);
  }

  FrameResponse (B.Buf, B.Len);
}

//
// EFI_STORAGE_SECURITY_COMMAND_PROTOCOL implementation.
//

// MockSendData — IF-SEND (SECURITY PROTOCOL OUT). Mirrors MockTPer.Send: only
// proto 0x01 on the session ComID is accepted; malformed framing is a device
// error and leaves all state (including the pending response) untouched.
STATIC
EFI_STATUS
EFIAPI
MockSendData (
  IN EFI_STORAGE_SECURITY_COMMAND_PROTOCOL  *This,
  IN UINT32                                 MediaId,
  IN UINT64                                 Timeout,
  IN UINT8                                  SecurityProtocolId,
  IN UINT16                                 SecurityProtocolSpecificData,
  IN UINTN                                  PayloadBufferSize,
  IN VOID                                   *PayloadBuffer
  )
{
  CONST UINT8  *Payload;
  UINTN        PayloadLen;

  if (SecurityProtocolId != MOCK_PROTO_SECURITY ||
      MOCK_COMID (SecurityProtocolSpecificData) != MOCK_COMID_SESSION)
  {
    return EFI_DEVICE_ERROR;
  }

  // fail-after-unlock: once the global range is unlocked, the drive "drops
  // off the bus" — every further IF-SEND fails at transport level. The
  // GlobalRange Set response staged before this point stays receivable.
  if (mFault == MockFaultAfterUnlock && !mLocked) {
    return EFI_DEVICE_ERROR;
  }

  if (PayloadBuffer == NULL ||
      !DecodeFrame (PayloadBuffer, PayloadBufferSize, &Payload, &PayloadLen))
  {
    return EFI_DEVICE_ERROR;
  }

  HandlePayload (Payload, PayloadLen);
  return EFI_SUCCESS;
}

// MockReceiveData — IF-RECV (SECURITY PROTOCOL IN). Mirrors MockTPer.Recv:
// the discovery ComID returns the golden Discovery0 image (flags patched from
// live state); the session ComID returns the pending response, truncated to
// the request size like a real IF-RECV.
STATIC
EFI_STATUS
EFIAPI
MockReceiveData (
  IN  EFI_STORAGE_SECURITY_COMMAND_PROTOCOL  *This,
  IN  UINT32                                 MediaId,
  IN  UINT64                                 Timeout,
  IN  UINT8                                  SecurityProtocolId,
  IN  UINT16                                 SecurityProtocolSpecificData,
  IN  UINTN                                  PayloadBufferSize,
  OUT VOID                                   *PayloadBuffer,
  OUT UINTN                                  *PayloadTransferSize
  )
{
  UINT8  Discovery[sizeof (mDiscovery0Locked)];
  UINTN  N;

  if (PayloadTransferSize == NULL || (PayloadBuffer == NULL && PayloadBufferSize != 0)) {
    return EFI_INVALID_PARAMETER;
  }
  if (SecurityProtocolId != MOCK_PROTO_SECURITY) {
    return EFI_DEVICE_ERROR;
  }

  if (MOCK_COMID (SecurityProtocolSpecificData) == MOCK_COMID_DISCOVERY) {
    // Golden fixture bytes (test/fixtures/opal/discovery0-locked.bin), with
    // the Locking-feature flags byte patched from live state. In the initial
    // locked state the patch is the identity, so the response is byte-exact.
    CopyMem (Discovery, mDiscovery0Locked, sizeof (Discovery));
    if (mLocked) {
      Discovery[DISCOVERY_LOCKING_FLAGS_OFF] |= LOCKING_FLAG_LOCKED;
    } else {
      Discovery[DISCOVERY_LOCKING_FLAGS_OFF] &= ~LOCKING_FLAG_LOCKED;
    }
    if (mMbrDone) {
      Discovery[DISCOVERY_LOCKING_FLAGS_OFF] |= LOCKING_FLAG_MBR_DONE;
    } else {
      Discovery[DISCOVERY_LOCKING_FLAGS_OFF] &= ~LOCKING_FLAG_MBR_DONE;
    }
    N = MIN (sizeof (Discovery), PayloadBufferSize);
    CopyMem (PayloadBuffer, Discovery, N);
    *PayloadTransferSize = N;
    return EFI_SUCCESS;
  }

  if (MOCK_COMID (SecurityProtocolSpecificData) != MOCK_COMID_SESSION) {
    return EFI_DEVICE_ERROR;
  }

  N = MIN (mRespLen, PayloadBufferSize);
  CopyMem (PayloadBuffer, mResp, N);
  *PayloadTransferSize = N;
  return EFI_SUCCESS;
}

STATIC EFI_STORAGE_SECURITY_COMMAND_PROTOCOL  mMockOpalSsc = {
  MockReceiveData,
  MockSendData
};

//
// Fault-variable parsing and driver entry.
//

STATIC
BOOLEAN
FaultValueIs (
  IN CONST CHAR8  *Buf,
  IN UINTN        Len,
  IN CONST CHAR8  *Want
  )
{
  UINTN  WantLen;

  WantLen = AsciiStrLen (Want);
  while (Len > 0 && Buf[Len - 1] == '\0') {  // tolerate a trailing NUL
    Len--;
  }
  return (BOOLEAN)(Len == WantLen && CompareMem (Buf, Want, WantLen) == 0);
}

// ReadFaultVariable selects the injected fault from the MockOpalFault UEFI
// variable. Absent → none. Unknown/unreadable content fails closed: the mock
// behaves as auth-always-fail rather than silently running fault-free.
STATIC
VOID
ReadFaultVariable (
  VOID
  )
{
  CHAR8       Buf[32];
  UINTN       Size;
  EFI_STATUS  Status;

  Size   = sizeof (Buf);
  Status = gRT->GetVariable (L"MockOpalFault", &mMockOpalFaultGuid, NULL, &Size, Buf);
  if (Status == EFI_NOT_FOUND) {
    mFault = MockFaultNone;
    return;
  }

  if (!EFI_ERROR (Status) && FaultValueIs (Buf, Size, "auth-fail")) {
    mFault = MockFaultAuthFail;
    SerialStr ("MOCKOPAL: fault auth-fail active\r\n");
  } else if (!EFI_ERROR (Status) && FaultValueIs (Buf, Size, "fail-mbrdone")) {
    mFault = MockFaultMbrDoneFail;
    SerialStr ("MOCKOPAL: fault fail-mbrdone active\r\n");
  } else if (!EFI_ERROR (Status) && FaultValueIs (Buf, Size, "fail-after-unlock")) {
    mFault = MockFaultAfterUnlock;
    SerialStr ("MOCKOPAL: fault fail-after-unlock active\r\n");
  } else {
    mFault = MockFaultAuthFail;
    SerialStr ("MOCKOPAL: fault unknown failing closed as auth-fail\r\n");
  }
}

/**
  Driver entry: emit the dispatch marker, select the fault mode, and install
  the Storage Security Command protocol on a fresh handle.

  @param[in] ImageHandle  The driver image handle.
  @param[in] SystemTable  The EFI system table.

  @retval EFI_SUCCESS  The protocol was installed.
  @return              Error from InstallMultipleProtocolInterfaces.
**/
EFI_STATUS
EFIAPI
MockOpalDxeEntryPoint (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_HANDLE  Handle;
  EFI_STATUS  Status;

  SerialStr ("MOCKOPAL: dispatched\r\n");
  ReadFaultVariable ();

  Handle = NULL;
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &Handle,
                  &gEfiStorageSecurityCommandProtocolGuid,
                  &mMockOpalSsc,
                  NULL
                  );
  if (EFI_ERROR (Status)) {
    SerialStr ("MOCKOPAL: install failed\r\n");
    return Status;
  }

  SerialStr ("MOCKOPAL: protocol installed\r\n");
  return EFI_SUCCESS;
}
