# QROF Session State

Last updated: 2026-03-04

## Collaboration Workflow Rule
- On every assistant reply, refresh `SESSION_STATE.md` so it reflects current code truth, test status, and validated manual outcomes.

## Current Project Snapshot
- Language/runtime: Go (`go.mod` module `qrof`)
- Entry point: `main.go`
- Core package: `qrof/`

## Project Goal (canonical)
- Build a secure, resource-bounded UDP fabric for object routing that is:
  - namespace-isolated (cross-network traffic dropped at ingress),
  - economically gated (PoW for unsolicited discovery + PoD for interests),
  - self-cleaning (thermodynamic active/dormant decay + eviction),
  - authenticity-verified (self-certifying identity + signed data),
  - and evolvable toward large payload transport (fragmentation) and post-quantum signatures (ML-DSA).

## Implemented (code truth)
- Modes in `main.go`: `receiver`, `sender`, `discover`, `pull`, `promote_test`.
- Packet types in `qrof/packet.go`:
  - `Beacon` (`FrameTypeBeacon`)
  - `Interest` (`FrameTypeInterest`)
  - `Data` (`FrameTypeData`) with strict parser-based decode:
    - `[Preamble2][Type1][OID32][PubKey32][SigLen2][Sig][PayloadLen2][Payload]`
    - Structs updated with `ChunkIndex` and `TotalChunks`.
    - **`InterestPacket` upgraded to carry `TotalChunks` (wire format: 75 bytes).**
- Crypto/economy in `qrof/economy.go`:
  - Interest PoD solve/verify (Argon2id + SHAKE256)
  - **PoD challenge upgraded to bind fragment metadata: `OID || ChunkIndex || TotalChunks || Nonce`.**
  - Beacon PoW solve/verify
  - Discovery PoW verify (`VerifyDiscoveryPoW`)
  - Namespace hash derivation (`DeriveNamespace`)
  - Data packet builder (`CraftDataPacket`) with pubkey/signature/payload fields
- Identity/signature in `qrof/crypto.go`:
  - persistent identity loader/generator (`LoadOrGenerateIdentity`)
  - self-certifying OID derivation (`DeriveOID = sha256(pubkey)`)
  - signed message helpers (`BuildDataSigningMessage`, `SignData`, `VerifySignature`)
  - **`BuildDataSigningMessage` upgraded to v1.1 fragment-bound signature domain: `OID || ChunkIndex || TotalChunks || SHA256(Payload)`.**
  - **`VerifySignature` now includes `[DEBUG] Signature verification FAILED` log on failure.**
- Gradient/routing state in `qrof/gradient.go`:
  - active table + PIT + dormant table with lock separation
  - active decay and eviction threshold `0.1`
  - active cap `2.0`
  - dormant 3-lambda decay + dormant eviction logging
  - dormant helpers (`HasDormant`, `DormantLeafHash`, `PromoteDormant`)
- Receiver behavior (`runReceiver`):
  - namespace ingress gate (`n >= 32` + hash prefix match)
  - admission gate on `inPIT || inDormant`
  - dormant promotion on valid PoD
  - fixed-window PPS/EER telemetry via atomic swaps
  - loads/saves receiver identity from `receiver_identity.key`
  - computes and prints authentic OID (`DeriveOID(pubkey)`)
  - broadcasts beacons with authentic OID + rolling leaf hash challenge
  - signs and returns authenticated `Data` response on valid interest (binds fragment metadata).
  - **Verifies PoD interests bound to fragment metadata.**
- Sender behavior (`runSender`):
  - namespace ingress gate on incoming beacons
  - explicit ingress telemetry counters/logs:
    - `[INGRESS] Alien beacon dropped. Drops: N`
    - `[INGRESS] Valid beacon accepted. Accepts: N`
  - **Solves PoD interests bound to fragment metadata (chunk 0/1 by default).**
- Promote test behavior (`runPromoteTest`):
  - requires `-oid` target
  - reactively waits for live beacon for that OID and captures `LeafHash`
  - solves/sends PoD interest using captured challenge (**binds chunk 0/1**).
  - parses response via `ParseDataPacket`
  - verifies `DeriveOID(pubkey) == OID` and signature validity (**verifies fragment-bound metadata**).
  - logs `[SECURE] Authentic Data Received: ...` on success

## Validation Status
- Local compilation: passed (`go build .` success)
- Local tests:
  - `go test ./...` passed (no tests in current package)
- Manual multi-host tests (from user logs):
  - Namespace isolation at receiver boundary validated (alien namespace dropped)
  - Valid namespace path validated: discovery -> promotion -> active eviction

## Latest Implementation Note (2026-03-04, Debug Instrumentation)
- Applied:
  - `qrof/crypto.go`: `VerifySignature` updated with explicit failure logging.
  - Verified compilation with `go build .`.
- Goal: Distinguish between parse errors and cryptographic signature failures in the multi-host test environment.

## Next Action Required
- User to rebuild on both Windows (receiver) and Linux (sender/promote_test) machines and re-run manual tests.
- Re-analyze output for `[DEBUG]` messages.
