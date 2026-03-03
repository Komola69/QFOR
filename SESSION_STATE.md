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
    - **Upgraded to Protocol Version 0x02.**
    - **InterestPacket (v0x02, 90 bytes):** `[Preamble 2][Type 1][Version 1][OID 32][ObjectNonce 16][ChunkIndex 2][Nonce 4][SaltedPoD 32]`.
    - **DataPacket (v0x02, 90 bytes min):** `[Preamble 2][Type 1][Version 1][OID 32][ObjectNonce 16][PubKey 32][ChunkIndex 2][TotalChunks 2][SigLen 2][Sig][PayloadLen 2][Payload]`.
    - **Strict Version Gating:** Packets with Version != 0x02 are dropped by parsers.
- Crypto/economy in `qrof/economy.go`:
  - Interest PoD solve/verify (Argon2id + SHAKE256)
  - **PoD challenge binds fragment metadata: `OID || ChunkIndex || TotalChunks || Nonce`.**
  - Beacon PoW solve/verify
  - Discovery PoW verify (`VerifyDiscoveryPoW`)
  - Namespace hash derivation (`DeriveNamespace`)
  - Data packet builder (**`CraftDataPacket`**) now supports Protocol Version 0x02 and `ObjectNonce`.
- Identity/signature in `qrof/crypto.go`:
  - persistent identity loader/generator (`LoadOrGenerateIdentity`)
  - **Self-certifying OID derivation upgraded to Object-Centric Identity: `DeriveOID(pub, objectNonce) = Hash(pub || objectNonce)`.**
  - signed message helpers (`BuildDataSigningMessage`, `SignData`, `VerifySignature`)
  - **`BuildDataSigningMessage` binds v1.1 versioned fragment-bound signature domain: `Version || OID || ChunkIndex || TotalChunks || SHA256(Payload)`.**
  - **`VerifySignature` now includes `[DEBUG] Signature verification FAILED` log on failure.**
- Gradient/routing state in `qrof/gradient.go`:
  - active table + PIT + dormant table with lock separation
  - active decay and eviction threshold `0.1`
  - active cap `2.0`
  - dormant 3-lambda decay + dormant eviction logging
  - dormant helpers (`HasDormant`, `DormantLeafHash`, `PromoteDormant`)
- Receiver behavior (`runReceiver` in `main.go`):
  - namespace ingress gate (`n >= 32` + hash prefix match)
  - admission gate on `inPIT || inDormant`
  - dormant promotion on valid PoD
  - fixed-window PPS/EER telemetry via atomic swaps
  - loads/saves receiver identity from `receiver_identity.key`
  - **Identity Fork Phase 3 Applied:** Uses Object-routed OID for authentication. Computes `authenticOID` with a local `ObjectNonce`.
  - broadcasts beacons with authentic OID + rolling leaf hash challenge.
  - **Verifies Interest OID using the provided `ObjectNonce` from the packet.**
- Sender behavior (`runSender`):
  - namespace ingress gate on incoming beacons
  - explicit ingress telemetry counters/logs:
    - `[INGRESS] Alien beacon dropped. Drops: N`
    - `[INGRESS] Valid beacon accepted. Accepts: N`
  - **Generates a random `ObjectNonce` per Interest.**
- Promote test behavior (`runPromoteTest`):
  - **Upgraded to v1.1 Identity Law.**
  - **Generates random `ObjectNonce` for Interest.**
  - **Verifies received `DataPacket` OID using its `ObjectNonce` and `PubKey`.**
  - **Binds `Version` in signature verification.**

## Validation Status
- Local compilation: **SUCCESS** (`go build .` passed).
- Local tests:
  - `go test ./...` passed (no tests in current package)
- Manual multi-host tests (from user logs):
  - v1.0 validated. **v1.1 (Identity Fork) ready for manual verification.**

## Latest Status Sync (2026-03-04, Identity Fork Complete)
- Applied:
  - `qrof/packet.go`: v0.2 Wire Schema.
  - `qrof/crypto.go`: v1.1 Identity Law (Object-routed OID + Versioned Signatures).
  - `qrof/economy.go`: Updated `CraftDataPacket` to v1.1.
  - `main.go`: Full application-level alignment with v1.1 Identity Law.
- Conclusion: The system has successfully transitioned from producer-centric to object-centric identity. The OID now commits to both the producer and a specific object instance via a random `ObjectNonce`.

## Next Action Required
- Manual verification on 2 laptops to confirm the new `promote_test` flow.
- Proceed to Path A Phase 3: Reassembly layer implementation.
