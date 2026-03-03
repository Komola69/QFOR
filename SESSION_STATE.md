# QROF Session State

Last updated: 2026-03-04

## Collaboration Workflow Rule
- On every assistant reply, refresh `SESSION_STATE.md` so it reflects current code truth, test status, and validated manual outcomes.

## Current Project Snapshot
- Language/runtime: Go (`go.mod` module `qrof`)
- Entry point: `main.go`
- Core package: `qrof/`

## Implemented (code truth)
- Modes in `main.go`: `receiver`, `sender`, `discover`, `pull`, `promote_test`.
- Packet types in `qrof/packet.go`:
  - `Beacon` (`FrameTypeBeacon`)
  - `Interest` (`FrameTypeInterest`)
  - `Data` (`FrameTypeData`) with strict parser-based decode:
    - `[Preamble2][Type1][OID32][PubKey32][SigLen2][Sig][PayloadLen2][Payload]`
- Crypto/economy in `qrof/economy.go`:
  - Interest PoD solve/verify (Argon2id + SHAKE256)
  - Beacon PoW solve/verify
  - Discovery PoW verify (`VerifyDiscoveryPoW`)
  - Namespace hash derivation (`DeriveNamespace`)
  - Data packet builder (`CraftDataPacket`) with pubkey/signature/payload fields
- Identity/signature in `qrof/crypto.go`:
  - persistent identity loader/generator (`LoadOrGenerateIdentity`)
  - self-certifying OID derivation (`DeriveOID = sha256(pubkey)`)
  - signed message helpers (`BuildDataSigningMessage`, `SignData`, `VerifySignature`)
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
  - signs and returns authenticated `Data` response on valid interest
- Sender behavior (`runSender`):
  - namespace ingress gate on incoming beacons
  - explicit ingress telemetry counters/logs:
    - `[INGRESS] Alien beacon dropped. Drops: N`
    - `[INGRESS] Valid beacon accepted. Accepts: N`
- Promote test behavior (`runPromoteTest`):
  - requires `-oid` target
  - reactively waits for live beacon for that OID and captures `LeafHash`
  - solves/sends PoD interest using captured challenge
  - parses response via `ParseDataPacket`
  - verifies `DeriveOID(pubkey) == OID` and signature validity
  - logs `[SECURE] Authentic Data Received: ...` on success

## Validation Status
- Local tests:
  - `go test ./...` passed
  - `go test -race ./...` passed
- Manual multi-host tests (from user logs):
  - Namespace isolation at receiver boundary validated (alien namespace dropped)
  - Valid namespace path validated: discovery -> promotion -> active eviction

## Known Gaps
- No ML-DSA signing/verification path yet (current bootstrap uses `ed25519`).
- Receiver private key is persisted as raw key bytes in local file (no passphrase/keystore layer).
- Manual two-laptop validation for the new authenticated `[SECURE]` flow is still pending.

## Latest Reality Check (2026-03-04, Phase 4 kickoff)
- Gemini Phase 4 direction is valid: authenticity/signatures are the next logical step.
- Critical design correction:
  - A packet layout of `[namespace][oid][signature][payload]` is not enough to verify signatures unless the verifier can recover the public key from `oid` via a trusted registry.
  - For self-contained verification, include sender public key in the Data frame and verify `oid == Hash(pubkey)` before signature verification.
- Recommended bootstrap:
  - Implement with `ed25519` first (stable in stdlib), keep interfaces abstract so ML-DSA can replace it later.
- Pending user decision:
  - Start with `ed25519` now vs immediate ML-DSA package integration.

## Latest Reality Check (2026-03-04, Gemini self-certifying patch)
- Overall direction is good and mostly code-aligned.
- Corrections required before implementation:
  - Do not duplicate namespace bytes inside `CraftDataPacket`; namespace prefixing is already handled by `addNamespacePrefix` in transport path.
  - Avoid manual raw slicing for Data parsing when possible; keep using/extend `ParseDataPacket` to prevent offset drift and frame-type bypass.
  - `runPromoteTest -oid` is useful for targeting receiver identity, but PoD solving still needs a valid `LeafHash`; this must come from a beacon or from a deterministic receiver-advertised challenge path.
  - Receiver identity generated at startup is only process-persistent; for stable OID across restarts, key material must be persisted (future step).
- Recommended next step:
  - Implement `ed25519` + self-certifying check (`oid == sha256(pub)`), but keep current frame wrapper semantics and parser-centric decoding.

## Latest Reality Check (2026-03-04, revised self-certifying alignment)
- Gemini revision improved and is mostly accurate.
- One factual mismatch remains:
  - It claimed `CraftDataPacket`/`ParseDataPacket` did not exist; they existed and have now been extended for pubkey/signature fields.
- Confirmed valid requirements for next patch:
  - persistent identity load/save,
  - OID derivation from public key,
  - signed authenticated data fields,
  - reactive `promote_test` that captures beacon `LeafHash` before PoD solve,
  - parser-based decoding and verification (`DeriveOID(pub)==OID` + signature verify).

## Latest Implementation Note (2026-03-04, parser-first self-certifying data)
- Applied:
  - `qrof/crypto.go` added (`LoadOrGenerateIdentity`, `DeriveOID`, `SignData`, `VerifySignature`, signing message builder).
  - `DataPacket` upgraded to include `PubKey`, `Signature`, and length-prefixed payload fields.
  - `ParseDataPacket` upgraded to strict error-return bounds checks.
  - `runReceiver` now uses persistent identity and authentic OID beacons, and signs returned data.
  - `runPromoteTest` converted to reactive sync->pull->verify flow with cryptographic checks.
- Local compile/race tests after patch: passed.
- `gofmt` applied to changed Go files (`main.go`, `qrof/packet.go`, `qrof/economy.go`, `qrof/crypto.go`) and tests re-run: passed.

## Notes for Next Session
- Read first:
  - `main.go`
  - `qrof/crypto.go`
  - `qrof/packet.go`
  - `qrof/gradient.go`
  - `qrof/economy.go`
- Treat this file as source-of-truth summary; avoid claiming completion unless reflected in code and/or manual logs.
