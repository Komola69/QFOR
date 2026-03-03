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
  - `Data` (`FrameTypeData`) with `Serialize`/`ParseDataPacket`
- Crypto/economy in `qrof/economy.go`:
  - Interest PoD solve/verify (Argon2id + SHAKE256)
  - Beacon PoW solve/verify
  - Discovery PoW verify (`VerifyDiscoveryPoW`)
  - Namespace hash derivation (`DeriveNamespace`)
  - Data packet builder (`CraftDataPacket`)
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
  - sends `Data` response (`Hello from Windows`) on valid interest
- Sender behavior (`runSender`):
  - namespace ingress gate on incoming beacons
  - explicit ingress telemetry counters/logs:
    - `[INGRESS] Alien beacon dropped. Drops: N`
    - `[INGRESS] Valid beacon accepted. Accepts: N`
- Promote test behavior (`runPromoteTest`):
  - sends discovery beacon
  - waits 3s
  - sends matching interest
  - waits up to 5s for namespaced `Data` response and logs `Data Received: ...`

## Validation Status
- Local tests:
  - `go test ./...` passed
  - `go test -race ./...` passed
- Manual multi-host tests (from user logs):
  - Namespace isolation at receiver boundary validated (alien namespace dropped)
  - Valid namespace path validated: discovery -> promotion -> active eviction

## Known Gaps
- No ML-DSA signing/verification path yet.
- `Data` payload is currently demo/plain payload (no signature/MAC/auth layer).
- End-to-end sender ingress proof still depends on manual two-laptop telemetry runs.

## Notes for Next Session
- Read first:
  - `main.go`
  - `qrof/packet.go`
  - `qrof/gradient.go`
  - `qrof/economy.go`
- Treat this file as source-of-truth summary; avoid claiming completion unless reflected in code and/or manual logs.
