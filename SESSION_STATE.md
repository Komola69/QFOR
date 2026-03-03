# QROF Session State

Last updated: 2026-03-03

## User Collaboration Rule (must follow)
- Respond as if addressing Gemini directly when discussing audits/specs.
- Do not start editing immediately after analysis; first state the conclusion and ask the user for permission to patch.

## Current Project Snapshot
- Language/runtime: Go (`go.mod` module `qrof`)
- Entry point: `main.go`
- Core package: `qrof/`

### Implemented
- UDP sender/receiver/discover controller in `main.go`.
- Beacon + interest packet structures and parse/serialize paths in `qrof/packet.go`.
- Admission + inclusion logic in `qrof/admission.go`.
- PoD verification/solver (Argon2id + SHAKE256) in `qrof/economy.go`.
- Gradient decay loop with exponential cooling in `qrof/gradient.go`.
- PPS reset behavior (per-second) using `atomic.SwapUint64`.
- Active lifecycle controls:
  - weight cap `2.0`
  - eviction threshold `0.1`
  - active+PIT cleanup on eviction with `!!! EVICTED` logs
  - fixed-window EER telemetry reset
- Discovery isolation controls:
  - `VerifyDiscoveryPoW(beacon)` in `qrof/economy.go`
  - dormant table in `qrof/gradient.go`
  - dormant 3-lambda decay and `[DISCOVERY] !!! DORMANT EVICTED` logs
  - receiver routes unsolicited beacons into dormant path after discovery PoW

### Known Gaps (code truth, not target spec)
- No ML-DSA verification path is implemented.
- PIT entries can still grow from periodic beacon insertion patterns if not matched; decay cleanup only removes PIT keys tied to evicted active entries.

## Agreed Next Patch Set (pending user permission)
1. `qrof/gradient.go` (done)
- Weight cap `2.0` in `UpdateGradient`.
- Eviction threshold `0.1`.
- Eviction cleanup for both `entries` and `pit`.
- Eviction logging: `!!! EVICTED: %x`.
- Dormant map + mutex.
- Dormant 3-lambda decay and `[DISCOVERY] !!! DORMANT EVICTED` logging.

2. `main.go` (done)
- PPS reset preserved.
- EER converted to fixed-window by swapping/resetting verify counters every second.
- Receiver unsolicited beacon routing to dormant state via discovery PoW gate.

3. `qrof/economy.go` (done)
- Added `VerifyDiscoveryPoW(beacon)` wrapper over full beacon work verification at `DifficultyDiscovery`.

4. Verification status
- `go test ./...` passed.
- `go test -race ./...` passed.

## Notes for New Session Start
- Read this file first, then inspect:
  - `main.go`
  - `qrof/gradient.go`
  - `qrof/economy.go`
- Avoid target-state claims unless reflected in code.
