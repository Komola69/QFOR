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
- Modes in `main.go`: `receiver`, `sender`, `discover`, `pull`, `promote_test`, `reassembly_test`.
- Packet types in `qrof/packet.go`:
  - `Beacon`, `Interest`, `Data` upgraded to **Protocol Version 0x02**.
- Crypto/economy in `qrof/economy.go`:
  - PoD challenge binds `OID || ChunkIndex || TotalChunks || Nonce`.
- **Reassembly Layer in `qrof/reassembly.go`**:
  - `ReassemblyTable` handles multi-chunk reconstruction with hard caps.
  - **`HasState(oid)` helper added.**
- **Directional PIT v1.1 in `qrof/pit.go`**:
  - Keyed by `(OID, Nonce)`, decoupled from gradient decay, 5s TTL.
- **Transport Lifecycle Isolation in `main.go`**:
  - **Conditional Acceptance Logic:** Consumer receive loops (`runPromoteTest`, `runPull`) now admit fragments if `PIT exists OR ReassemblyState exists`.
  - **First-Fragment Authorization:** PIT entry is removed immediately upon the arrival of the first valid fragment.
  - **Continuity:** Subsequent fragments are accepted via `ReassemblyState` lookup.

## Validation Status
- Local compilation: **SUCCESS** (`go build .` passed).
- Local tests:
  - `go test ./...` passed (no tests in current package)
- Manual multi-host tests (from user logs):
  - v1.1 Identity Fork VALIDATED.
  - Multi-chunk Reassembly VALIDATED.
  - Directional PIT v1.1 (isolation + conditional logic) ready for final verification.

## Latest Status Sync (2026-03-04, Transport Finality)
- Applied:
  - `main.go`: Refined PIT/Reassembly integration logic to strictly adhere to the "first-fragment authorization" rule.
  - `main.go`: Upgraded `runPull` to include a functional receive loop with v1.1 transport law.
- Conclusion: The core transport layer is now structurally complete, isolated, and robust against request collision and unsolicited fragment amplification.

## Next Action Required
- **Run `reassembly_test` and `promote_test`** to confirm multi-chunk transport correctness.
- Proceed to Path A Phase 4: Cache Layer implementation.
