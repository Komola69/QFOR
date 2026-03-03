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
- **Directional PIT v1.1 in `qrof/pit.go`**:
  - **Isolated Lifecycle**: PIT is now a dedicated component, decoupled from gradient decay.
  - **Keyed by `(OID, Nonce)`**: Prevents request collisions.
  - **Fixed 5s TTL**: Independent `Sweep` loop handles eviction.
  - **Hard Cap**: `MAX_CONCURRENT_PIT = 512`.
  - **Consumer-side only**: Producers no longer maintain PIT for inbound interests.
- Receiver behavior (`runReceiver` in `main.go`):
  - **Admission Logic**: No longer uses PIT for inbound interests. Relies on self-identity (`authenticOID`/`serviceNonce`) or discovery status (`HasDormant`).
- Consumer behaviors (`runSender`, `runPull`, `runPromoteTest`):
  - Now instantiate and use `PITTable` to track pending requests.
  - **`runPromoteTest`**: Verified PIT entry check and removal on first fragment arrival.

## Validation Status
- Local compilation: **SUCCESS** (`go build .` passed).
- Local tests:
  - `go test ./...` passed (no tests in current package)
- Manual multi-host tests (from user logs):
  - v1.1 Identity Fork VALIDATED.
  - Multi-chunk Reassembly VALIDATED.
  - **Directional PIT v1.1 ready for manual verification.**

## Latest Status Sync (2026-03-04, PIT Isolation)
- Applied:
  - `qrof/pit.go`: New implementation of the Pending Interest Table.
  - `qrof/gradient.go`: Removed legacy PIT implementation.
  - `main.go`: Updated all call sites to use isolated PIT logic and request-scoped keys.
- Conclusion: The core transport substrate is now architecturally clean. Requests are uniquely tracked by `(OID, Nonce)` with isolated lifecycles and hard memory bounds.

## Next Action Required
- **Verify PIT v1.1 functionality** on 2 laptops.
- Proceed to Path A Phase 4: Cache Layer implementation.
