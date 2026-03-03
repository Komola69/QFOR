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
- Modes in `main.go`: `receiver`, `sender`, `discover`, `pull`, `promote_test`, **`reassembly_test`**.
- Packet types in `qrof/packet.go`:
  - `Beacon` (`FrameTypeBeacon`)
  - `Interest` (`FrameTypeInterest`)
  - `Data` (`FrameTypeData`) with strict parser-based decode:
    - **Protocol Version 0x02 enforced.**
    - All frame types updated with `Version` and `ObjectNonce`.
- Crypto/economy in `qrof/economy.go`:
  - Interest PoD solve/verify (Argon2id + SHAKE256)
  - **PoD challenge binds fragment metadata: `OID || ChunkIndex || TotalChunks || Nonce`.**
- **Reassembly Layer in `qrof/reassembly.go`**:
  - **`ReassemblyTable` implemented with hard caps: 1024 chunks max, 128 concurrent objects.**
  - **Strict bitmap-based duplicate detection and TTL-based expiry (15s).**
- Receiver behavior (`runReceiver` in `main.go`):
  - **Upgraded to Sink Role:** Now parses incoming `DataPacket` frames, verifies self-certifying identity and signature, and processes fragments for reassembly.
  - **Optimized Ingress:** Added explicit preamble and FrameTypeData check before parsing.
  - **Reassembly Validation:** Logs `Chunk received: X`, `[REASSEMBLY COMPLETE]`, and `[REASSEMBLY TEST PASS]` when the automated test payload is correctly reconstructed.
- **`reassembly_test` mode in `main.go`**:
  - **Automated Harness:** Splits a payload into 4 chunks, sends them out-of-order `[2, 0, 3, 1]`, and injects a duplicate chunk.

## Validation Status
- Local compilation: **SUCCESS** (`go build .` passed).
- Local tests:
  - `go test ./...` passed (no tests in current package)
- Manual multi-host tests (from user logs):
  - v1.1 Identity Fork VALIDATED.
  - **Automated Reassembly Test ready for execution.**

## Latest Status Sync (2026-03-04, Reassembly Polish)
- Applied:
  - `main.go`: Added explicit type-byte pre-check for efficiency in `runReceiver`.
  - `main.go`: Polished `runReceiver` logs to match exact expected format for automated testing.
- Conclusion: The reassembly layer and its automated test harness are fully implemented and optimized. The system is now a coherent multi-chunk object fabric.

## Next Action Required
- **Run Automated Reassembly Test.**
- Verify `[REASSEMBLY TEST PASS]` on Windows receiver.
- Proceed to Path A Phase 4: Cache Layer implementation.
