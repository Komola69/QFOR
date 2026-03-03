package main

import (
	"crypto/rand"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"qrof/qrof"
)

func main() {
	workers := runtime.NumCPU()
	runtime.GOMAXPROCS(workers)

	gate := qrof.AdmissionGate{
		Difficulty: ^uint32(0) / 10,
		QueueSize:  workers,
	}

	var oid [32]byte
	mustRead(oid[:])

	payload := make([]byte, 1024)
	mustRead(payload)

	foldedPath := make([]byte, 256)
	mustRead(foldedPath)

	packet := qrof.QROFPacket{
		Preamble:    [2]byte{0x51, 0x52},
		OID:         oid,
		FragmentIdx: 0,
		PoWNonce:    0,
		MerkleProof: foldedPath,
		Payload:     payload,
	}
	_ = packet.Serialize()

	const duration = 10 * time.Second
	deadline := time.Now().Add(duration)

	var packetChecks uint64
	var tier0Pass uint64
	var tier1Pass uint64

	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func(workerID int) {
			defer wg.Done()

			nonce := uint32(workerID + 1)
			var localChecks uint64
			var localTier0 uint64
			var localTier1 uint64

			for {
				if gate.MicroAdmit(packet.OID, nonce) {
					localTier0++
				}
				if gate.InclusionVerify(packet.OID, packet.Payload, packet.MerkleProof) {
					localTier1++
				}

				nonce++
				localChecks++

				if localChecks&1023 == 0 && time.Now().After(deadline) {
					break
				}
			}

			atomic.AddUint64(&packetChecks, localChecks)
			atomic.AddUint64(&tier0Pass, localTier0)
			atomic.AddUint64(&tier1Pass, localTier1)
		}(i)
	}
	wg.Wait()

	pps := float64(packetChecks) / duration.Seconds()

	fmt.Printf("Workers: %d\n", workers)
	fmt.Printf("Packets Checked: %d\n", packetChecks)
	fmt.Printf("Packets Per Second (PPS): %.2f\n", pps)
	fmt.Printf("Tier 0 Passes: %d\n", tier0Pass)
	fmt.Printf("Tier 1 Passes: %d\n", tier1Pass)

	if pps >= 100000 {
		fmt.Println("Target met: >= 100000 PPS")
		return
	}
	fmt.Println("Target not met: < 100000 PPS")
}

func mustRead(dst []byte) {
	if _, err := rand.Read(dst); err != nil {
		panic(err)
	}
}
