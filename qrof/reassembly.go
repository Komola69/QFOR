package qrof

import (
	"sync"
	"time"
)

const (
	MAX_CHUNKS                = 1024
	MAX_CHUNK_SIZE            = 1200
	MAX_OBJECT_SIZE           = MAX_CHUNKS * MAX_CHUNK_SIZE
	MAX_CONCURRENT_REASSEMBLY = 128
	REASSEMBLY_TTL            = 15 * time.Second
)

type ReassemblyState struct {
	OID           [32]byte
	TotalChunks   uint16
	ReceivedCount uint16

	Bitmap []byte   // bitset
	Chunks [][]byte // stored fragments

	Expiry time.Time
}

type ReassemblyTable struct {
	mu     sync.Mutex
	states map[[32]byte]*ReassemblyState
}

func NewReassemblyTable() *ReassemblyTable {
	t := &ReassemblyTable{
		states: make(map[[32]byte]*ReassemblyState),
	}
	go t.Sweep()
	return t
}

func (t *ReassemblyTable) Process(pkt *DataPacket) ([]byte, bool) {
	// Step A: Structural Guard
	if pkt.TotalChunks == 0 || pkt.TotalChunks > MAX_CHUNKS || len(pkt.Payload) > MAX_CHUNK_SIZE {
		return nil, false
	}
	if pkt.ChunkIndex >= pkt.TotalChunks {
		return nil, false
	}
	// Defensive check: total size check
	if int(pkt.TotalChunks)*len(pkt.Payload) > MAX_OBJECT_SIZE {
		return nil, false
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	// Step B: Lookup State
	state, exists := t.states[pkt.OID]

	if !exists {
		// Cap enforcement
		if len(t.states) >= MAX_CONCURRENT_REASSEMBLY {
			return nil, false
		}

		// Step C: INIT Allocation
		state = &ReassemblyState{
			OID:         pkt.OID,
			TotalChunks: pkt.TotalChunks,
			Bitmap:      make([]byte, (pkt.TotalChunks+7)/8),
			Chunks:      make([][]byte, pkt.TotalChunks),
			Expiry:      time.Now().Add(REASSEMBLY_TTL),
		}
		t.states[pkt.OID] = state
	}

	// Step D: Consistency Check
	if pkt.TotalChunks != state.TotalChunks {
		return nil, false
	}
	if time.Now().After(state.Expiry) {
		delete(t.states, pkt.OID)
		return nil, false
	}

	// Step E: Duplicate Check
	byteIndex := pkt.ChunkIndex / 8
	bitMask := byte(1 << (pkt.ChunkIndex % 8))

	if state.Bitmap[byteIndex]&bitMask != 0 {
		return nil, false
	}

	// Step F: Store Fragment
	payloadCopy := make([]byte, len(pkt.Payload))
	copy(payloadCopy, pkt.Payload)

	state.Chunks[pkt.ChunkIndex] = payloadCopy
	state.Bitmap[byteIndex] |= bitMask
	state.ReceivedCount++
	state.Expiry = time.Now().Add(REASSEMBLY_TTL)

	// Step G: Completion
	if state.ReceivedCount == state.TotalChunks {
		var full []byte
		for i := uint16(0); i < state.TotalChunks; i++ {
			full = append(full, state.Chunks[i]...)
		}
		delete(t.states, pkt.OID)
		return full, true
	}

	return nil, false
}

func (t *ReassemblyTable) HasState(oid [32]byte) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	_, exists := t.states[oid]
	return exists
}

func (t *ReassemblyTable) Sweep() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		t.mu.Lock()
		now := time.Now()
		for oid, state := range t.states {
			if now.After(state.Expiry) {
				delete(t.states, oid)
			}
		}
		t.mu.Unlock()
	}
}
