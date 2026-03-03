package qrof

import (
	"sync"
	"time"
)

const (
	PIT_TTL            = 5 * time.Second
	MAX_CONCURRENT_PIT = 512
)

type PITKey struct {
	OID   [32]byte
	Nonce uint32
}

type PITEntry struct {
	CreatedAt time.Time
	Expiry    time.Time
}

type PITTable struct {
	mu      sync.Mutex
	entries map[PITKey]*PITEntry
}

func NewPITTable() *PITTable {
	t := &PITTable{
		entries: make(map[PITKey]*PITEntry),
	}
	go t.Sweep()
	return t
}

func (p *PITTable) Add(oid [32]byte, nonce uint32) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.entries) >= MAX_CONCURRENT_PIT {
		return false
	}

	key := PITKey{OID: oid, Nonce: nonce}

	if _, exists := p.entries[key]; exists {
		return true // idempotent
	}

	now := time.Now()

	p.entries[key] = &PITEntry{
		CreatedAt: now,
		Expiry:    now.Add(PIT_TTL),
	}

	return true
}

func (p *PITTable) Has(oid [32]byte, nonce uint32) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	key := PITKey{OID: oid, Nonce: nonce}

	entry, ok := p.entries[key]
	if !ok {
		return false
	}

	if time.Now().After(entry.Expiry) {
		delete(p.entries, key)
		return false
	}

	return true
}

func (p *PITTable) HasAny(oid [32]byte) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	for key, entry := range p.entries {
		if key.OID == oid {
			if now.After(entry.Expiry) {
				delete(p.entries, key)
				continue
			}
			return true
		}
	}
	return false
}

func (p *PITTable) Remove(oid [32]byte, nonce uint32) {
	p.mu.Lock()
	defer p.mu.Unlock()

	delete(p.entries, PITKey{OID: oid, Nonce: nonce})
}

func (p *PITTable) Sweep() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		p.mu.Lock()
		now := time.Now()
		for k, v := range p.entries {
			if now.After(v.Expiry) {
				delete(p.entries, k)
			}
		}
		p.mu.Unlock()
	}
}
