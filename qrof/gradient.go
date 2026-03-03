package qrof

import (
	"fmt"
	"math"
	"sync"
	"time"
)

const (
	gradientPotentialThreshold = 1.0
	gradientDecayTick          = 1 * time.Second
	gradientHalfLifeSeconds    = 10.0
	gradientWeightCap          = 2.0
	gradientEvictionWeight     = 0.1
	dormantDecayMultiplier     = 3.0
	dormantInitialWeight       = 1.0
)

type OIDEntry struct {
	Potential float64
	Weight    float64
	LastSeen  time.Time
}

type DormantEntry struct {
	Weight   float64
	LastSeen time.Time
}

type GradientTable struct {
	mu        sync.RWMutex
	entries   map[[32]byte]OIDEntry
	pitMu     sync.RWMutex
	pit       map[[32]byte]time.Time
	dormantMu sync.Mutex
	dormant   map[[32]byte]*DormantEntry
	decayOnce sync.Once
}

func NewGradientTable() *GradientTable {
	g := &GradientTable{
		entries: make(map[[32]byte]OIDEntry),
		pit:     make(map[[32]byte]time.Time),
		dormant: make(map[[32]byte]*DormantEntry),
	}
	g.DecayLoop()
	return g
}

func (g *GradientTable) UpdateGradient(oid [32]byte, signalStrength float64) {
	now := time.Now()

	g.mu.Lock()
	defer g.mu.Unlock()

	entry, ok := g.entries[oid]
	if !ok {
		g.entries[oid] = OIDEntry{
			Potential: signalStrength,
			Weight:    1.0,
			LastSeen:  now,
		}
		return
	}

	// Lower potential means stronger signal, so keep the better value.
	if signalStrength < entry.Potential {
		entry.Potential = signalStrength
	}
	entry.Weight += 1.0
	if entry.Weight > gradientWeightCap {
		entry.Weight = gradientWeightCap
	}
	entry.LastSeen = now
	g.entries[oid] = entry
}

func (g *GradientTable) GetBestInterface(oid [32]byte) bool {
	g.mu.RLock()
	entry, ok := g.entries[oid]
	g.mu.RUnlock()

	if !ok {
		return false
	}
	return entry.Potential < gradientPotentialThreshold && entry.Weight > gradientEvictionWeight
}

func (g *GradientTable) DecayLoop() {
	g.decayOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(gradientDecayTick)
			defer ticker.Stop()

			lastTick := time.Now()
			for now := range ticker.C {
				elapsedSeconds := now.Sub(lastTick).Seconds()
				lastTick = now
				activeDecayFactor := math.Exp(-math.Ln2 * elapsedSeconds / gradientHalfLifeSeconds)
				dormantDecayFactor := math.Exp(-(dormantDecayMultiplier * math.Ln2 * elapsedSeconds) / gradientHalfLifeSeconds)

				// Phase A: decay active entries and collect evictions.
				evicted := make([][32]byte, 0)
				g.mu.Lock()
				for oid, entry := range g.entries {
					entry.Weight *= activeDecayFactor
					if entry.Weight < gradientEvictionWeight {
						delete(g.entries, oid)
						evicted = append(evicted, oid)
						continue
					}
					g.entries[oid] = entry
				}
				g.mu.Unlock()

				for _, oid := range evicted {
					fmt.Printf("!!! EVICTED: %x\n", oid[:4])
				}

				// Phase B: PIT cleanup for evicted active entries.
				if len(evicted) > 0 {
					g.pitMu.Lock()
					for _, oid := range evicted {
						delete(g.pit, oid)
					}
					g.pitMu.Unlock()
				}

				// Phase C: decay dormant entries 3x faster than active entries.
				dormantEvicted := make([][32]byte, 0)
				g.dormantMu.Lock()
				for oid, entry := range g.dormant {
					entry.Weight *= dormantDecayFactor
					if entry.Weight < gradientEvictionWeight {
						delete(g.dormant, oid)
						dormantEvicted = append(dormantEvicted, oid)
					}
				}
				g.dormantMu.Unlock()

				for _, oid := range dormantEvicted {
					fmt.Printf("[DISCOVERY] !!! DORMANT EVICTED: %x\n", oid[:4])
				}
			}
		}()
	})
}

func (g *GradientTable) DecayGradients() {
	g.DecayLoop()
}

func (g *GradientTable) AddPendingInterest(oid [32]byte) {
	g.pitMu.Lock()
	g.pit[oid] = time.Now()
	g.pitMu.Unlock()
}

func (g *GradientTable) RemovePendingInterest(oid [32]byte) {
	g.pitMu.Lock()
	delete(g.pit, oid)
	g.pitMu.Unlock()
}

func (g *GradientTable) AddDormant(oid [32]byte) {
	now := time.Now()

	g.dormantMu.Lock()
	defer g.dormantMu.Unlock()

	entry, ok := g.dormant[oid]
	if !ok {
		g.dormant[oid] = &DormantEntry{
			Weight:   dormantInitialWeight,
			LastSeen: now,
		}
		return
	}

	entry.Weight = dormantInitialWeight
	entry.LastSeen = now
}

func (g *GradientTable) HasPendingInterest(oid [32]byte) bool {
	g.pitMu.RLock()
	_, ok := g.pit[oid]
	g.pitMu.RUnlock()
	return ok
}

// Demand-triggered verification gate: avoid expensive signature work
// unless there is matching demand in the PIT.
func (g *GradientTable) VerifyBeaconIfDemanded(beacon Beacon, verifyMLDSA func(Beacon) bool) bool {
	if !g.HasPendingInterest(beacon.OID) {
		return false
	}
	if verifyMLDSA == nil {
		return true
	}
	return verifyMLDSA(beacon)
}
