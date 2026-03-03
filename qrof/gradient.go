package qrof

import (
	"sync"
	"time"
)

const (
	gradientPotentialThreshold = 1.0
	gradientDecayTick          = 1 * time.Second
	gradientDecayStep          = 0.02
	gradientForgetPotential    = 10.0
)

type GradientEntry struct {
	Potential float64
	LastSeen  time.Time
}

type GradientTable struct {
	mu      sync.RWMutex
	entries map[[32]byte]GradientEntry
}

func NewGradientTable() *GradientTable {
	g := &GradientTable{
		entries: make(map[[32]byte]GradientEntry),
	}
	g.DecayGradients()
	return g
}

func (g *GradientTable) UpdateGradient(oid [32]byte, signalStrength float64) {
	now := time.Now()

	g.mu.Lock()
	defer g.mu.Unlock()

	entry, ok := g.entries[oid]
	if !ok {
		g.entries[oid] = GradientEntry{
			Potential: signalStrength,
			LastSeen:  now,
		}
		return
	}

	// Lower potential means stronger signal, so keep the better value.
	if signalStrength < entry.Potential {
		entry.Potential = signalStrength
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
	return entry.Potential < gradientPotentialThreshold
}

func (g *GradientTable) DecayGradients() {
	go func() {
		ticker := time.NewTicker(gradientDecayTick)
		defer ticker.Stop()

		for now := range ticker.C {
			g.mu.Lock()
			for oid, entry := range g.entries {
				if now.Sub(entry.LastSeen) < gradientDecayTick {
					continue
				}

				entry.Potential += gradientDecayStep
				if entry.Potential >= gradientForgetPotential {
					delete(g.entries, oid)
					continue
				}
				g.entries[oid] = entry
			}
			g.mu.Unlock()
		}
	}()
}
