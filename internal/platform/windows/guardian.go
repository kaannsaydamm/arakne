package windows

import (
	"arakne/internal/core"
)

// --- Protection Modules ---

// DriverScanner detects Vulnerable Drivers (BYOVD)
// Protection against: Kernel exploitations using legitimate but vulnerable drivers.
// Note: See loldrivers.go for the hash-based implementation.
// This struct remains for architectural compatibility if needed.
type DriverScanner struct{}

func (d *DriverScanner) ScanLoadedDrivers() []core.Threat {
	// Implemented in loldrivers.go
	return []core.Threat{}
}

// MemoryScanner is implemented in memory.go
// UEFIScanner is implemented in uefi.go
