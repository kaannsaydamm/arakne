package core

import (
	"fmt"
	"os"
	"path/filepath"
)

// Centralized Application Paths
const (
	BaseDir = "C:\\Arakne"
)

var (
	// Subdirectories
	QuarantineDir   = filepath.Join(BaseDir, "Quarantine")
	EvidenceDir     = filepath.Join(BaseDir, "Evidence")
	IntelligenceDir = filepath.Join(BaseDir, "Intelligence")
	TempDir         = filepath.Join(BaseDir, "Temp")
	DriversDir      = filepath.Join(BaseDir, "Drivers")
	LogsDir         = filepath.Join(BaseDir, "Logs")
	BackupsDir      = filepath.Join(BaseDir, "Backups")
)

// EnsureDirectories checks and creates the necessary directory structure.
func EnsureDirectories() error {
	dirs := []string{
		BaseDir,
		QuarantineDir,
		EvidenceDir,
		IntelligenceDir,
		TempDir,
		DriversDir,
		LogsDir,
		BackupsDir,
	}

	for _, d := range dirs {
		if _, err := os.Stat(d); os.IsNotExist(err) {
			fmt.Printf("[*] Creating directory: %s\n", d)
			if err := os.MkdirAll(d, 0755); err != nil {
				return fmt.Errorf("failed to create %s: %v", d, err)
			}
		}
	}
	return nil
}
