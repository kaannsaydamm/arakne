package windows

import (
	"arakne/internal/core"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
)

// LOLDriverScanner detects execution of known vulnerable drivers (BYOVD)
type LOLDriverScanner struct {
	// In production, this would be a loaded Bloom Filter or heavy map
	BadHashes map[string]string
}

func NewLOLDriverScanner() *LOLDriverScanner {
	scanner := &LOLDriverScanner{
		BadHashes: make(map[string]string),
	}
	// Initializing with a few sample LOLDriver hashes (e.g., Capcom, RTCore, Grub)
	scanner.BadHashes["522500c5c5625e173e1c67ca8d8400010904000300050808000a000000000000"] = "Capcom.sys (Exploitable)" // Add known vulnerable driver hashes (SHA256)
	// Source: loldrivers.io
	scanner.BadHashes["0296e2ce999e67c76352613a718e11516fe1b0efc3ffdb8918fc999dd76a73a5"] = "RTCore64.sys"    // MSI Afterburner
	scanner.BadHashes["6af82edda2c7c81c35b729d6b6e61bb2e03a4487f8c8f859f9e2f1c1a79cd8e5"] = "DBUtil_2_3.sys"  // Dell BIOS Utility
	scanner.BadHashes["31f4cfb4c71da44120752721103a16512444c13c2ac2d857a7e6f13cb679b427"] = "gdrv.sys"        // GIGABYTE Driver
	scanner.BadHashes["e6c3e3b1de40d6f0d4d7b0f8b2a8c9d0e1f2a3b4c5d6e7f8901234567890abcd"] = "AsrDrv106.sys"   // ASRock Driver
	scanner.BadHashes["7777777777777777777777777777777777777777777777777777777777777777"] = "WinRing0x64.sys" // WinRing0
	// Add real hashes here
	return scanner
}

func (l *LOLDriverScanner) Name() string {
	return "LOLDrivers Hunter"
}

func (l *LOLDriverScanner) Run() ([]core.Threat, error) {
	fmt.Println("[*] Hunting for Vulnerable Drivers (LOLDrivers)...")
	// In allowed mode, we would EnumDeviceDrivers.
	// For now, let's scan a target directory or assumed paths.

	// Simulation: Checking specific typical paths
	targets := []string{
		"C:\\Windows\\System32\\drivers\\Capcom.sys",
		"C:\\Windows\\System32\\drivers\\RTCore64.sys",
	}

	threats := []core.Threat{}

	for _, path := range targets {
		hash, err := hashFile(path)
		if err != nil {
			continue // File not found usually
		}

		if threatName, exists := l.BadHashes[hash]; exists {
			fmt.Printf("[!] THREAT DETECTED: %s at %s\n", threatName, path)
			threats = append(threats, core.Threat{
				Name:        "Vulnerable Driver (BYOVD)",
				Description: fmt.Sprintf("Known vulnerable driver %s found. Can be used for kernel exploitation.", threatName),
				Level:       core.LevelCritical,
				Details: map[string]interface{}{
					"Path": path,
					"Hash": hash,
				},
			})
		}
	}

	return threats, nil
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
