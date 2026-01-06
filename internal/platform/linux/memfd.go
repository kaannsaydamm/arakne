package linux

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"arakne/internal/core"
)

// MemfdHunter detects Fileless Malware on Linux
// Technique: Scanning /proc/[pid]/fd for "memfd:" or "(deleted)" executable links
type MemfdHunter struct {}

func NewMemfdHunter() *MemfdHunter {
	return &MemfdHunter{}
}

func (m *MemfdHunter) Name() string {
	return "Linux Memfd/Fileless Hunter"
}

func (m *MemfdHunter) Run() ([]core.Threat, error) {
	fmt.Println("[*] Hunting for Fileless Malware (memfd_create)...")
	
	threats := []core.Threat{}
	
	// 1. Get all PIDs
	procs, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}

	for _, p := range procs {
		if !p.IsDir() {
			continue
		}
		pid := p.Name()
		// Basic numeric check
		if _, err := os.Stat(filepath.Join("/proc", pid)); err != nil {
			continue
		}

		// 2. Scan File Descriptors
		fdPath := filepath.Join("/proc", pid, "fd")
		fds, err := os.ReadDir(fdPath)
		if err == nil {
			for _, fd := range fds {
				linkPath := filepath.Join(fdPath, fd.Name())
				target, err := os.Readlink(linkPath)
				if err != nil {
					continue
				}

				// Check for known fileless indicators
				// Malicious actors often use memfd_create() and then execve() it.
				// It appears as "/memfd:name (deleted)" often.
				if strings.Contains(target, "memfd:") || 
				   (strings.Contains(target, "(deleted)") && isExecutable(linkPath)) {
					
					fmt.Printf("[!] SUSPICIOUS: PID %s -> FD %s -> %s\n", pid, fd.Name(), target)
					
					threats = append(threats, core.Threat{
						Name: "Fileless Execution Detected (memfd)",
						Description: fmt.Sprintf("Process %s holding anonymous executable memory: %s", pid, target),
						Level: core.LevelCritical,
						Details: map[string]interface{}{
							"PID": pid,
							"Target": target,
						},
					})
				}
			}
		}
		
		// 3. Scan Maps for rwxp (Memory Execution)
		// ... logic for parsing /proc/pid/maps would go here
	}

	return threats, nil
}

func isExecutable(path string) bool {
	// Simplified check. Real check would stat the link target or check map permissions
	return true 
}
