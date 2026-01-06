package windows

import (
	"arakne/internal/core"
	"fmt"
)

// MemoryScanner implements the Scanner interface for RAM Forensics
type MemoryScanner struct{}

func (m *MemoryScanner) Name() string {
	return "Active Memory Hunter"
}

func (m *MemoryScanner) Run() ([]core.Threat, error) {
	fmt.Println("[*] Starting Memory Scan (Ghost Hunting)...")
	return m.ScanProcesses(), nil
}

func (m *MemoryScanner) ScanProcesses() []core.Threat {
	threats := []core.Threat{}

	procs, err := GetProcessList()
	if err != nil {
		fmt.Printf("[-] Failed to list processes: %v\n", err)
		return nil
	}

	fmt.Printf("[*] Scanning %d active processes for Injection/Shellcode...\n", len(procs))

	for _, p := range procs {
		// Skip System (0) and Idle (4) usually
		if p.PID <= 4 {
			continue
		}

		t := m.scanPID(p.PID, p.Name)
		if len(t) > 0 {
			threats = append(threats, t...)
		}
	}
	return threats
}

func (m *MemoryScanner) scanPID(pid uint32, name string) []core.Threat {
	threats := []core.Threat{}

	// Open Process with QUERY_INFORMATION | VM_READ
	// 0x1000 = PROCESS_QUERY_LIMITED_INFORMATION (safer), 0x0010 = VM_READ
	handle, err := OpenProcess(0x0400|0x0010, false, pid)
	if err != nil {
		// fmt.Printf("[-] Access Denied: %s (%d)\n", name, pid)
		return nil
	}
	defer CloseHandle(handle)

	var address uintptr = 0

	for {
		mbi, err := VirtualQueryEx(handle, address)
		if err != nil {
			break // End of memory or error
		}

		// Check for RWX (Execute + Write)
		// PAGE_EXECUTE_READWRITE = 0x40
		// PAGE_EXECUTE_WRITECOPY = 0x80
		if (mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_WRITECOPY) &&
			mbi.State == MEM_COMMIT {

			// Further check: Is it MEM_PRIVATE or MEM_MAPPED?
			// Legitimate DLLs are MEM_IMAGE.
			// Shellcode injection is almost ALWAYS MEM_PRIVATE or MEM_MAPPED.
			if mbi.Type == MEM_PRIVATE {
				fmt.Printf("[!] THREAT: RWX Memory Detect in %s (PID: %d) @ 0x%X Size: %d\n", name, pid, mbi.BaseAddress, mbi.RegionSize)

				threats = append(threats, core.Threat{
					Name:        "RWX Injection (Shellcode)",
					Description: fmt.Sprintf("Executable & Writable Private Memory found in %s", name),
					Level:       core.LevelCritical,
					Details: map[string]interface{}{
						"PID":     pid,
						"Address": mbi.BaseAddress,
						"Type":    "MEM_PRIVATE",
					},
				})
			}
		}

		address += mbi.RegionSize
	}

	return threats
}
