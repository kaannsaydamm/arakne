package windows

import (
	"arakne/internal/core"
	"fmt"
	"strings"
	"syscall"
	"unsafe"
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

		// Get executable path and verify signature
		execPath := getProcessPath(p.PID)
		if execPath != "" {
			trusted, reason := IsExecutableTrusted(execPath)
			if trusted {
				// Skip signed/trusted executables - they use RWX for JIT legitimately
				continue
			}
			// Log unsigned/untrusted for visibility
			if reason == "unsigned" {
				fmt.Printf("    [i] Unsigned process: %s (%s)\n", p.Name, reason)
			}
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
	handle, err := OpenProcess(0x0400|0x0010, false, pid)
	if err != nil {
		return nil
	}
	defer CloseHandle(handle)

	var address uintptr = 0
	rwxCount := 0
	maxRWXReports := 3 // Limit reports per process to avoid spam

	for {
		mbi, err := VirtualQueryEx(handle, address)
		if err != nil {
			break
		}

		// Check for RWX (Execute + Write)
		if (mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_WRITECOPY) &&
			mbi.State == MEM_COMMIT {

			// Shellcode is almost always MEM_PRIVATE
			if mbi.Type == MEM_PRIVATE {
				rwxCount++

				if rwxCount <= maxRWXReports {
					fmt.Printf("[!] THREAT: RWX Memory in %s (PID: %d) @ 0x%X Size: %d\n", name, pid, mbi.BaseAddress, mbi.RegionSize)

					threats = append(threats, core.Threat{
						Name:        "RWX Injection (Shellcode)",
						Description: fmt.Sprintf("Executable & Writable Private Memory found in UNSIGNED %s", name),
						Level:       core.LevelHigh,
						Details: map[string]interface{}{
							"PID":     pid,
							"Address": mbi.BaseAddress,
							"Type":    "MEM_PRIVATE",
						},
					})
				}
			}
		}

		address += mbi.RegionSize
	}

	if rwxCount > maxRWXReports {
		fmt.Printf("    [+] (and %d more RWX regions in %s)\n", rwxCount-maxRWXReports, name)
	}

	return threats
}

// getProcessPath gets the executable path for a PID using QueryFullProcessImageNameW
func getProcessPath(pid uint32) string {
	// Open process with PROCESS_QUERY_LIMITED_INFORMATION (0x1000)
	handle, err := OpenProcess(0x1000, false, pid)
	if err != nil {
		return ""
	}
	defer CloseHandle(handle)

	// Buffer for path
	buf := make([]uint16, 1024)
	size := uint32(len(buf))

	// Call QueryFullProcessImageNameW
	ret, _, _ := procQueryFullProcessImageNameW.Call(
		uintptr(handle),
		0, // Use Win32 path format
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
	)

	if ret == 0 {
		return ""
	}

	return syscall.UTF16ToString(buf[:size])
}

// isKnownJITProcess checks if process name matches known JIT engines
// This is a fallback when signature verification fails
func isKnownJITProcess(name string) bool {
	jitNames := []string{
		"chrome", "msedge", "firefox", "zen", "brave",
		"powershell", "pwsh", "node", "java",
		"code", "devenv", "antigravity",
	}

	lowerName := strings.ToLower(name)
	for _, jit := range jitNames {
		if strings.Contains(lowerName, jit) {
			return true
		}
	}
	return false
}
