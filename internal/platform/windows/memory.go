package windows

import (
	"arakne/internal/core"
	"fmt"
	"strings"
)

// MemoryScanner implements the Scanner interface for RAM Forensics
type MemoryScanner struct{}

// Processes known to legitimately use RWX memory (JIT engines, browsers, etc)
var jitWhitelist = map[string]bool{
	// Browsers (V8/SpiderMonkey JIT)
	"chrome.exe":         true,
	"msedge.exe":         true,
	"msedgewebview2.exe": true,
	"firefox.exe":        true,
	"zen.exe":            true,
	"brave.exe":          true,
	"opera.exe":          true,
	"vivaldi.exe":        true,

	// .NET / PowerShell (CLR JIT)
	"powershell.exe": true,
	"pwsh.exe":       true,
	"dotnet.exe":     true,

	// Java (HotSpot JIT)
	"java.exe":  true,
	"javaw.exe": true,

	// Node.js (V8 JIT)
	"node.exe": true,

	// GPU / Graphics (shader compilation)
	"nvidia overlay.exe": true,
	"amd.exe":            true,

	// Development tools
	"code.exe":        true,
	"devenv.exe":      true,
	"antigravity.exe": true,

	// Common legitimate apps with JIT
	"discord.exe":        true,
	"slack.exe":          true,
	"teams.exe":          true,
	"spotify.exe":        true,
	"whatsapp.exe":       true,
	"telegram.exe":       true,
	"openvpnconnect.exe": true,
	"anydesk.exe":        true,

	// System apps that use RWX
	"wmiprvse.exe":            true,
	"searchui.exe":            true,
	"runtimebroker.exe":       true,
	"backgroundtaskhost.exe":  true,
	"phoneexperiencehost.exe": true,

	// Vendor tools (MSI, etc)
	"msi_lan_manager_tool.exe": true,
	"msi.terminalserver.exe":   true,
	"omapsvcbroker.exe":        true,
	"nhnotifsys.exe":           true,
	"dcv2.exe":                 true,
	"rvrvpngui.exe":            true,
}

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

		// Skip whitelisted JIT processes
		lowerName := strings.ToLower(p.Name)
		if jitWhitelist[lowerName] {
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
	rwxCount := 0
	maxRWXReports := 3 // Limit reports per process to avoid spam

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
				rwxCount++

				// Only report first few to avoid spam
				if rwxCount <= maxRWXReports {
					fmt.Printf("[!] THREAT: RWX Memory Detect in %s (PID: %d) @ 0x%X Size: %d\n", name, pid, mbi.BaseAddress, mbi.RegionSize)

					threats = append(threats, core.Threat{
						Name:        "RWX Injection (Shellcode)",
						Description: fmt.Sprintf("Executable & Writable Private Memory found in %s", name),
						Level:       core.LevelHigh, // Downgrade from Critical - needs investigation
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
