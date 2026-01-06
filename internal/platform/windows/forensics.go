package windows

import (
	"arakne/internal/core"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// ForensicsScanner handles Event Logs, USN Journal, and Prefetch
type ForensicsScanner struct{}

func NewForensicsScanner() *ForensicsScanner {
	return &ForensicsScanner{}
}

func (f *ForensicsScanner) Name() string {
	return "Deep Forensics (Logs/History)"
}

func (f *ForensicsScanner) Run() ([]core.Threat, error) {
	fmt.Println("[*] Starting Deep Forensics Analysis...")
	threats := []core.Threat{}

	// 1. Event Log Analysis (Lateral Movement, Persistence)
	eventThreats := f.scanEventLogs()
	threats = append(threats, eventThreats...)

	// 2. Check for cleared logs (anti-forensics)
	clearedThreats := f.checkClearedLogs()
	threats = append(threats, clearedThreats...)

	// 3. Prefetch Analysis
	prefetchThreats := f.scanPrefetch()
	threats = append(threats, prefetchThreats...)

	fmt.Printf("[+] Forensics Analysis Complete. Found %d indicators.\n", len(threats))
	return threats, nil
}

func (f *ForensicsScanner) scanEventLogs() []core.Threat {
	fmt.Println("    [-] Querying Security Event Log...")
	threats := []core.Threat{}

	// Check for Type 3 (Network) and Type 10 (RemoteInteractive) logons from unusual sources
	cmd := exec.Command("wevtutil", "qe", "Security",
		"/q:*[System[(EventID=4624)]]", "/c:100", "/f:text")
	output, err := cmd.Output()
	if err != nil {
		fmt.Println("    [!] Could not query Security log (need admin)")
		return threats
	}

	lines := strings.Split(string(output), "\n")
	type3Count := 0
	type10Count := 0

	for _, line := range lines {
		if strings.Contains(line, "Logon Type") {
			if strings.Contains(line, "3") {
				type3Count++
			}
			if strings.Contains(line, "10") {
				type10Count++
			}
		}
	}

	if type3Count > 20 {
		threats = append(threats, core.Threat{
			Name:        "High Network Logon Activity",
			Description: fmt.Sprintf("Detected %d Type 3 (Network) logons. May indicate lateral movement.", type3Count),
			Level:       core.LevelMedium,
		})
	}

	if type10Count > 5 {
		threats = append(threats, core.Threat{
			Name:        "Remote Desktop Activity",
			Description: fmt.Sprintf("Detected %d Type 10 (RDP) logons. Review for unauthorized access.", type10Count),
			Level:       core.LevelMedium,
		})
	}

	// Check for new service installations (persistence)
	fmt.Println("    [-] Checking for new service installations...")
	cmd = exec.Command("wevtutil", "qe", "System",
		"/q:*[System[(EventID=7045)]]", "/c:50", "/f:text")
	output, _ = cmd.Output()

	susServices := []string{"cmd.exe", "powershell", "mshta", "wscript", "cscript", "rundll32"}
	for _, svc := range susServices {
		if strings.Contains(strings.ToLower(string(output)), svc) {
			threats = append(threats, core.Threat{
				Name:        "Suspicious Service Installation",
				Description: fmt.Sprintf("Service installed with suspicious binary: %s", svc),
				Level:       core.LevelCritical,
			})
		}
	}

	// Check for process creation with command line (4688)
	fmt.Println("    [-] Analyzing process creation events...")
	cmd = exec.Command("wevtutil", "qe", "Security",
		"/q:*[System[(EventID=4688)]]", "/c:100", "/f:text")
	output, _ = cmd.Output()

	susProcesses := []string{
		"whoami", "net user", "net group", "nltest", "dsquery",
		"mimikatz", "procdump", "psexec", "wmic shadowcopy",
	}
	for _, proc := range susProcesses {
		if strings.Contains(strings.ToLower(string(output)), proc) {
			threats = append(threats, core.Threat{
				Name:        "Reconnaissance/Attack Tool Execution",
				Description: fmt.Sprintf("Detected execution of: %s", proc),
				Level:       core.LevelHigh,
			})
		}
	}

	return threats
}

func (f *ForensicsScanner) checkClearedLogs() []core.Threat {
	fmt.Println("    [-] Checking for log clearing (anti-forensics)...")
	threats := []core.Threat{}

	// Event ID 1102 = Security log was cleared
	cmd := exec.Command("wevtutil", "qe", "Security",
		"/q:*[System[(EventID=1102)]]", "/c:10", "/f:text")
	output, _ := cmd.Output()

	if len(output) > 100 { // If we got results
		threats = append(threats, core.Threat{
			Name:        "Security Log Cleared",
			Description: "Windows Security event log was cleared - possible anti-forensics activity",
			Level:       core.LevelCritical,
		})
	}

	// Check log sizes (small = potentially cleared)
	cmd = exec.Command("wevtutil", "gli", "Security")
	output, _ = cmd.Output()

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "numberOfLogRecords") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				count, _ := strconv.Atoi(strings.TrimSpace(parts[1]))
				if count < 100 {
					threats = append(threats, core.Threat{
						Name:        "Suspiciously Small Log",
						Description: fmt.Sprintf("Security log has only %d events - may have been cleared", count),
						Level:       core.LevelMedium,
					})
				}
			}
		}
	}

	return threats
}

func (f *ForensicsScanner) scanPrefetch() []core.Threat {
	fmt.Println("    [-] Analyzing Prefetch files...")
	threats := []core.Threat{}

	// Check for execution of known attack tools via prefetch
	cmd := exec.Command("cmd", "/c", "dir", "C:\\Windows\\Prefetch\\*.pf", "/b")
	output, err := cmd.Output()
	if err != nil {
		return threats
	}

	susTools := []string{
		"MIMIKATZ", "PROCDUMP", "PSEXEC", "WCEAUX", "GSECDUMP",
		"FGDUMP", "PWDUMP", "SECRETSDUMP", "BLOODHOUND", "SHARPHOUND",
		"RUBEUS", "KEKEO", "SAFETYKATZ", "LAZAGNE",
	}

	files := strings.Split(string(output), "\n")
	for _, file := range files {
		upper := strings.ToUpper(file)
		for _, tool := range susTools {
			if strings.Contains(upper, tool) {
				threats = append(threats, core.Threat{
					Name:        "Attack Tool Prefetch Found",
					Description: fmt.Sprintf("Evidence of %s execution found in Prefetch", tool),
					Level:       core.LevelCritical,
					FilePath:    "C:\\Windows\\Prefetch\\" + strings.TrimSpace(file),
				})
			}
		}
	}

	return threats
}
