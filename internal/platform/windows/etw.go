package windows

import (
	"arakne/internal/core"
	"fmt"
	"os/exec"
	"strings"
)

// ETWSniffer monitors real-time events via Event Tracing for Windows
type ETWSniffer struct {
	Providers []ETWProvider
}

type ETWProvider struct {
	Name string
	GUID string
}

func NewETWSniffer() *ETWSniffer {
	return &ETWSniffer{
		Providers: []ETWProvider{
			{Name: "Microsoft-Windows-DotNETRuntime", GUID: "{E13C0D23-CCBC-4E12-931B-D9CC2EEE27E4}"},
			{Name: "Microsoft-Windows-PowerShell", GUID: "{A0C1853B-5C40-4B15-8766-3CF1C58F985A}"},
			{Name: "Microsoft-Antimalware-Scan-Interface", GUID: "{2A576B87-09A7-520E-C21A-4942F0271D67}"},
		},
	}
}

func (e *ETWSniffer) Name() string {
	return "ETW Real-Time Monitor"
}

func (e *ETWSniffer) Run() ([]core.Threat, error) {
	fmt.Println("[*] Initializing ETW Sniffer...")
	threats := []core.Threat{}

	// Check for suspicious PowerShell activity via Event Log
	psThreats := e.checkPowerShellLogs()
	threats = append(threats, psThreats...)

	// Check for .NET assembly loads
	dotnetThreats := e.checkDotNetLogs()
	threats = append(threats, dotnetThreats...)

	// Check AMSI bypasses
	amsiThreats := e.checkAMSILogs()
	threats = append(threats, amsiThreats...)

	fmt.Printf("[+] ETW Analysis Complete. Found %d suspicious events.\n", len(threats))
	return threats, nil
}

func (e *ETWSniffer) checkPowerShellLogs() []core.Threat {
	threats := []core.Threat{}

	// Query PowerShell ScriptBlock logging via wevtutil
	cmd := exec.Command("wevtutil", "qe", "Microsoft-Windows-PowerShell/Operational",
		"/q:*[System[(EventID=4104)]]", "/c:50", "/f:text")
	output, err := cmd.Output()
	if err != nil {
		fmt.Println("    [-] Could not query PowerShell logs (may need admin)")
		return threats
	}

	// Check for suspicious patterns
	susPatterns := []string{
		"Invoke-Mimikatz",
		"Invoke-Expression",
		"IEX",
		"DownloadString",
		"Net.WebClient",
		"FromBase64String",
		"Bypass",
		"Hidden",
		"-enc ",
		"Invoke-Shellcode",
		"AmsiUtils",
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		for _, pattern := range susPatterns {
			if strings.Contains(strings.ToLower(line), strings.ToLower(pattern)) {
				fmt.Printf("    [!] Suspicious PowerShell: %s\n", pattern)
				threats = append(threats, core.Threat{
					Name:        "Suspicious PowerShell Activity",
					Description: fmt.Sprintf("ScriptBlock contains: %s", pattern),
					Level:       core.LevelHigh,
					Details:     map[string]interface{}{"pattern": pattern},
				})
				break
			}
		}
	}

	return threats
}

func (e *ETWSniffer) checkDotNetLogs() []core.Threat {
	threats := []core.Threat{}

	// Check for in-memory .NET assembly loads (execute-assembly style)
	cmd := exec.Command("wevtutil", "qe", "Microsoft-Windows-DotNETRuntime/Operational",
		"/q:*[System[(EventID=152)]]", "/c:20", "/f:text")
	output, _ := cmd.Output()

	if strings.Contains(string(output), "Assembly Loader") {
		// Look for assemblies loaded from memory (no path)
		if strings.Contains(string(output), "DynamicAssembly") {
			threats = append(threats, core.Threat{
				Name:        "In-Memory .NET Assembly",
				Description: "Dynamic assembly loaded (possible execute-assembly attack)",
				Level:       core.LevelCritical,
			})
		}
	}

	return threats
}

func (e *ETWSniffer) checkAMSILogs() []core.Threat {
	threats := []core.Threat{}

	// Check Windows Defender logs for AMSI detections
	cmd := exec.Command("wevtutil", "qe", "Microsoft-Windows-Windows Defender/Operational",
		"/q:*[System[(EventID=1116 or EventID=1117)]]", "/c:10", "/f:text")
	output, _ := cmd.Output()

	if len(output) > 0 && strings.Contains(string(output), "Threat") {
		threats = append(threats, core.Threat{
			Name:        "AMSI Detection",
			Description: "Windows Defender AMSI detected malicious content",
			Level:       core.LevelCritical,
		})
	}

	return threats
}
