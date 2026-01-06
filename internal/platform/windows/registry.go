package windows

import (
	"arakne/internal/core"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// RegistryParser analyzes registry for persistence and threats
type RegistryParser struct {
	Threats []core.Threat
}

func NewRegistryParser(data []byte) (*RegistryParser, error) {
	// Data parameter kept for offline hive support (future)
	return &RegistryParser{}, nil
}

func (r *RegistryParser) Name() string {
	return "Registry Persistence Analyzer"
}

func (r *RegistryParser) Walk() {
	fmt.Println("[*] Scanning Registry for persistence mechanisms...")

	r.Threats = []core.Threat{}

	// Check all Run keys
	r.checkRunKeys()

	// Check Services
	r.checkServices()

	// Check Scheduled Tasks (via registry)
	r.checkScheduledTasks()

	// Check AppInit_DLLs
	r.checkAppInitDLLs()

	// Check Image File Execution Options (debugger hijack)
	r.checkIFEO()

	// Check WMI persistence
	r.checkWMI()

	fmt.Printf("[+] Registry scan complete. Found %d persistence mechanisms.\n", len(r.Threats))
}

func (r *RegistryParser) checkRunKeys() {
	runKeys := []struct {
		root registry.Key
		path string
		name string
	}{
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, "HKLM Run"},
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, "HKLM RunOnce"},
		{registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, "HKCU Run"},
		{registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, "HKCU RunOnce"},
		{registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`, "HKLM Run (WOW64)"},
	}

	for _, rk := range runKeys {
		key, err := registry.OpenKey(rk.root, rk.path, registry.QUERY_VALUE)
		if err != nil {
			continue
		}

		names, _ := key.ReadValueNames(-1)
		for _, name := range names {
			val, _, err := key.GetStringValue(name)
			if err != nil {
				continue
			}

			// Check for suspicious entries
			lower := strings.ToLower(val)
			suspicious := false
			reason := ""

			// Whitelist for known legitimate apps that run from AppData
			legitApps := []string{
				"discord",
				"slack",
				"notion",
				"spotify",
				"steam",
				"bluestacks",
				"microsoft teams",
				"zoom",
				"brave",
				"chrome",
				"firefox",
				"opera",
				"vivaldi",
				"telegram",
				"whatsapp",
				"signal",
				"dropbox",
				"onedrive",
				"google drive",
				"nvidia",
				"amd",
				"msi",
				"logitech",
				"razer",
				"corsair",
				"steelseries",
				"openvpn",
				"nordvpn",
				"expressvpn",
				"anydesk",
				"teamviewer",
			}

			// Check if it's a legitimate app
			isLegit := false
			for _, app := range legitApps {
				if strings.Contains(lower, app) {
					isLegit = true
					break
				}
			}

			// Only check suspicious patterns if NOT a known legit app
			if !isLegit {
				susPatterns := map[string]string{
					"\\temp\\":            "Runs from Temp directory",
					"powershell -enc":     "Encoded PowerShell",
					"powershell -e ":      "Encoded PowerShell",
					"cmd /c":              "CMD execution",
					"mshta":               "MSHTA execution",
					"wscript":             "WSH script",
					"cscript":             "CScript execution",
					"regsvr32 /s /n":      "Regsvr32 bypass",
					"rundll32 javascript": "Rundll32 script",
					"\\public\\":          "Runs from Public folder",
					"\\programdata\\":     "Runs from ProgramData (non-installer)",
					"http://":             "Downloads from URL",
					"https://pastebin":    "Downloads from Pastebin",
				}

				for pattern, desc := range susPatterns {
					if strings.Contains(lower, pattern) {
						suspicious = true
						reason = desc
						break
					}
				}
			}

			if suspicious {
				fmt.Printf("    [!] Suspicious: %s\\%s = %s\n", rk.name, name, val)
				r.Threats = append(r.Threats, core.Threat{
					Name:        "Suspicious Auto-Run Entry",
					Description: fmt.Sprintf("%s: %s", reason, name),
					Level:       core.LevelHigh,
					Details: map[string]interface{}{
						"key":   rk.name,
						"name":  name,
						"value": val,
					},
				})
			}
		}
		key.Close()
	}
}

func (r *RegistryParser) checkServices() {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services`, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return
	}
	defer key.Close()

	services, _ := key.ReadSubKeyNames(-1)

	for _, svc := range services {
		svcKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
			`SYSTEM\CurrentControlSet\Services\`+svc, registry.QUERY_VALUE)
		if err != nil {
			continue
		}

		imagePath, _, _ := svcKey.GetStringValue("ImagePath")
		lower := strings.ToLower(imagePath)

		// Check for suspicious service paths
		if strings.Contains(lower, "\\temp\\") ||
			strings.Contains(lower, "\\appdata\\") ||
			strings.Contains(lower, "\\public\\") ||
			strings.Contains(lower, "cmd.exe") ||
			strings.Contains(lower, "powershell") {
			r.Threats = append(r.Threats, core.Threat{
				Name:        "Suspicious Service",
				Description: fmt.Sprintf("Service '%s' has suspicious path", svc),
				Level:       core.LevelHigh,
				Details: map[string]interface{}{
					"service":   svc,
					"imagePath": imagePath,
				},
			})
		}
		svcKey.Close()
	}
}

func (r *RegistryParser) checkScheduledTasks() {
	// Check task cache in registry
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks`,
		registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return
	}
	defer key.Close()

	tasks, _ := key.ReadSubKeyNames(-1)
	fmt.Printf("    [-] Found %d scheduled task GUIDs in registry.\n", len(tasks))
}

func (r *RegistryParser) checkAppInitDLLs() {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`, registry.QUERY_VALUE)
	if err != nil {
		return
	}
	defer key.Close()

	dlls, _, _ := key.GetStringValue("AppInit_DLLs")
	if dlls != "" && dlls != " " {
		r.Threats = append(r.Threats, core.Threat{
			Name:        "AppInit_DLLs Set",
			Description: "DLLs injected into every process via AppInit",
			Level:       core.LevelCritical,
			Details:     map[string]interface{}{"dlls": dlls},
		})
	}

	loadAppInit, _, _ := key.GetIntegerValue("LoadAppInit_DLLs")
	if loadAppInit == 1 && dlls != "" {
		fmt.Println("    [!] WARNING: AppInit_DLLs injection is ACTIVE")
	}
}

func (r *RegistryParser) checkIFEO() {
	// Image File Execution Options - debugger hijacking
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`,
		registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return
	}
	defer key.Close()

	exes, _ := key.ReadSubKeyNames(-1)
	for _, exe := range exes {
		exeKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
			`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\`+exe,
			registry.QUERY_VALUE)
		if err != nil {
			continue
		}

		debugger, _, _ := exeKey.GetStringValue("Debugger")
		if debugger != "" {
			r.Threats = append(r.Threats, core.Threat{
				Name:        "IFEO Debugger Hijack",
				Description: fmt.Sprintf("%s redirected to: %s", exe, debugger),
				Level:       core.LevelCritical,
				Details: map[string]interface{}{
					"target":   exe,
					"debugger": debugger,
				},
			})
		}
		exeKey.Close()
	}
}

func (r *RegistryParser) checkWMI() {
	fmt.Println("    [-] Scanning WMI Persistence (OBJECTS.DATA)...")

	// WMI persistence locations
	wmiPaths := []string{
		os.Getenv("SYSTEMROOT") + "\\System32\\wbem\\Repository\\OBJECTS.DATA",
		os.Getenv("SYSTEMROOT") + "\\System32\\wbem\\Repository\\FS\\OBJECTS.DATA",
	}

	for _, wmiPath := range wmiPaths {
		r.parseWMIObjectsData(wmiPath)
	}

	// Also check via WMI query for active subscriptions
	r.checkWMISubscriptions()
}

func (r *RegistryParser) parseWMIObjectsData(filePath string) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return
	}

	fmt.Printf("    [+] Parsing OBJECTS.DATA (%d bytes)...\n", len(data))

	// Search for WMI event consumer signatures
	signatures := []struct {
		pattern []byte
		name    string
	}{
		{[]byte("CommandLineEventConsumer"), "CommandLineEventConsumer"},
		{[]byte("ActiveScriptEventConsumer"), "ActiveScriptEventConsumer"},
		{[]byte("__EventFilter"), "EventFilter"},
		{[]byte("__FilterToConsumerBinding"), "FilterToConsumerBinding"},
	}

	for _, sig := range signatures {
		count := countOccurrences(data, sig.pattern)
		if count > 0 {
			fmt.Printf("    [!] Found %d %s entries\n", count, sig.name)
		}
	}

	// Search for suspicious command patterns in MOF data
	suspiciousPatterns := []struct {
		pattern []byte
		desc    string
	}{
		{[]byte("powershell"), "PowerShell execution"},
		{[]byte("cmd.exe"), "CMD execution"},
		{[]byte("wscript"), "WScript execution"},
		{[]byte("cscript"), "CScript execution"},
		{[]byte("mshta"), "MSHTA execution"},
		{[]byte("-enc"), "Encoded PowerShell"},
		{[]byte("-EncodedCommand"), "Encoded PowerShell"},
		{[]byte("DownloadString"), "Download cradle"},
		{[]byte("Invoke-Expression"), "IEX"},
		{[]byte("FromBase64String"), "Base64 decoding"},
		{[]byte("Net.WebClient"), "WebClient"},
		{[]byte("bitsadmin"), "BITS transfer"},
		{[]byte("certutil"), "Certutil download"},
	}

	for _, p := range suspiciousPatterns {
		if containsBytes(data, p.pattern) {
			// Extract surrounding context
			context := extractContext(data, p.pattern, 100)

			r.Threats = append(r.Threats, core.Threat{
				Name:        "WMI Persistence Detected",
				Description: fmt.Sprintf("OBJECTS.DATA contains: %s", p.desc),
				Level:       core.LevelCritical,
				FilePath:    filePath,
				Details: map[string]interface{}{
					"pattern": string(p.pattern),
					"context": context,
				},
			})
		}
	}

	// Parse for CommandLineTemplate strings
	cmdTemplates := extractCommandLineTemplates(data)
	for _, cmd := range cmdTemplates {
		if len(cmd) > 10 {
			fmt.Printf("    [!] CommandLineTemplate: %s\n", truncate(cmd, 80))
			r.Threats = append(r.Threats, core.Threat{
				Name:        "WMI Command Execution",
				Description: truncate(cmd, 200),
				Level:       core.LevelCritical,
				FilePath:    filePath,
			})
		}
	}
}

func (r *RegistryParser) checkWMISubscriptions() {
	// Query active WMI subscriptions via wmic
	output, err := runWMIC("wmic", "/namespace:\\\\root\\subscription", "path", "__EventFilter", "get", "Name,Query", "/format:csv")
	if err == nil && len(output) > 50 {
		// Parse output for suspicious queries
		if containsString(output, "SELECT") && (containsString(output, "Win32_Process") || containsString(output, "__InstanceCreation")) {
			r.Threats = append(r.Threats, core.Threat{
				Name:        "Active WMI Event Subscription",
				Description: "WMI EventFilter detected - possible persistence",
				Level:       core.LevelHigh,
			})
		}
	}

	// Check EventConsumers
	output, _ = runWMIC("wmic", "/namespace:\\\\root\\subscription", "path", "CommandLineEventConsumer", "get", "Name,CommandLineTemplate", "/format:csv")
	if len(output) > 50 {
		r.Threats = append(r.Threats, core.Threat{
			Name:        "Active WMI CommandLine Consumer",
			Description: "CommandLineEventConsumer detected",
			Level:       core.LevelCritical,
		})
	}
}

// Helper functions
func countOccurrences(data, pattern []byte) int {
	count := 0
	for i := 0; i <= len(data)-len(pattern); i++ {
		if matchBytes(data[i:], pattern) {
			count++
		}
	}
	return count
}

func containsBytes(data, pattern []byte) bool {
	for i := 0; i <= len(data)-len(pattern); i++ {
		if matchBytes(data[i:], pattern) {
			return true
		}
	}
	return false
}

func matchBytes(data, pattern []byte) bool {
	for i := 0; i < len(pattern); i++ {
		if data[i] != pattern[i] {
			return false
		}
	}
	return true
}

func extractContext(data, pattern []byte, size int) string {
	for i := 0; i <= len(data)-len(pattern); i++ {
		if matchBytes(data[i:], pattern) {
			start := i - size
			if start < 0 {
				start = 0
			}
			end := i + len(pattern) + size
			if end > len(data) {
				end = len(data)
			}
			return sanitizeString(string(data[start:end]))
		}
	}
	return ""
}

func extractCommandLineTemplates(data []byte) []string {
	results := []string{}

	// Search for CommandLineTemplate followed by string data
	pattern := []byte("CommandLineTemplate")

	for i := 0; i <= len(data)-len(pattern)-50; i++ {
		if matchBytes(data[i:], pattern) {
			// Look for command string after the pattern
			for j := i + len(pattern); j < i+500 && j < len(data)-1; j++ {
				// Look for typical command starts
				if (data[j] == 'c' || data[j] == 'C') && j+3 < len(data) {
					if matchBytes(data[j:], []byte("cmd")) || matchBytes(data[j:], []byte("CMD")) ||
						matchBytes(data[j:], []byte("pow")) || matchBytes(data[j:], []byte("Pow")) {
						// Extract until null or control char
						end := j
						for end < len(data) && data[end] >= 32 && data[end] < 127 {
							end++
						}
						if end-j > 10 {
							results = append(results, string(data[j:end]))
						}
						break
					}
				}
			}
		}
	}

	return results
}

func sanitizeString(s string) string {
	result := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] >= 32 && s[i] < 127 {
			result = append(result, s[i])
		} else {
			result = append(result, '.')
		}
	}
	return string(result)
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func containsString(s, substr string) bool {
	return strings.Contains(s, substr)
}

func runWMIC(args ...string) (string, error) {
	// Use os/exec
	cmd := exec.Command(args[0], args[1:]...)
	output, err := cmd.Output()
	return string(output), err
}
