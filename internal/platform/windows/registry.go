package windows

import (
	"arakne/internal/core"
	"fmt"
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

			susPatterns := map[string]string{
				"\\temp\\":        "Runs from Temp directory",
				"\\appdata\\":     "Runs from AppData",
				"powershell":      "PowerShell in Run key",
				"cmd /c":          "CMD execution",
				"mshta":           "MSHTA execution",
				"wscript":         "WSH script",
				"cscript":         "CScript execution",
				"regsvr32 /s /n":  "Regsvr32 bypass",
				"rundll32":        "Rundll32 execution",
				"\\public\\":      "Runs from Public folder",
				"\\programdata\\": "Runs from ProgramData",
			}

			for pattern, desc := range susPatterns {
				if strings.Contains(lower, pattern) {
					suspicious = true
					reason = desc
					break
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
	// WMI permanent event subscriptions
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Wbem`, registry.QUERY_VALUE)
	if err != nil {
		return
	}
	defer key.Close()

	// WMI persistence usually requires WMI queries, but we can check for artifacts
	fmt.Println("    [-] WMI persistence check requires WMI queries (use wmic)")
}
