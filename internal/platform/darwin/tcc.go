package darwin

import (
	"arakne/internal/core"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

// TCCScanner implements macOS threat detection
type TCCScanner struct {
	SystemDB string
	UserDB   string
	Threats  []core.Threat
}

func NewTCCScanner() *TCCScanner {
	return &TCCScanner{
		SystemDB: "/Library/Application Support/com.apple.TCC/TCC.db",
		UserDB:   "~/Library/Application Support/com.apple.TCC/TCC.db",
	}
}

func (m *TCCScanner) Name() string {
	return "macOS TCC (Privacy) Analyzer"
}

func (m *TCCScanner) Run() ([]core.Threat, error) {
	fmt.Println("[*] Scanning macOS for threats...")
	m.Threats = []core.Threat{}

	// 1. Check Launch Agents/Daemons
	m.scanLaunchItems()

	// 2. Check for suspicious shell profiles
	m.checkShellProfiles()

	// 3. Check Kext loading
	m.checkKexts()

	// 4. Check login items
	m.checkLoginItems()

	// 5. Check for SIP status
	m.checkSIPStatus()

	fmt.Printf("[+] macOS scan complete. Found %d threats.\n", len(m.Threats))
	return m.Threats, nil
}

func (m *TCCScanner) scanLaunchItems() {
	fmt.Println("    [-] Scanning LaunchAgents and LaunchDaemons...")

	home, _ := os.UserHomeDir()
	launchPaths := []string{
		"/Library/LaunchDaemons",
		"/Library/LaunchAgents",
		"/System/Library/LaunchDaemons",
		filepath.Join(home, "Library/LaunchAgents"),
	}

	susPatterns := []string{
		"curl", "wget", "nc ", "bash -c", "python -c",
		"/tmp/", "/var/tmp/", "base64", "openssl",
	}

	for _, path := range launchPaths {
		files, err := ioutil.ReadDir(path)
		if err != nil {
			continue
		}

		for _, f := range files {
			if !strings.HasSuffix(f.Name(), ".plist") {
				continue
			}

			plistPath := filepath.Join(path, f.Name())
			data, err := ioutil.ReadFile(plistPath)
			if err != nil {
				continue
			}

			content := strings.ToLower(string(data))

			// Check for suspicious patterns
			for _, pattern := range susPatterns {
				if strings.Contains(content, pattern) {
					m.Threats = append(m.Threats, core.Threat{
						Name:        "Suspicious Launch Item",
						Description: fmt.Sprintf("Pattern '%s' found in %s", pattern, f.Name()),
						Level:       core.LevelHigh,
						FilePath:    plistPath,
					})
					break
				}
			}

			// Check for items running from unusual locations
			if strings.Contains(content, "/tmp/") ||
				strings.Contains(content, "/var/tmp/") ||
				strings.Contains(content, "/users/shared/") {
				m.Threats = append(m.Threats, core.Threat{
					Name:        "Launch Item from Temp Directory",
					Description: fmt.Sprintf("%s runs from suspicious location", f.Name()),
					Level:       core.LevelCritical,
					FilePath:    plistPath,
				})
			}
		}
	}
}

func (m *TCCScanner) checkShellProfiles() {
	fmt.Println("    [-] Checking shell profiles for persistence...")

	home, _ := os.UserHomeDir()
	profiles := []string{
		filepath.Join(home, ".bash_profile"),
		filepath.Join(home, ".bashrc"),
		filepath.Join(home, ".zshrc"),
		filepath.Join(home, ".profile"),
		"/etc/profile",
		"/etc/bashrc",
	}

	susPatterns := []string{
		"curl", "wget", "base64", "eval", "exec",
		"/dev/tcp", "nc -e", "python -c",
	}

	for _, profile := range profiles {
		data, err := ioutil.ReadFile(profile)
		if err != nil {
			continue
		}

		content := strings.ToLower(string(data))
		for _, pattern := range susPatterns {
			if strings.Contains(content, pattern) {
				m.Threats = append(m.Threats, core.Threat{
					Name:        "Suspicious Shell Profile Entry",
					Description: fmt.Sprintf("Pattern '%s' in %s", pattern, filepath.Base(profile)),
					Level:       core.LevelHigh,
					FilePath:    profile,
				})
				break
			}
		}
	}
}

func (m *TCCScanner) checkKexts() {
	fmt.Println("    [-] Checking loaded kernel extensions...")

	// List kexts from /Library/Extensions
	kextPath := "/Library/Extensions"
	files, err := ioutil.ReadDir(kextPath)
	if err != nil {
		return
	}

	for _, f := range files {
		if strings.HasSuffix(f.Name(), ".kext") {
			// Check if it's signed (would require codesign check)
			fmt.Printf("    [+] Found kext: %s\n", f.Name())
		}
	}
}

func (m *TCCScanner) checkLoginItems() {
	fmt.Println("    [-] Checking login items...")

	home, _ := os.UserHomeDir()
	loginItemsPath := filepath.Join(home, "Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm")

	if _, err := os.Stat(loginItemsPath); err == nil {
		fmt.Println("    [+] Found login items database")
		// Would need to parse the BTM format
	}
}

func (m *TCCScanner) checkSIPStatus() {
	fmt.Println("    [-] Checking System Integrity Protection...")

	// Check csrutil status via nvram or output
	// This is a simplified check
	_, err := os.Stat("/System/Library/Sandbox/rootless.conf")
	if err != nil {
		m.Threats = append(m.Threats, core.Threat{
			Name:        "SIP May Be Disabled",
			Description: "Could not verify System Integrity Protection status",
			Level:       core.LevelMedium,
		})
	}
}
