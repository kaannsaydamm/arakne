package windows

import (
	"arakne/internal/core"
	"fmt"
	"os/exec"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// UEFIScanner inspects EFI configuration and Secure Boot status
type UEFIScanner struct{}

func NewUEFIScanner() *UEFIScanner {
	return &UEFIScanner{}
}

func (u *UEFIScanner) Name() string {
	return "UEFI/Bootkit Scanner"
}

func (u *UEFIScanner) Run() ([]core.Threat, error) {
	fmt.Println("[*] Scanning UEFI & Secure Boot Configuration...")

	threats := []core.Threat{}

	// 1. Check Secure Boot State via Registry
	secureBootEnabled := u.checkSecureBootRegistry()
	if !secureBootEnabled {
		fmt.Println("[!] WARNING: Secure Boot is DISABLED.")
		threats = append(threats, core.Threat{
			Name:        "Secure Boot Disabled",
			Description: "System is vulnerable to Bootkits/Rootkits. Attacker can load unsigned boot code.",
			Level:       core.LevelCritical,
		})
	} else {
		fmt.Println("[+] Secure Boot is ENABLED.")
	}

	// 2. Check if UEFI or Legacy BIOS
	isUEFI := u.checkUEFIMode()
	if !isUEFI {
		fmt.Println("[!] WARNING: System is in Legacy BIOS mode (MBR vulnerable).")
		threats = append(threats, core.Threat{
			Name:        "Legacy BIOS Mode",
			Description: "System uses MBR boot which is vulnerable to bootkits like TDL4/Alureon.",
			Level:       core.LevelHigh,
		})
	}

	// 3. Check for Test Signing Mode
	testSigning := u.checkTestSigning()
	if testSigning {
		fmt.Println("[!] WARNING: Test Signing Mode is ENABLED.")
		threats = append(threats, core.Threat{
			Name:        "Test Signing Enabled",
			Description: "Unsigned drivers can be loaded. Common in development but dangerous in production.",
			Level:       core.LevelHigh,
		})
	}

	// 4. Check DEP/NX status
	depEnabled := u.checkDEP()
	if !depEnabled {
		threats = append(threats, core.Threat{
			Name:        "DEP Disabled",
			Description: "Data Execution Prevention is disabled, making exploitation easier.",
			Level:       core.LevelMedium,
		})
	}

	return threats, nil
}

func (u *UEFIScanner) checkSecureBootRegistry() bool {
	// HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\SecureBoot\State`, registry.QUERY_VALUE)
	if err != nil {
		return false // Key doesn't exist = likely Legacy BIOS
	}
	defer key.Close()

	val, _, err := key.GetIntegerValue("UEFISecureBootEnabled")
	if err != nil {
		return false
	}

	return val == 1
}

func (u *UEFIScanner) checkUEFIMode() bool {
	// Check if EFI system partition exists via diskpart/bcdedit
	cmd := exec.Command("bcdedit", "/enum", "firmware")
	output, err := cmd.Output()
	if err != nil {
		// Try alternative method
		key, err := registry.OpenKey(registry.LOCAL_MACHINE,
			`SYSTEM\CurrentControlSet\Control\SecureBoot`, registry.QUERY_VALUE)
		if err != nil {
			return false // SecureBoot key doesn't exist = Legacy BIOS
		}
		key.Close()
		return true
	}

	return strings.Contains(string(output), "firmware")
}

func (u *UEFIScanner) checkTestSigning() bool {
	cmd := exec.Command("bcdedit", "/enum", "{current}")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	return strings.Contains(strings.ToLower(string(output)), "testsigning") &&
		strings.Contains(strings.ToLower(string(output)), "yes")
}

func (u *UEFIScanner) checkDEP() bool {
	// Check NX policy
	cmd := exec.Command("bcdedit", "/enum", "{current}")
	output, err := cmd.Output()
	if err != nil {
		return true // Assume enabled if we can't check
	}

	lower := strings.ToLower(string(output))
	// "nx" set to "alwaysoff" means DEP disabled
	if strings.Contains(lower, "nx") && strings.Contains(lower, "alwaysoff") {
		return false
	}

	return true
}
