package windows

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// VSSHelper manages access to Volume Shadow Copies to read locked system files.
type VSSHelper struct {
	DriveLetter string
}

func NewVSSHelper(drive string) *VSSHelper {
	return &VSSHelper{DriveLetter: drive}
}

// CreateShadowCopy creates a new shadow copy for the drive and returns its Device Object path.
// Example return: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
func (v *VSSHelper) CreateShadowCopy() (string, error) {
	fmt.Printf("[*] VSS: Attempting to create Shadow Copy for %s...\n", v.DriveLetter)

	// We use vssadmin for now. In a production EnCase/EDR tool, we'd use the COM API (IVssBackupComponents).
	// This is "noisy" but effective for a standalone tool.
	cmd := exec.Command("vssadmin", "create", "shadow", "/for="+v.DriveLetter)

	// vssadmin output contains: "Shadow Copy Volume Name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyX"
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("vssadmin failed: %v | Output: %s", err, string(output))
	}

	outStr := string(output)
	if strings.Contains(outStr, "Successfully created") {
		// Extract path
		re := regexp.MustCompile(`Shadow Copy Volume Name: ([^\r\n]+)`)
		matches := re.FindStringSubmatch(outStr)
		if len(matches) > 1 {
			shadowPath := strings.TrimSpace(matches[1])
			fmt.Printf("[+] VSS: Snapshot mounted at %s\n", shadowPath)
			return shadowPath, nil
		}
	}

	return "", fmt.Errorf("could not parse vssadmin output")
}

// DeleteShadowCopies cleans up (Nuke tracks)
func (v *VSSHelper) DeleteShadowCopies() {
	exec.Command("vssadmin", "delete", "shadows", "/for="+v.DriveLetter, "/quiet").Run()
}
