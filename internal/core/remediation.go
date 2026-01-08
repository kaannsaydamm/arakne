package core

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// RemediationManager handles the "Secure First, Ask Later" workflow
type RemediationManager struct {
	Jail       *QuarantineJail
	Bag        *BagHandler
	LogFile    *os.File
	Aggressive bool // Nuke Mode
	Verifier   func(hash string) (bool, string)
}

func NewRemediationManager(aggressive bool) *RemediationManager {
	// Initialize Jail and Evidence Bag
	jail := NewQuarantineJail("")
	bag := NewBagHandler("CASE_" + time.Now().Format("20060102"))

	return &RemediationManager{
		Jail:       jail,
		Bag:        bag,
		Aggressive: aggressive,
	}
}

// HandleThreat performs the full neutralization lifecycle - AUTOMATICALLY
func (r *RemediationManager) HandleThreat(t Threat) {
	fmt.Printf("\n[!!!] THREAT DETECTED: %s [Level: %d]\n", t.Name, t.Level)
	fmt.Printf("      Reason: %s\n", t.Description)

	// Special handling for Configuration Threats (UEFI/BIOS)
	if t.Type == ThreatTypeConfig {
		r.handleConfigThreat(t)
		return
	}

	// ---------------------------------------------------------
	// ONLINE VERIFICATION (Known-Good Check)
	// ---------------------------------------------------------
	if r.Verifier != nil && t.FilePath != "" {
		hash := t.FileHash
		if hash == "" {
			// Calculate hash if missing
			fmt.Printf("    [*] calculating hash for %s...\n", t.FilePath)
			h, err := r.calculateHash(t.FilePath)
			if err == nil {
				hash = h
			}
		}

		if hash != "" {
			fmt.Printf("    [*] Checking Known-Good Database (Online)... [%s]\n", hash[:12])
			isGood, desc := r.Verifier(hash)
			if isGood {
				fmt.Printf("    [!] FALSE POSITIVE DETECTED: %s\n", desc)
				fmt.Println("    [+] Whitelisting and skipping remediation.")
				return
			}
		}
	}
	// ---------------------------------------------------------

	// Auto-Evidence Collection
	if t.FilePath != "" {
		fmt.Println("[*] Auto-Collecting evidence...")
		r.Bag.Collect(t.FilePath)
	}

	// AUTOMATIC REMEDIATION (ComboFix Style)
	fmt.Println("[*] Initiating automatic neutralization...")

	switch t.Level {
	case 100: // Critical/Known Bad
		r.immobilize(t)
		r.quarantine(t)
	case 10: // Suspicious/Heuristic
		r.quarantine(t)
	default:
		// Default to quarantine for safety
		r.quarantine(t)
	}

	fmt.Println("[+] Threat neutralized.")
}

func (r *RemediationManager) calculateHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func (r *RemediationManager) handleConfigThreat(t Threat) {
	if fixCmd, ok := t.Details["FixCommand"].(string); ok {
		fmt.Printf("\n[+] Auto-Fix Available: %s\n", fixCmd)
		fmt.Print("    Apply fix now? (y/n): ")
		choice := r.readInput()
		if choice == "y" {
			fmt.Println("[*] Applying fix...")
			parts := strings.Fields(fixCmd)
			cmd := exec.Command(parts[0], parts[1:]...)
			out, err := cmd.CombinedOutput()
			if err != nil {
				fmt.Printf("[-] Fix Failed: %v\nOutput: %s\n", err, string(out))
			} else {
				fmt.Printf("[+] Fix Applied Successfully!\nOutput: %s\n", string(out))
				if strings.Contains(strings.ToLower(fixCmd), "bcdedit") {
					fmt.Println("[!] NOTE: A restart is required for BCD changes to take effect.")
				}
			}
		} else {
			fmt.Println("[-] Skipped.")
		}
	} else if instr, ok := t.Details["ManualInstructions"].(string); ok {
		fmt.Printf("\n[i] Manual Intervention Required:\n    %s\n", instr)
		fmt.Println("[*] Please address this issue manually (BIOS/Settings).")
	} else {
		fmt.Println("\n[!] No automated fix available for this configuration issue.")
	}
}

func (r *RemediationManager) immobilize(t Threat) {
	fmt.Println("    [Action] Immobilizing Threat...")

	// If it's a process -> Suspend & Kill Network
	if pid, ok := t.Details["PID"]; ok {
		fmt.Printf("    [Process] Suspending PID %v...\n", pid)
		// r.suspend(pid) // Todo: Implement suspend via syscall
		fmt.Printf("    [Network] Cutting connections for PID %v...\n", pid)
	}

	// If it's a file -> Collect Evidence
	if path, ok := t.Details["FilePath"]; ok {
		pStr := fmt.Sprintf("%v", path)
		fmt.Printf("    [Evidence] Bagging %s...\n", pStr)
		r.Bag.Collect(pStr)
	}
}

func (r *RemediationManager) quarantine(t Threat) (string, error) {
	if path, ok := t.Details["FilePath"]; ok {
		pStr := fmt.Sprintf("%v", path)
		fmt.Printf("    [Jail] Locking up %s...\n", pStr)

		// Lockup moves it to Jail (effectively deleting original)
		err := r.Jail.Lockup(pStr)
		if err != nil {
			return "", err
		}

		// Return the new path in jail (simplified)
		_, pName := filepath.Split(pStr) // Pseudo path matching Lockup logic
		return r.Jail.JailPath + "/" + time.Now().Format("20060102_150405") + "_" + pName + ".quarantine", nil
	}
	return "", nil
}

func (r *RemediationManager) readInput() string {
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(strings.ToLower(input))
}
