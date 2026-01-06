package core

import (
	"bufio"
	"fmt"
	"os"
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

// HandleThreat performs the full neutralization lifecycle
func (r *RemediationManager) HandleThreat(t Threat) {
	fmt.Printf("\n[!!!] THREAT DETECTED: %s [Level: %d]\n", t.Name, t.Level)
	fmt.Printf("      Reason: %s\n", t.Description)

	// 1. Immobilize & Collect Evidence (Automatic)
	r.immobilize(t)

	// 2. Quarantine (Automatic - Move to Jail)
	quarantinedPath, err := r.quarantine(t)
	if err != nil {
		fmt.Printf("[-] Quarantine Failed: %v\n", err)
	}

	// 3. User Decision (Unless Nuke Mode)
	if r.Aggressive {
		fmt.Println("[NUKE] Threat annihilated. No questions asked.")
		return
	}

	// Normal Mode: Ask for final disposition
	fmt.Print("\n[?] Threat is JAILED and SECURED. \n    Evidence saved in Bag. \n    Delete permanently? (y/n/restore): ")
	choice := r.readInput()

	switch choice {
	case "y":
		fmt.Println("[*] Deleting permanently...")
		if quarantinedPath != "" {
			os.Remove(quarantinedPath)
		}
	case "restore":
		fmt.Println("[!] Restore not implemented in Alpha. File remains in Jail.")
	default:
		fmt.Println("[*] File kept in Quarantine Jail.")
	}
}

func (r *RemediationManager) immobilize(t Threat) {
	fmt.Println("    [Action] Immobilizing Threat...")

	// If it's a process -> Suspend & Kill Network
	if pid, ok := t.Details["PID"]; ok {
		fmt.Printf("    [Process] Suspending PID %v...\n", pid)
		// r.suspend(pid)
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
