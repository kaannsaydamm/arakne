package main

import (
	"arakne/internal/core"
	"arakne/internal/platform/windows"
	"fmt"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// IOCTL Codes (must match driver/windows/ioctl.h)
const (
	FILE_DEVICE_ARAKNE = 0x00008000

	// CTL_CODE calculation: (DeviceType << 16) | (Access << 14) | (Function << 2) | Method
	IOCTL_ARAKNE_PING              = (FILE_DEVICE_ARAKNE << 16) | (0 << 14) | (0x800 << 2) // 0x80002000
	IOCTL_ARAKNE_TERMINATE_PROCESS = (FILE_DEVICE_ARAKNE << 16) | (0 << 14) | (0x801 << 2) // 0x80002004
	IOCTL_ARAKNE_NETWORK_ISOLATE   = (FILE_DEVICE_ARAKNE << 16) | (0 << 14) | (0x802 << 2) // 0x80002008
	IOCTL_ARAKNE_NUKE_MODE         = (FILE_DEVICE_ARAKNE << 16) | (0 << 14) | (0x803 << 2) // 0x8000200C
	IOCTL_ARAKNE_SELF_DEFENSE      = (FILE_DEVICE_ARAKNE << 16) | (0 << 14) | (0x804 << 2) // 0x80002010
)

// Helper to send IOCTL to driver
func sendIOCTL(code uint32, input unsafe.Pointer, inputSize uint32) error {
	handle, err := syscall.CreateFile(
		syscall.StringToUTF16Ptr("\\\\.\\Arakne"),
		syscall.GENERIC_READ|syscall.GENERIC_WRITE,
		0, nil, syscall.OPEN_EXISTING, 0, 0,
	)
	if err != nil {
		return fmt.Errorf("driver not loaded: %v", err)
	}
	defer syscall.CloseHandle(handle)

	var bytesReturned uint32
	err = syscall.DeviceIoControl(
		handle, code,
		(*byte)(input), inputSize,
		nil, 0,
		&bytesReturned, nil,
	)
	return err
}

// EnableSelfDefense registers our PID with the driver for protection
func EnableSelfDefense() error {
	type SelfDefenseRequest struct {
		ProtectionLevel uint32
		ProtectedPID    uint32
	}

	pid := uint32(syscall.Getpid())
	req := SelfDefenseRequest{ProtectionLevel: 1, ProtectedPID: pid}

	err := sendIOCTL(IOCTL_ARAKNE_SELF_DEFENSE, unsafe.Pointer(&req), uint32(unsafe.Sizeof(req)))
	if err != nil {
		return err
	}
	fmt.Printf("[+] Self-Defense enabled for PID %d\n", pid)
	return nil
}

func runProcessKiller() {
	clearScreen()
	fmt.Println("=== PROCESS KILLER (Kernel Mode) ===")
	fmt.Print("Enter PID to terminate: ")
	var pid uint32
	fmt.Scan(&pid)

	if pid == 0 {
		fmt.Println("[-] Invalid PID.")
		waitForKey()
		return
	}

	// Check whitelist
	wl := core.NewWhitelistManager()
	procs, _ := windows.GetProcessList()
	for _, p := range procs {
		if p.PID == pid && wl.IsCritical(p.Name) {
			fmt.Printf("[-] BLOCKED: %s is a protected system process!\n", p.Name)
			waitForKey()
			return
		}
	}

	fmt.Printf("[*] Attempting to kill PID %d via Kernel Driver...\n", pid)

	killer := windows.NewProcessKiller()
	err := killer.Remediate(pid)
	if err != nil {
		fmt.Printf("[-] Termination failed: %v\n", err)
	} else {
		fmt.Println("[+] Process terminated successfully.")
	}
	waitForKey()
}

func runQuarantine() {
	clearScreen()
	fmt.Println("=== QUARANTINE FILE ===")
	fmt.Print("Enter file path to quarantine: ")
	scanner.Scan()
	path := strings.TrimSpace(scanner.Text())

	if path == "" {
		fmt.Println("[-] No path provided.")
		waitForKey()
		return
	}

	jail := core.NewQuarantineJail("")
	err := jail.Lockup(path)
	if err != nil {
		fmt.Printf("[-] Quarantine failed: %v\n", err)
	} else {
		fmt.Printf("[+] File locked in quarantine: %s\n", path)
	}
	waitForKey()
}

func runWhitelistManager() {
	clearScreen()
	fmt.Println("=== WHITELIST MANAGEMENT ===")

	wl := core.NewWhitelistManager()
	fmt.Println("Protected Processes:")
	for proc := range wl.CriticalProcs {
		fmt.Printf("  - %s\n", proc)
	}

	fmt.Println("\n[*] Whitelist is hardcoded for safety.")
	fmt.Println("    To modify, edit internal/core/whitelist.go")
	waitForKey()
}

func runNetworkKillswitch() {
	clearScreen()
	fmt.Println("=== NETWORK KILLSWITCH (WFP) ===")
	fmt.Println("[!] WARNING: This will block ALL network traffic system-wide.")
	fmt.Print("Activate killswitch? (y/n): ")

	if readInput() != "y" {
		return
	}

	type NetworkRequest struct {
		Isolate uint32 // BOOLEAN in C is typically 1 byte, but we align to 4
	}
	req := NetworkRequest{Isolate: 1}

	fmt.Println("[*] Sending IOCTL to Kernel Driver...")
	err := sendIOCTL(IOCTL_ARAKNE_NETWORK_ISOLATE, unsafe.Pointer(&req), uint32(unsafe.Sizeof(req)))
	if err != nil {
		fmt.Printf("[-] Failed: %v\n", err)
		fmt.Println("    [NOTE] Driver may not be loaded. Run as admin with driver installed.")
	} else {
		fmt.Println("[+] Network Killswitch ACTIVATED!")
		fmt.Println("[!] All outbound connections are now BLOCKED.")
		fmt.Println("    Run again with 'n' or restart to disable.")
	}
	waitForKey()
}

func runNukeMode() {
	clearScreen()
	fmt.Println("=== NUKE MODE ===")
	fmt.Println("[!] DANGER: This enables aggressive blocking of ALL non-whitelisted processes.")
	fmt.Print("Toggle Nuke Mode? (y/n): ")

	if readInput() != "y" {
		return
	}

	fmt.Println("[*] Sending IOCTL to Kernel Driver...")
	err := sendIOCTL(IOCTL_ARAKNE_NUKE_MODE, nil, 0)
	if err != nil {
		fmt.Printf("[-] Failed: %v\n", err)
	} else {
		fmt.Println("[+] Nuke Mode TOGGLED!")
	}
	waitForKey()
}

func viewEvidenceBag() {
	clearScreen()
	fmt.Println("=== EVIDENCE BAG ===")
	fmt.Println("[*] Evidence is stored in: ./evidence/")
	fmt.Println("    Each case has a timestamped directory.")
	fmt.Println("\n[*] Use 'Seal Evidence' to create a forensic ZIP.")
	waitForKey()
}

func sealEvidenceBag() {
	clearScreen()
	fmt.Println("=== SEAL EVIDENCE ===")

	bag := core.NewBagHandler(fmt.Sprintf("CASE_%s", time.Now().Format("20060102_150405")))
	zipPath, err := bag.Seal()
	if err != nil {
		fmt.Printf("[-] Failed to seal evidence: %v\n", err)
	} else {
		fmt.Printf("[+] Evidence sealed: %s\n", zipPath)
	}
	waitForKey()
}

func generateReport() {
	clearScreen()
	fmt.Println("=== GENERATE REPORT ===")

	caseID := fmt.Sprintf("CASE_%s", time.Now().Format("20060102_150405"))
	err := core.GenerateReport(caseID, []core.Threat{})
	if err != nil {
		fmt.Printf("[-] Report generation failed: %v\n", err)
	} else {
		fmt.Printf("[+] Report generated: report_%s.json & .html\n", caseID)
	}
	waitForKey()
}
