package main

import (
	"arakne/internal/core"
	"arakne/internal/intelligence"
	"arakne/internal/platform/windows"
	"fmt"
	"net"
	"os"
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
func sendIOCTL(code uint32, input unsafe.Pointer, inputSize uint32, output unsafe.Pointer, outputSize uint32) error {
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
		(*byte)(output), outputSize,
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

	err := sendIOCTL(IOCTL_ARAKNE_SELF_DEFENSE, unsafe.Pointer(&req), uint32(unsafe.Sizeof(req)), nil, 0)
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

	// 1. Check current driver state
	var currentState uint32
	queryAction := uint32(2) // 2 = Query

	err := sendIOCTL(IOCTL_ARAKNE_NETWORK_ISOLATE,
		unsafe.Pointer(&queryAction), 4,
		unsafe.Pointer(&currentState), 4)

	if err != nil {
		fmt.Printf("[-] Failed to query driver: %v\n", err)
		fmt.Println("    [NOTE] Driver may not be loaded.")
		waitForKey()
		return
	}

	// 2. Check actual connectivity
	conn, _ := net.DialTimeout("tcp", "8.8.8.8:53", 2*time.Second)
	isConnected := (conn != nil)
	if conn != nil {
		conn.Close()
	}

	// 3. Logic
	if currentState == 1 {
		fmt.Println("\n[!] STATUS: KILLSWITCH ACTIVE (Network BLOCKED via Driver)")
		fmt.Println("\n[?] Do you want to RESTORE network access?")
		fmt.Println("    This will unblock outbound connections.")
		fmt.Print("    Restore? (y/n): ")

		if readInput() == "y" {
			action := uint32(0) // OFF
			sendIOCTL(IOCTL_ARAKNE_NETWORK_ISOLATE, unsafe.Pointer(&action), 4, unsafe.Pointer(&currentState), 4)
			if currentState == 0 {
				fmt.Println("\n[+] Network Restored! Killswitch DISENGAGED.")
			} else {
				fmt.Println("\n[-] Failed to disable killswitch.")
			}
		}
	} else {
		// Driver is OFF
		fmt.Println("\n[+] STATUS: Killswitch DISENGAGED (Driver Allowing Traffic)")

		if isConnected {
			fmt.Println("    Connection: ONLINE (Google DNS reachable)")
			fmt.Println("\n[!] Do you want to ACTIVATE the Killswitch?")
			fmt.Println("    This will BLOCK ALL outbound traffic immediately.")
			fmt.Print("    Activate? (y/n): ")

			if readInput() == "y" {
				action := uint32(1) // ON
				sendIOCTL(IOCTL_ARAKNE_NETWORK_ISOLATE, unsafe.Pointer(&action), 4, unsafe.Pointer(&currentState), 4)
				if currentState == 1 {
					fmt.Println("\n[+] KILLSWITCH ACTIVATED! Network Severed.")
				} else {
					fmt.Println("\n[-] Failed to activate killswitch.")
				}
			}
		} else {
			fmt.Println("    Connection: OFFLINE (No route to Google DNS)")
			fmt.Println("\n[i] It seems your network is already down/unplugged.")
			fmt.Println("    You can still activate the driver lock to be sure.")
			fmt.Print("    Activate lock? (y/n): ")

			if readInput() == "y" {
				action := uint32(1) // ON
				sendIOCTL(IOCTL_ARAKNE_NETWORK_ISOLATE, unsafe.Pointer(&action), 4, unsafe.Pointer(&currentState), 4)
				if currentState == 1 {
					fmt.Println("\n[+] KILLSWITCH ACTIVATED! Lock engaged.")
				}
			}
		}
	}

	waitForKey()
}

// runNukeMode removed (merged into standard scan)

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

// runCombofixMode implements the nostalgic all-in-one scan mode
// Runs all analysis steps automatically, only prompts for deletion
func runCombofixMode(_ string) {
	clearScreen()

	// Combofix ASCII banner
	combofixBanner := `
   ██████╗ ██████╗ ███╗   ███╗██████╗  ██████╗ ███████╗██╗██╗  ██╗
  ██╔════╝██╔═══██╗████╗ ████║██╔══██╗██╔═══██╗██╔════╝██║╚██╗██╔╝
  ██║     ██║   ██║██╔████╔██║██████╔╝██║   ██║█████╗  ██║ ╚███╔╝ 
  ██║     ██║   ██║██║╚██╔╝██║██╔══██╗██║   ██║██╔══╝  ██║ ██╔██╗ 
  ╚██████╗╚██████╔╝██║ ╚═╝ ██║██████╔╝╚██████╔╝██║     ██║██╔╝ ██╗
   ╚═════╝ ╚═════╝ ╚═╝     ╚═╝╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝
                    [ N O S T A L G I A   M O D E ]
`
	fmt.Println(combofixBanner)
	fmt.Println("┌─────────────────────────────────────────────────────────────┐")
	fmt.Println("│  This will run ALL analysis modules automatically.         │")
	fmt.Println("│  Sit back and watch. Deletion prompts will appear at end.  │")
	fmt.Println("└─────────────────────────────────────────────────────────────┘")
	fmt.Println()
	fmt.Print("[?] Press ENTER to begin full system analysis...")
	readInput()

	allThreats := []core.Threat{}
	startTime := time.Now()

	// Stage 1: Browser Forensics
	fmt.Println("\n" + strings.Repeat("═", 60))
	fmt.Println("STAGE 1/8: BROWSER FORENSICS")
	fmt.Println(strings.Repeat("═", 60))
	time.Sleep(500 * time.Millisecond)
	browserScanner := windows.NewBrowserScanner()
	threats, _ := browserScanner.Run()
	allThreats = append(allThreats, threats...)

	// Stage 2: Registry Persistence
	fmt.Println("\n" + strings.Repeat("═", 60))
	fmt.Println("STAGE 2/8: REGISTRY PERSISTENCE ANALYSIS")
	fmt.Println(strings.Repeat("═", 60))
	time.Sleep(500 * time.Millisecond)
	regParser, _ := windows.NewRegistryParser(nil)
	regParser.Walk()
	allThreats = append(allThreats, regParser.Threats...)

	// Stage 3: YARA Scan
	fmt.Println("\n" + strings.Repeat("═", 60))
	fmt.Println("STAGE 3/8: YARA MALWARE SCAN")
	fmt.Println(strings.Repeat("═", 60))
	time.Sleep(500 * time.Millisecond)
	yaraScanner := windows.NewYARAScanner("")
	threats, _ = yaraScanner.Run()
	allThreats = append(allThreats, threats...)

	// Stage 4: ETW Log Analysis
	fmt.Println("\n" + strings.Repeat("═", 60))
	fmt.Println("STAGE 4/8: ETW/EVENT LOG ANALYSIS")
	fmt.Println(strings.Repeat("═", 60))
	time.Sleep(500 * time.Millisecond)
	etwScanner := windows.NewETWSniffer()
	threats, _ = etwScanner.Run()
	allThreats = append(allThreats, threats...)

	// Stage 5: Memory Scan
	fmt.Println("\n" + strings.Repeat("═", 60))
	fmt.Println("STAGE 5/8: MEMORY SCAN (RWX Regions)")
	fmt.Println(strings.Repeat("═", 60))
	time.Sleep(500 * time.Millisecond)
	memScanner := windows.NewForensicsScanner()
	threats, _ = memScanner.Run()
	allThreats = append(allThreats, threats...)

	// Stage 6: UEFI/Boot Check
	fmt.Println("\n" + strings.Repeat("═", 60))
	fmt.Println("STAGE 6/8: UEFI/SECURE BOOT CHECK")
	fmt.Println(strings.Repeat("═", 60))
	time.Sleep(500 * time.Millisecond)
	uefiScanner := windows.NewUEFIScanner()
	threats, _ = uefiScanner.Run()
	allThreats = append(allThreats, threats...)

	// Stage 7: LOLDrivers
	fmt.Println("\n" + strings.Repeat("═", 60))
	fmt.Println("STAGE 7/8: VULNERABLE DRIVER SCAN")
	fmt.Println(strings.Repeat("═", 60))
	time.Sleep(500 * time.Millisecond)
	lolScanner := windows.NewLOLDriverScanner()
	threats, _ = lolScanner.Run()
	allThreats = append(allThreats, threats...)

	// Stage 8: Shimcache
	fmt.Println("\n" + strings.Repeat("═", 60))
	fmt.Println("STAGE 8/8: SHIMCACHE EXECUTION HISTORY")
	fmt.Println(strings.Repeat("═", 60))
	time.Sleep(500 * time.Millisecond)
	shimScanner := windows.NewShimCacheParser()
	threats, _ = shimScanner.Run()
	allThreats = append(allThreats, threats...)

	// Analysis Complete
	elapsed := time.Since(startTime)

	fmt.Println("\n" + strings.Repeat("█", 60))
	fmt.Println("                    ANALYSIS COMPLETE")
	fmt.Println(strings.Repeat("█", 60))
	fmt.Printf("\n[+] Time elapsed: %v\n", elapsed.Round(time.Second))
	fmt.Printf("[+] Total threats found: %d\n\n", len(allThreats))

	if len(allThreats) == 0 {
		fmt.Println("┌─────────────────────────────────────────────────────────────┐")
		fmt.Println("│                 ✓ NO THREATS DETECTED                       │")
		fmt.Println("│              Your system appears to be clean!               │")
		fmt.Println("└─────────────────────────────────────────────────────────────┘")
		waitForKey()
		return
	}

	// Display all threats
	fmt.Println("┌─────────────────────────────────────────────────────────────┐")
	fmt.Println("│                    THREAT SUMMARY                           │")
	fmt.Println("└─────────────────────────────────────────────────────────────┘")
	fmt.Println()

	for i, threat := range allThreats {
		levelStr := "INFO"
		switch threat.Level {
		case core.LevelCritical:
			levelStr = "CRITICAL"
		case core.LevelHigh:
			levelStr = "HIGH"
		case core.LevelMedium:
			levelStr = "MEDIUM"
		case core.LevelMalicious:
			levelStr = "MALICIOUS"
		}

		fmt.Printf("[%d] [%s] %s\n", i+1, levelStr, threat.Name)
		fmt.Printf("    Description: %s\n", threat.Description)
		if threat.FilePath != "" {
			fmt.Printf("    Path: %s\n", threat.FilePath)
		}
		fmt.Println()
	}

	// Auto-Remediate All Threats found in ComboFix Mode
	if len(allThreats) > 0 {
		fmt.Println("\n[*] Initiating ComboFix Auto-Clean...")
		remediator := core.NewRemediationManager(true) // Aggressive
		for _, t := range allThreats {
			remediator.HandleThreat(t)
		}
	}

	fmt.Println("\n[+] Combofix Mode complete!")
	waitForKey()
}

// runScanner executes the selected scanner modules with AUTO-REMEDIATION (Standard Scanner Wrapper)
func runScanner(scannerName string, scanner func() []core.Threat) {
	fmt.Printf("\n[*] Starting %s...\n", scannerName)

	// ComboFix Style: Always Aggressive/Automatic
	remediator := core.NewRemediationManager(true)

	threats := scanner()

	if len(threats) == 0 {
		fmt.Printf("[+] %s: System Clean. No threats found.\n", scannerName)
	} else {
		for _, t := range threats {
			remediator.HandleThreat(t)
		}
	}
	waitForKey()
}

func runHashCheckTool() {
	clearScreen()
	fmt.Println("=== HASH CHECK TOOL (TIERED VERIFICATION) ===")
	fmt.Println("Check a File or Hash against:")
	fmt.Println("1. Local Whitelist (Fast)")
	fmt.Println("2. Digital Signature (Cert)")
	fmt.Println("3. MalwareBazaar (Known Bad)")
	fmt.Println("4. Circl.lu (Known Good)")
	fmt.Println()
	fmt.Print("Enter File Path or SHA256 Hash: ")

	input := readInput()
	if input == "" {
		return
	}

	// Check if file
	isFile := false
	if _, err := os.Stat(input); err == nil {
		isFile = true
	}

	hash := input
	if isFile {
		h, err := intelligence.CalculateFileSHA256(input)
		if err != nil {
			fmt.Printf("[-] Error hashing file: %v\n", err)
			waitForKey()
			return
		}
		hash = h
		fmt.Printf("\n[+] File Hash (SHA256): %s\n", hash)
	} else {
		// Validation for manual hash input
		hash = strings.TrimSpace(hash)
		if len(hash) != 64 {
			// Not a SHA256. Could be MD5 (32)?
			// Our DB assumes SHA256 keys.
			// Warn user.
			fmt.Println("\n[-] Invalid Hash Format.")
			fmt.Println("    Please provide a valid SHA256 (64 characters) or a File Path.")
			if len(hash) == 32 {
				fmt.Println("    [i] MD5 detected, but this tool currently requires SHA256.")
			}
			waitForKey()
			return
		}
	}

	// 1. Local Whitelist
	fmt.Println("\n[1] Checking Local Whitelist/Blacklist...")
	if intelligence.GlobalDB != nil {
		if isGood, desc := intelligence.GlobalDB.IsKnownGood(hash); isGood {
			fmt.Printf("   [+] CLEAN: Found in Local Whitelist (%s)\n", desc)
			waitForKey()
			return
		}
		// Also check local known bad (which is MB cache)
		if isBad, name := intelligence.GlobalDB.IsKnownBad(hash); isBad {
			fmt.Printf("   [!] MALICIOUS: %s (Local Cache)\n", name)
			waitForKey()
			return
		}
	}
	fmt.Println("   [-] Not in local database.")

	// 2. Certificate Check (If File)
	if isFile {
		fmt.Println("\n[2] Checking Digital Signature...")
		isTrusted, _ := windows.IsExecutableTrusted(input)
		if isTrusted {
			fmt.Println("   [+] CLEAN: File is Digitally Signed & Trusted.")
			fmt.Println("   [i] Trusting signature. Skipping cloud checks.")
			waitForKey()
			return
		} else {
			fmt.Println("   [-] Invalid or Missing Signature.")
		}
	} else {
		fmt.Println("\n[2] Checking Digital Signature... [SKIPPED: Not a file]")
	}

	// 3 & 4. Cloud Checks (MalwareBazaar & Circl)
	fmt.Println("\n[3] Checking MalwareBazaar (Known Bad)...")
	fmt.Println("[4] Checking Circl.lu (Known Good)...")

	verdict := intelligence.Global.VerifyHash(hash)

	if verdict.IsKnownBad {
		fmt.Printf("\n   [!] MALICIOUS: %s (%s)\n", verdict.MalwareName, verdict.Source)
		waitForKey()
		return
	}

	if verdict.IsKnownGood {
		fmt.Printf("\n   [+] CLEAN: %s\n", verdict.Source)
		waitForKey()
		return
	}

	fmt.Println("\n[?] VERDICT: UNKNOWN / SUSPICIOUS")
	fmt.Println("    Hash not found in any database and has no trusted signature.")
	waitForKey()
}
