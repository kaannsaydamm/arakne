package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"arakne/internal/core"
	"arakne/internal/intelligence"
	"arakne/internal/platform/darwin"
	"arakne/internal/platform/linux"
	"arakne/internal/platform/windows"
	"arakne/internal/stages"
	"arakne/internal/utils"
)

var scanner = bufio.NewScanner(os.Stdin)

var remediator *core.RemediationManager

func main() {
	// Global Panic Handler to prevent instant crash
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("\n[!!!] CRITICAL ERROR (PANIC) [!!!]")
			fmt.Printf("Error: %v\n", r)
			fmt.Println("Stack Trace:")
			debug.PrintStack()
			fmt.Println("\nPress Enter to exit...")
			bufio.NewReader(os.Stdin).ReadString('\n')
		}
	}()

	banner := `
    ___               __            
   ╱   │  _________ _╱ ╱______  ___ 
  ╱ ╱│ │ ╱ ___╱ __ ╱ ╱╱_╱ __ ╲╱ _ ╲
 ╱ ___ │╱ ╱  ╱ ╱_╱ ╱ ,< ╱ ╱ ╱ ╱  __╱
╱_╱  │_╱_╱   ╲__,_╱_╱│_╱_╱ ╱_╱╲___╱ 
                                    
  :: Arakne v1.1.0 :: By Kaan Saydam, 2026.
  [+] Running with ELEVATED privileges. Full power unlocked.
`
	// Check Admin
	if !utils.IsAdmin() {
		fmt.Println("[-] Error: Arakne requires Administrator privileges.")
		fmt.Println("    Right-click -> Run as Administrator")
		time.Sleep(5 * time.Second)
		os.Exit(1)
	}
	// CLI Flags
	nuke := flag.Bool("nuke", false, "Aggressive Nuke Mode (No questions)")
	help := flag.Bool("help", false, "Show usage")
	flag.Parse()

	if *help {
		fmt.Print(banner)
		flag.PrintDefaults()
		return
	}

	remediator = core.NewRemediationManager(*nuke)

	clearScreen()
	fmt.Print(banner)

	// 1. Initial Admin Check
	checkAdminPrivileges()

	// 2. Initial Dependency/Driver Check
	fmt.Println("[*] System initializing...")
	// Ensure "C:\Arakne" and subdirs exist
	if err := core.EnsureDirectories(); err != nil {
		fmt.Printf("[!] Fatal: Failed to initialize directories: %v\n", err)
		fmt.Println("    Please run as Administrator.")
		os.Exit(1)
	}

	// Startup Menu (Avoids Loop)
	for {
		clearScreen()
		fmt.Print(banner)
		fmt.Println("\n:: STARTUP OPTIONS ::")
		fmt.Println("1. Launch Arakne System (Auto-Load Driver)")
		fmt.Println("2. Install/Repair Kernel Driver")
		fmt.Println("3. Exit")
		fmt.Print("\nSelect Option [1-3]: ")

		choice := readInput()
		if choice == "1" {
			checkAndLoadDrivers(runtime.GOOS)
			break
		} else if choice == "2" {
			installDriver()
		} else if choice == "3" {
			fmt.Println("Exiting...")
			os.Exit(0)
		}
	}

	// Initialize Intelligence Database (Hash Cache)
	fmt.Println("[*] Loading Intelligence Database...")
	intelligence.InitHashDatabase()

	// Inject Signature Verification Callback (Dependency Injection)
	if runtime.GOOS == "windows" {
		intelligence.VerifySignatureCallback = func(filePath string) (bool, string, error) {
			// Adapter: IsExecutableTrusted (platform) -> VerifySignatureCallback (intelligence)
			isTrusted, reason := windows.IsExecutableTrusted(filePath)
			// We only count it as "Signed & Good" if it is TRUSTED (verified vendor)
			return isTrusted, reason, nil
		}
	}

	time.Sleep(1 * time.Second)

	// 3. Enable Self-Defense (Protect our own process)
	if runtime.GOOS == "windows" {
		err := EnableSelfDefense()
		if err != nil {
			fmt.Println("[!] Self-Defense could not be enabled (driver may not be loaded)")
		}
	}

	// 4. Main Loop
	for {
		clearScreen()
		fmt.Print(banner)
		fmt.Println("\nSelect Operation Mode:")
		fmt.Println("1. Windows Module (Heavy Artillery)")
		fmt.Println("2. Linux Module (The Hunter)")
		fmt.Println("3. macOS Module (The Gatekeeper)")
		fmt.Println("4. Exit")
		fmt.Print("\nSelect [1-4]: ")

		choice := readInput()

		switch choice {
		case "1":
			handleOSMenu("windows")
		case "2":
			handleOSMenu("linux")
		case "3":
			handleOSMenu("darwin")
		case "4":
			fmt.Println("Exiting Arakne...")
			os.Exit(0)
		default:
			fmt.Println("Invalid selection.")
			time.Sleep(1 * time.Second)
		}
	}
}

func handleOSMenu(osType string) {
	if osType != runtime.GOOS {
		fmt.Printf("\n[!] WARNING: You selected %s but are running on %s.\n", osType, runtime.GOOS)
		fmt.Println("    This mode is only valid for analyzing MOUNTED external drives or offline images.")
		fmt.Print("    Continue? (y/n): ")
		if readInput() != "y" {
			return
		}
	}

	for {
		clearScreen()
		fmt.Printf(":: Arakne > %s Mode ::\n\n", strings.Title(osType))
		fmt.Println("=== PRIMARY OPERATIONS ===")
		fmt.Println("1. ** SURGICAL SCAN (ComboFix Mode) **")
		fmt.Println("   [Automated: Restore Point -> Temp Clean -> Full Scan -> Remediation]")
		fmt.Println("")
		fmt.Println("=== UTILITIES ===")
		fmt.Println("2. Toolbox (Manual Tools)")
		fmt.Println("3. Back to Main Menu")
		fmt.Print("\nSelect Option [1-3]: ")

		choice := readInput()

		switch choice {
		case "1":
			// Surgical Mode
			stages.RunSurgicalScan()
			waitForKey()
		case "2":
			runToolbox(osType)
		case "3":
			return
		default:
			fmt.Println("Invalid selection.")
			time.Sleep(1 * time.Second)
		}
	}
}

func runToolbox(osType string) {
	for {
		clearScreen()
		fmt.Printf(":: Arakne > %s > Toolbox ::\n\n", strings.Title(osType))
		fmt.Println("1. Quick Scan (Lightweight)")
		fmt.Println("2. Process Killer (Kernel Mode)")
		fmt.Println("3. Quarantine Manager")
		fmt.Println("4. Whitelist Manager")
		fmt.Println("5. Network Killswitch (Toggle)")
		fmt.Println("6. Evidence Bag Utils")
		fmt.Println("7. Manual Hash Check")
		fmt.Println("8. Back")
		fmt.Print("\nSelect Option [1-8]: ")

		choice := readInput()

		switch choice {
		case "1":
			runTask(osType, "Quick Scan", false)
		case "2":
			runProcessKiller()
		case "3":
			runQuarantine()
		case "4":
			runWhitelistManager()
		case "5":
			runNetworkKillswitch()
		case "6":
			// Submenu for evidence? Or just view/seal
			fmt.Println("\n[1] View Bag  [2] Seal Bag")
			sub := readInput()
			switch sub {
			case "1":
				viewEvidenceBag()
			case "2":
				sealEvidenceBag()
			}
		case "7":
			runHashCheckTool()
		case "8":
			return
		default:
			fmt.Println("Invalid selection.")
			time.Sleep(500 * time.Millisecond)
		}
		if choice != "8" {
			waitForKey()
		}
	}
}

func runTask(osType, taskName string, requireElevated bool) {
	fmt.Printf("\n[*] Preparing to run: %s (%s)...\n", taskName, osType)

	if requireElevated && !utils.IsAdmin() {
		fmt.Println("[!] ERROR: This task requires Administrator/Root privileges.")
		fmt.Println("    Please restart Arakne with elevated permissions.")
		waitForKey()
		return
	}

	fmt.Println("[+] Initializing Kernel Driver...")
	time.Sleep(500 * time.Millisecond)

	fmt.Print("[?] Ready to start used defined operation. Proceed? (y/n): ")
	if readInput() != "y" {
		fmt.Println("[-] Aborted.")
		time.Sleep(1 * time.Second)
		return
	}

	fmt.Println("[+] Executing...")

	// Initialize Remediation Manager
	// Initialize Remediation Manager (Auto Mode aka ComboFix Style)
	remediationMgr := core.NewRemediationManager(true)
	// Connect Online Intelligence
	if intelligence.GlobalDB != nil {
		remediationMgr.Verifier = intelligence.GlobalDB.LookupHashOnline
	}

	if osType == "windows" && taskName == "YARA Scan" {
		fmt.Println("\n[*] Running YARA Scan...")
		yaraScanner := windows.NewYARAScanner("./rules")
		yThreats, _ := yaraScanner.Run()
		for _, t := range yThreats {
			remediationMgr.HandleThreat(t)
		}
		fmt.Printf("\n[+] YARA Scan Complete. Threats found: %d\n", len(yThreats))

	} else if osType == "windows" && taskName == "Quick Scan" {
		// Quick Scan: Lightweight modules
		fmt.Println("\n[*] Running Quick Scan (Browser, Logs, Drivers)...")

		// Browser Forensics
		browserScanner := windows.NewBrowserScanner()
		bThreats, _ := browserScanner.Run()
		for _, t := range bThreats {
			remediationMgr.HandleThreat(t)
		}

		// Forensics (Event Logs, USN, Prefetch)
		forensicsScanner := windows.NewForensicsScanner()
		fThreats, _ := forensicsScanner.Run()
		for _, t := range fThreats {
			remediationMgr.HandleThreat(t)
		}

		// LOLDrivers
		driverScanner := windows.NewLOLDriverScanner()
		dThreats, _ := driverScanner.Run()
		for _, t := range dThreats {
			remediationMgr.HandleThreat(t)
		}

		// ETW Sniffer
		etwScanner := windows.NewETWSniffer()
		eThreats, _ := etwScanner.Run()
		for _, t := range eThreats {
			remediationMgr.HandleThreat(t)
		}

		fmt.Printf("\n[+] Quick Scan Complete. Total threats found: %d\n",
			len(bThreats)+len(fThreats)+len(dThreats)+len(eThreats))

	} else if osType == "windows" && taskName == "Deep Dive" {
		scanner := windows.NewMFTScanner("C:")
		threats, err := scanner.Run()
		if err != nil {
			fmt.Printf("[-] MFT Scan Failed: %v\n", err)
		} else {
			fmt.Printf("[+] MFT Scan Complete. Found %d threats.\n", len(threats))
			for _, t := range threats {
				remediationMgr.HandleThreat(t)
			}
		}

		// Offline Registry Analysis
		fmt.Println("\n[*] Starting Registry Persistence Analysis...")
		regParser, _ := windows.NewRegistryParser(nil)
		regParser.Walk()

		// Guardian Modules
		fmt.Println("\n[*] Engaging Guardian Modules (Advanced Protection)...")

		driverScanner := windows.NewLOLDriverScanner()
		dThreats, _ := driverScanner.Run()
		for _, t := range dThreats {
			remediationMgr.HandleThreat(t)
		}

		memScanner := windows.MemoryScanner{}
		mThreats, _ := memScanner.Run()
		for _, t := range mThreats {
			remediationMgr.HandleThreat(t)
		}

		uefiScanner := windows.NewUEFIScanner()
		uThreats, _ := uefiScanner.Run()
		for _, t := range uThreats {
			remediationMgr.HandleThreat(t)
		}

		// ShimCache
		shimParser := windows.ShimCacheParser{}
		shimParser.Run()

	} else if osType == "linux" {
		scanner := linux.NewLinuxHunter()
		threats, err := scanner.Run()
		if err != nil {
			fmt.Printf("[-] Linux Scan Failed: %v\n", err)
		} else {
			fmt.Printf("[+] Linux Scan Complete. Found %d threats.\n", len(threats))
		}

		// Doomsday Module: Memfd Hunter
		memfdScanner := linux.NewMemfdHunter()
		threats2, _ := memfdScanner.Run()
		// Merge results
		for _, t := range threats2 {
			remediator.HandleThreat(t)
		}

	} else if osType == "darwin" {
		scanner := darwin.NewTCCScanner()
		threats, err := scanner.Run()
		if err != nil {
			fmt.Printf("[-] macOS Scan Failed: %v\n", err)
		} else {
			fmt.Printf("[+] macOS Scan Complete. Found %d threats.\n", len(threats))
		}
	} else {
		// Unknown OS/Task combination
		fmt.Printf("[!] No handler for %s on %s\n", taskName, osType)
	}

	fmt.Println("[+] Task completed successfully.")
	waitForKey()
}

func checkAdminPrivileges() {
	if utils.IsAdmin() {
		fmt.Println("[+] Running with ELEVATED privileges. Full power unlocked.")
	} else {
		fmt.Println("[!] RUNNING AS STANDARD USER.")
		fmt.Println("[!] Deep forensics (MFT, Kernel, Raw Disk) will be UNAVAILABLE.")
		fmt.Println("[*] Press Enter to continue as restricted user (or Ctrl+C to exit)...")
		scanner.Scan()
	}
}

func checkAndLoadDrivers(osName string) {
	driverName := "None"
	switch osName {
	case "windows":
		driverName = "arakne_wfp.sys"
		fmt.Printf("[*] Auto-Loading Driver: %s\n", driverName)

		loader := windows.NewDriverLoader(driverName)
		err := loader.Load()
		if err == nil {
			fmt.Println("[+] Driver Communication Established. Kernel Mode ACTIVE.")
			return
		}

		fmt.Printf("[-] Driver Load Failed: %v\n", err)
		fmt.Println("    [!] Running in User Mode (Limited Capabilities).")
		return

	case "linux":
		driverName = "arakne_probe.ko"
	case "darwin":
		driverName = "arakne_kext"
	}

	fmt.Printf("[*] Checking for user mode simulation: %s...\n", driverName)
}

func installDriver() {
	if runtime.GOOS != "windows" {
		fmt.Println("[-] Installer is Windows only.")
		waitForKey()
		return
	}

	fmt.Println("[*] Launching Driver Installer (PowerShell)...")
	installScript := "driver\\windows\\install.ps1"

	// Execute PowerShell with UI visible so user can see progress/errors
	cmd := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", installScript)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		fmt.Printf("[!] Installation Failed: %v\n", err)
		fmt.Println("    [NOTE] You can run 'driver\\windows\\install.ps1' manually.")
	} else {
		fmt.Println("\n[+] Installer finished successfully.")
	}
	waitForKey()
}

func readInput() string {
	scanner.Scan()
	return strings.TrimSpace(strings.ToLower(scanner.Text()))
}

func waitForKey() {
	fmt.Println("\nPress Enter to continue...")
	scanner.Scan()
}

func clearScreen() {
	if runtime.GOOS == "windows" {
		fmt.Println("\033[H\033[2J")
	} else {
		fmt.Println("\033[H\033[2J")
	}
}
