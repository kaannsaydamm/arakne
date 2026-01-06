package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"arakne/internal/core"
	"arakne/internal/platform/darwin"
	"arakne/internal/platform/linux"
	"arakne/internal/platform/windows"
	"arakne/internal/utils"
)

const banner = `
    ___               __            
   ╱   │  _________ _╱ ╱______  ___ 
  ╱ ╱│ │ ╱ ___╱ __ ╱ ╱╱_╱ __ ╲╱ _ ╲
 ╱ ___ │╱ ╱  ╱ ╱_╱ ╱ ,< ╱ ╱ ╱ ╱  __╱
╱_╱  │_╱_╱   ╲__,_╱_╱│_╱_╱ ╱_╱╲___╱ 
                                    
  :: Arakne v1.0.0 :: By Kaan Saydam, 2026.
`

var scanner = bufio.NewScanner(os.Stdin)

var remediator *core.RemediationManager

func main() {
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
	checkAndLoadDrivers(runtime.GOOS)
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
		fmt.Println("=== SCANNING ===")
		fmt.Println("1. Quick Scan (Browser/Logs/Drivers)")
		fmt.Println("2. Deep Dive (MFT/Memory/UEFI)")
		fmt.Println("3. YARA Scan")
		fmt.Println("4. COMBOFIX MODE (Nostalgia) ★")
		fmt.Println("\n=== REMEDIATION ===")
		fmt.Println("5. Kill Process (Kernel Mode)")
		fmt.Println("6. Quarantine File")
		fmt.Println("\n=== CONFIGURATION ===")
		fmt.Println("7. Whitelist Management")
		fmt.Println("8. Network Killswitch (WFP)")
		fmt.Println("\n=== EVIDENCE & REPORTING ===")
		fmt.Println("9. View Evidence Bag")
		fmt.Println("10. Seal Evidence (ZIP)")
		fmt.Println("11. Generate Report (JSON/HTML)")
		fmt.Println("\n=== DANGER ZONE ===")
		fmt.Println("12. NUKE MODE (Toggle)")
		fmt.Println("\n13. Back to Main Menu")
		fmt.Print("\nSelect Option [1-13]: ")

		choice := readInput()

		switch choice {
		case "1":
			runTask(osType, "Quick Scan", false)
		case "2":
			runTask(osType, "Deep Dive", true)
		case "3":
			runTask(osType, "YARA Scan", false)
		case "4":
			runCombofixMode(osType)
		case "5":
			runProcessKiller()
		case "6":
			runQuarantine()
		case "7":
			runWhitelistManager()
		case "8":
			runNetworkKillswitch()
		case "9":
			viewEvidenceBag()
		case "10":
			sealEvidenceBag()
		case "11":
			generateReport()
		case "12":
			runNukeMode()
		case "13":
			return
		default:
			fmt.Println("Invalid selection.")
			time.Sleep(1 * time.Second)
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

	fmt.Println("[+] Initializing God Mode Kernel Driver...")
	time.Sleep(500 * time.Millisecond)

	fmt.Print("[?] Ready to start used defined operation. Proceed? (y/n): ")
	if readInput() != "y" {
		fmt.Println("[-] Aborted.")
		time.Sleep(1 * time.Second)
		return
	}

	fmt.Println("[+] Executing...")

	// Initialize Remediation Manager
	remediationMgr := core.NewRemediationManager(false)

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
				remediator.HandleThreat(t)
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
		if err != nil {
			fmt.Printf("[-] Driver Load Failed: %v\n", err)
			fmt.Println("    [NOTE] To enable Kernel Mode, place 'arakne_wfp.sys' in this directory.")
			fmt.Println("           If you don't have it, Arakne will run in User Mode (Standard).")
		} else {
			fmt.Println("[+] Driver Communication Established.")
		}
		return

	case "linux":
		driverName = "arakne_probe.ko"
	case "darwin":
		driverName = "arakne_kext"
	}

	fmt.Printf("[*] Checking for specific kernel driver: %s...\n", driverName)
	fmt.Println("[-] Driver not loaded (Simulation for non-Windows).")
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
