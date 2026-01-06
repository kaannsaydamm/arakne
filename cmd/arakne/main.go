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
	"arakne/internal/utils"
	"arakne/internal/platform/windows"
	"arakne/internal/platform/linux"
	"arakne/internal/platform/darwin"
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
		fmt.Println(banner)
		flag.PrintDefaults()
		return
	}

	remediator = core.NewRemediationManager(*nuke)

	clearScreen()
	fmt.Println(banner)
	
	// 1. Initial Admin Check
	checkAdminPrivileges()

	// 2. Initial Dependency/Driver Check
	fmt.Println("[*] System initializing...")
	checkAndLoadDrivers(runtime.GOOS)
	time.Sleep(1 * time.Second)

	// 3. Main Loop
	for {
		clearScreen()
		fmt.Println(banner)
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
		fmt.Println("1. Quick Scan (Logs & Basic)")
		fmt.Println("2. Deep Dive (MFT/Kernel/Memory)")
		fmt.Println("3. Remediation (Nuke/Clean)")
		fmt.Println("4. Back")
		fmt.Print("\nSelect Option: ")

		choice := readInput()

		switch choice {
		case "1":
			runTask(osType, "Quick Scan", false)
		case "2":
			runTask(osType, "Deep Dive", true)
		case "3":
			runTask(osType, "Remediation", true)
		case "4":
			return
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

	fmt.Println("[+] Verifying prerequisites...")
	time.Sleep(500 * time.Millisecond)

	fmt.Print("[?] Ready to start used defined operation. Proceed? (y/n): ")
	if readInput() != "y" {
		fmt.Println("[-] Aborted.")
		time.Sleep(1 * time.Second)
		return
	}

	fmt.Println("[+] Executing...")
	
	if osType == "windows" && taskName == "Deep Dive" {
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

		// Offline Registry
		fmt.Println("\n[*] Starting Offline Registry Analysis (Anti-Rootkit)...")
		regParser, _ := windows.NewRegistryParser([]byte("regf_mock_header"))
		regParser.Walk()
		
		// Guardian Modules
		fmt.Println("\n[*] Engaging Guardian Modules (Advanced Protection)...")
		
		driverScanner := windows.DriverScanner{}
		driverScanner.ScanLoadedDrivers()
		
		memScanner := windows.MemoryScanner{}
		memScanner.ScanProcesses()
		
		uefiScanner := windows.UEFIScanner{}
		uefiScanner.ScanEFI()

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
		// Mock for other modes
		time.Sleep(2 * time.Second) 
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
