package windows

import (
	"arakne/internal/core"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DriverLoader manages the installation and loading of Kernel Drivers
type DriverLoader struct {
	ServiceName string
	DisplayName string
	DriverPath  string
}

func NewDriverLoader(driverName string) *DriverLoader {
	// Check multiple possible locations for the driver
	possiblePaths := []string{
		filepath.Join(core.DriversDir, driverName),     // C:\Arakne\Drivers\file.sys (Standard)
		filepath.Join(core.BaseDir, driverName),        // C:\Arakne\file.sys (Legacy)
		"C:\\Arakne\\" + driverName,                    // Legacy Hardcoded
		filepath.Join("driver", "windows", driverName), // Source tree
	}

	// Add CWD-based path
	cwd, _ := os.Getwd()
	possiblePaths = append(possiblePaths, filepath.Join(cwd, driverName))
	possiblePaths = append(possiblePaths, filepath.Join(cwd, "driver", "windows", driverName))

	// Find first existing driver
	var driverPath string
	for _, p := range possiblePaths {
		if _, err := os.Stat(p); err == nil {
			driverPath = p
			break
		}
	}

	// Default to standard location if nothing found
	if driverPath == "" {
		driverPath = filepath.Join(core.DriversDir, driverName)
	}

	return &DriverLoader{
		ServiceName: "arakne",
		DisplayName: "Arakne Kernel Driver",
		DriverPath:  driverPath,
	}
}

func (d *DriverLoader) Load() error {
	fmt.Printf("[*] Checking for driver file: %s\n", d.DriverPath)
	if _, err := os.Stat(d.DriverPath); os.IsNotExist(err) {
		return fmt.Errorf("driver file not found")
	}

	fmt.Println("[*] Driver file found. Connecting to Service Control Manager...")

	scm, err := OpenSCManager(nil, nil, SC_MANAGER_CREATE_SERVICE|SC_MANAGER_CONNECT)
	if err != nil {
		return fmt.Errorf("failed to open SCM: %v", err)
	}
	defer CloseServiceHandle(scm)

	// Try to open existing service first
	fmt.Println("[*] Checking if service exists...")
	service, err := OpenService(scm, d.ServiceName, SERVICE_ALL_ACCESS)
	if err == nil {
		fmt.Println("[*] Service exists. Attempting to start...")
	} else {
		// Create Service
		fmt.Println("[*] Service not found. Creating new Kernel Service...")
		service, err = CreateService(scm, d.ServiceName, d.DisplayName, d.DriverPath)
		if err != nil {
			return fmt.Errorf("failed to create service: %v", err)
		}
		fmt.Println("[+] Service created successfully.")
	}
	defer CloseServiceHandle(service)

	// Start Service
	err = StartService(service)
	if err != nil {
		errStr := err.Error()
		// Check if already running (Error 1056 - ERROR_SERVICE_ALREADY_RUNNING)
		// Turkish: "halen çalışıyor" or English: "already running"
		if strings.Contains(errStr, "1056") || strings.Contains(errStr, "already running") ||
			strings.Contains(errStr, "halen") || strings.Contains(errStr, "çalışıyor") {
			fmt.Println("[+] Driver already running. Kernel Mode ACTIVE.")
			return nil
		}
		return fmt.Errorf("failed to start service (Code %v). It might be blocked by DSE or signing issue", err)
	}

	fmt.Println("[+] Driver Loaded Successfully! Kernel access obtained.")
	return nil
}
