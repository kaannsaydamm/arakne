package windows

import (
	"fmt"
	"path/filepath"
	"os"
)

// DriverLoader manages the installation and loading of Kernel Drivers
type DriverLoader struct {
	ServiceName string
	DisplayName string
	DriverPath  string
}

func NewDriverLoader(driverName string) *DriverLoader {
	cwd, _ := os.Getwd()
	return &DriverLoader{
		ServiceName: "ArakneDriver",
		DisplayName: "Arakne Kernel Driver",
		DriverPath:  filepath.Join(cwd, driverName),
	}
}

func (d *DriverLoader) Load() error {
	fmt.Printf("[*] Checking for driver file: %s\n", d.DriverPath)
	if _, err := os.Stat(d.DriverPath); os.IsNotExist(err) {
		return fmt.Errorf("driver file not found")
	}

	fmt.Println("[*] Driver file found. Connecting to Service Control Manager...")
	
	scm, err := OpenSCManager(nil, nil, SC_MANAGER_CREATE_SERVICE | SC_MANAGER_CONNECT)
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
		// Check if already running (Error 1056 - ERROR_SERVICE_ALREADY_RUNNING)
		// Simpler check: just log error but don't fail hard if it's "running"
		return fmt.Errorf("failed to start service (Code %v). It might be already running or blocked by DSE", err)
	}

	fmt.Println("[+] Driver Loaded Successfully! Kernel access obtained.")
	return nil
}
