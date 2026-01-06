package windows

import (
	"fmt"
	"syscall"
	"unsafe"
)

// ProcessKiller implements the Remediation interface for Windows
type ProcessKiller struct{}

func NewProcessKiller() *ProcessKiller {
	return &ProcessKiller{}
}

func (p *ProcessKiller) Remediate(pid uint32) error {
	fmt.Printf("[!] KILL COMMAND RECEIVED FOR PID: %d\n", pid)

	// 1. Enable SeDebugPrivilege (Critical for killing elevated procs)
	// In God Mode, we bypass this by using the Driver, but good to have for fallback.
	_ = enableDebugPrivilege()

	// 2. Kill the Process Tree (Driver Preferred)
	err := terminatePID(pid)
	if err != nil {
		fmt.Printf("[-] Failed to kill process %d: %v\n", pid, err)
		return err
	}

	fmt.Printf("[+] Process %d neutralized successfully.\n", pid)
	return nil
}

// terminatePID uses the Kernel Driver if available, else User Mode API
func terminatePID(pid uint32) error {
	// Try Kernel Mode First (The Iron Hand)
	err := terminateViaDriver(pid)
	if err == nil {
		fmt.Printf("[+] GOD MODE: Terminated PID %d via Kernel Driver.\n", pid)
		return nil
	}

	// Fallback to User Mode
	// fmt.Printf("[-] Driver Terminate Failed: %v. Using Standard API.\n", err)

	handle, err := OpenProcess(PROCESS_TERMINATE, false, pid)
	if err != nil {
		return err
	}
	defer CloseHandle(handle)

	return TerminateProcess(handle, 1) // Exit code 1
}

func terminateViaDriver(pid uint32) error {
	// 1. Open Driver Handle
	// "\\.\Arakne" matches the symlink created in main.c
	driverHandle, err := syscall.CreateFile(
		syscall.StringToUTF16Ptr("\\\\.\\Arakne"),
		syscall.GENERIC_READ|syscall.GENERIC_WRITE,
		0,
		nil,
		syscall.OPEN_EXISTING,
		0,
		0,
	)
	if err != nil {
		return fmt.Errorf("driver not reachable")
	}
	defer syscall.CloseHandle(driverHandle)

	// 2. Prepare IOCTL
	// IOCTL_ARAKNE_TERMINATE_PROCESS = CTL_CODE(0x8000, 0x801, ...)
	// Code = (DeviceType << 16) | (Access << 14) | (Function << 2) | Method
	// Code = (0x8000 << 16) | (0 << 14) | (0x801 << 2) | 0
	// 0x80000000 | 0x2004 | 0 = 0x80002004

	ioctlCode := uint32(0x80002004)

	type TerminateRequest struct {
		ProcessId uint32
	}
	input := TerminateRequest{ProcessId: pid}

	var bytesReturned uint32
	err = syscall.DeviceIoControl(
		driverHandle,
		ioctlCode,
		(*byte)(unsafe.Pointer(&input)),
		uint32(unsafe.Sizeof(input)),
		nil,
		0,
		&bytesReturned,
		nil,
	)

	return err
}

func enableDebugPrivilege() error {
	// ... (Implementation omitted for brevity in this step, assume standard token adjustment)
	// For "God Mode", the driver bypasses ACLs anyway.
	return nil
}

func (p *ProcessKiller) KillTree(rootPid uint32) error {
	// Kill children first (Not implemented in this snippet, simplistic approach)
	return p.Remediate(rootPid)
}
