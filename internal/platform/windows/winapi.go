package windows

import (
	"syscall"
	"unsafe"
)

var (
	modkernel32          = syscall.NewLazyDLL("kernel32.dll")
	procCreateFileW      = modkernel32.NewProc("CreateFileW")
	procReadFile         = modkernel32.NewProc("ReadFile")
	procCloseHandle      = modkernel32.NewProc("CloseHandle")
	procSetFilePointerEx = modkernel32.NewProc("SetFilePointerEx")
)

const (
	GENERIC_READ          = 0x80000000
	GENERIC_WRITE         = 0x40000000
	FILE_SHARE_READ       = 0x00000001
	FILE_SHARE_WRITE      = 0x00000002
	OPEN_EXISTING         = 3
	FILE_ATTRIBUTE_NORMAL = 0x00000080
	INVALID_HANDLE_VALUE  = ^uintptr(0)
)

// OpenRawVolume opens a handle to a volume or physical drive
func OpenRawVolume(path string) (syscall.Handle, error) {
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}

	handle, _, err := procCreateFileW.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		GENERIC_READ,
		FILE_SHARE_READ|FILE_SHARE_WRITE,
		0,
		OPEN_EXISTING,
		0, // No attributes for raw device
		0,
	)

	if handle == INVALID_HANDLE_VALUE {
		return 0, err
	}

	return syscall.Handle(handle), nil
}

// ReadRawBytes reads bytes from the handle
func ReadRawBytes(handle syscall.Handle, buffer []byte) (uint32, error) {
	var bytesRead uint32
	ret, _, err := procReadFile.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)),
		uintptr(unsafe.Pointer(&bytesRead)),
		0,
	)

	if ret == 0 {
		return 0, err
	}

	return bytesRead, nil
}

// CloseHandle closes the file handle
func CloseHandle(handle syscall.Handle) error {
	return syscall.CloseHandle(handle)
}

// SetFilePointer moves the read position
func SetFilePointer(handle syscall.Handle, offset int64, moveMethod uint32) (int64, error) {
	var newOffset int64
	ret, _, err := procSetFilePointerEx.Call(
		uintptr(handle),
		uintptr(offset),
		uintptr(unsafe.Pointer(&newOffset)),
		uintptr(moveMethod),
	)

	if ret == 0 {
		return 0, err
	}

	return newOffset, nil
}

// Process API Definitions
var (
	procCreateToolhelp32Snapshot = modkernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32First           = modkernel32.NewProc("Process32FirstW")
	procProcess32Next            = modkernel32.NewProc("Process32NextW")
	procOpenProcess              = modkernel32.NewProc("OpenProcess")
	procTerminateProcess         = modkernel32.NewProc("TerminateProcess")
)

const (
	TH32CS_SNAPPROCESS        = 0x00000002
	PROCESS_TERMINATE         = 0x0001
	PROCESS_QUERY_INFORMATION = 0x0400
)

type PROCESSENTRY32 struct {
	Size              uint32
	CntUsage          uint32
	ProcessID         uint32
	DefaultHeapID     uintptr
	ModuleID          uint32
	CntThreads        uint32
	ParentProcessID   uint32
	PriorityClassBase int32
	Flags             uint32
	ExeFile           [260]uint16
}

type ProcessInfo struct {
	PID  uint32
	Name string
}

// GetProcessList is a helper to return all active PIDs
func GetProcessList() ([]ProcessInfo, error) {
	snapshot, _, err := procCreateToolhelp32Snapshot.Call(uintptr(TH32CS_SNAPPROCESS), 0)
	if snapshot == INVALID_HANDLE_VALUE || snapshot == 0 {
		return nil, err
	}
	defer syscall.CloseHandle(syscall.Handle(snapshot))

	var pe PROCESSENTRY32
	pe.Size = uint32(unsafe.Sizeof(pe))

	ret, _, _ := procProcess32First.Call(snapshot, uintptr(unsafe.Pointer(&pe)))
	if ret == 0 {
		return nil, nil // No processes?
	}

	var procs []ProcessInfo
	for {
		name := syscall.UTF16ToString(pe.ExeFile[:])
		procs = append(procs, ProcessInfo{PID: pe.ProcessID, Name: name})

		ret, _, _ = procProcess32Next.Call(snapshot, uintptr(unsafe.Pointer(&pe)))
		if ret == 0 {
			break
		}
	}
	return procs, nil
}

func OpenProcess(desiredAccess uint32, inheritHandle bool, pid uint32) (syscall.Handle, error) {
	inherit := 0
	if inheritHandle {
		inherit = 1
	}
	ret, _, err := procOpenProcess.Call(uintptr(desiredAccess), uintptr(inherit), uintptr(pid))
	if ret == 0 {
		return 0, err
	}
	return syscall.Handle(ret), nil
}

func TerminateProcess(handle syscall.Handle, exitCode uint32) error {
	ret, _, err := procTerminateProcess.Call(uintptr(handle), uintptr(exitCode))
	if ret == 0 {
		return err
	}
	return nil
}

// --- Service Control Manager API ---

var (
	modadvapi32            = syscall.NewLazyDLL("advapi32.dll")
	procOpenSCManager      = modadvapi32.NewProc("OpenSCManagerW")
	procCreateService      = modadvapi32.NewProc("CreateServiceW")
	procOpenService        = modadvapi32.NewProc("OpenServiceW")
	procStartService       = modadvapi32.NewProc("StartServiceW")
	procCloseServiceHandle = modadvapi32.NewProc("CloseServiceHandle")
)

const (
	SC_MANAGER_CREATE_SERVICE = 0x0002
	SC_MANAGER_CONNECT        = 0x0001

	SERVICE_KERNEL_DRIVER = 0x00000001
	SERVICE_DEMAND_START  = 0x00000003
	SERVICE_ERROR_NORMAL  = 0x00000001

	SERVICE_START      = 0x0010
	SERVICE_ALL_ACCESS = 0xF01FF
)

func OpenSCManager(machineName *uint16, dbName *uint16, access uint32) (syscall.Handle, error) {
	ret, _, err := procOpenSCManager.Call(
		uintptr(unsafe.Pointer(machineName)),
		uintptr(unsafe.Pointer(dbName)),
		uintptr(access),
	)
	if ret == 0 {
		return 0, err
	}
	return syscall.Handle(ret), nil
}

func CreateService(scm syscall.Handle, serviceName, displayName, binaryPath string) (syscall.Handle, error) {
	sName, _ := syscall.UTF16PtrFromString(serviceName)
	dName, _ := syscall.UTF16PtrFromString(displayName)
	bPath, _ := syscall.UTF16PtrFromString(binaryPath)

	ret, _, err := procCreateService.Call(
		uintptr(scm),
		uintptr(unsafe.Pointer(sName)),
		uintptr(unsafe.Pointer(dName)),
		uintptr(SERVICE_ALL_ACCESS),
		uintptr(SERVICE_KERNEL_DRIVER),
		uintptr(SERVICE_DEMAND_START),
		uintptr(SERVICE_ERROR_NORMAL),
		uintptr(unsafe.Pointer(bPath)),
		0, 0, 0, 0, 0,
	)
	if ret == 0 {
		return 0, err
	}
	return syscall.Handle(ret), nil
}

func OpenService(scm syscall.Handle, serviceName string, access uint32) (syscall.Handle, error) {
	sName, _ := syscall.UTF16PtrFromString(serviceName)
	ret, _, err := procOpenService.Call(
		uintptr(scm),
		uintptr(unsafe.Pointer(sName)),
		uintptr(access),
	)
	if ret == 0 {
		return 0, err
	}
	return syscall.Handle(ret), nil
}

func StartService(service syscall.Handle) error {
	ret, _, err := procStartService.Call(
		uintptr(service),
		0,
		0,
	)
	if ret == 0 {
		return err
	}
	return nil
}

func CloseServiceHandle(handle syscall.Handle) error {
	ret, _, err := procCloseServiceHandle.Call(uintptr(handle))
	if ret == 0 {
		return err
	}
	return nil
}

// --- Memory Management API ---

var (
	procVirtualQueryEx    = modkernel32.NewProc("VirtualQueryEx")
	procReadProcessMemory = modkernel32.NewProc("ReadProcessMemory")
)

const (
	MEM_COMMIT  = 0x1000
	MEM_RESERVE = 0x2000
	MEM_PRIVATE = 0x20000
	MEM_IMAGE   = 0x1000000
	MEM_MAPPED  = 0x40000

	PAGE_NOACCESS          = 0x01
	PAGE_READONLY          = 0x02
	PAGE_READWRITE         = 0x04
	PAGE_WRITECOPY         = 0x08
	PAGE_EXECUTE           = 0x10
	PAGE_EXECUTE_READ      = 0x20
	PAGE_EXECUTE_READWRITE = 0x40 // RWX (Danger!)
	PAGE_EXECUTE_WRITECOPY = 0x80
)

type MEMORY_BASIC_INFORMATION struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	PartitionId       uint16
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
}

func VirtualQueryEx(hProcess syscall.Handle, lpAddress uintptr) (MEMORY_BASIC_INFORMATION, error) {
	var mbi MEMORY_BASIC_INFORMATION
	ret, _, err := procVirtualQueryEx.Call(
		uintptr(hProcess),
		lpAddress,
		uintptr(unsafe.Pointer(&mbi)),
		uintptr(unsafe.Sizeof(mbi)),
	)
	if ret == 0 {
		return mbi, err
	}
	return mbi, nil
}

func ReadProcessMemory(hProcess syscall.Handle, lpBaseAddress uintptr, size uintptr) ([]byte, error) {
	buf := make([]byte, size)
	var bytesRead uintptr
	ret, _, err := procReadProcessMemory.Call(
		uintptr(hProcess),
		lpBaseAddress,
		uintptr(unsafe.Pointer(&buf[0])),
		size,
		uintptr(unsafe.Pointer(&bytesRead)),
	)
	if ret == 0 {
		return nil, err
	}
	return buf, nil
}
