// Arakne WDM Kernel Driver - Pure WDM (No KMDF)
// Copyright (c) 2026 Kaan Saydam

#include <ntddk.h>
#include <ntstrsafe.h>
#include "ioctl.h"

#define DRIVER_TAG 'krnA'
#define DEVICE_NAME L"\\Device\\Arakne"
#define SYMLINK_NAME L"\\DosDevices\\Arakne"

// Process access rights
#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE           0x0001
#endif

// Global state
BOOLEAN g_NukeMode = FALSE;
ULONG g_ProtectedPID = 0;
PDEVICE_OBJECT g_DeviceObject = NULL;

// Forward declarations
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;
_Dispatch_type_(IRP_MJ_CREATE) DRIVER_DISPATCH DispatchCreate;
_Dispatch_type_(IRP_MJ_CLOSE) DRIVER_DISPATCH DispatchClose;
_Dispatch_type_(IRP_MJ_DEVICE_CONTROL) DRIVER_DISPATCH DispatchDeviceControl;

// External functions from callbacks.c and wfp.c
NTSTATUS RegisterProcessCallbacks(void);
VOID UnregisterProcessCallbacks(void);
VOID UnregisterWFPCallouts(void);
NTSTATUS RegisterWFPCallouts(PDEVICE_OBJECT DeviceObject);

// Terminate process by PID
NTSTATUS TerminateProcessByPid(ULONG ProcessId)
{
    NTSTATUS status;
    HANDLE hProcess = NULL;
    OBJECT_ATTRIBUTES objAttr;
    CLIENT_ID clientId;
    
    clientId.UniqueProcess = (HANDLE)(ULONG_PTR)ProcessId;
    clientId.UniqueThread = NULL;
    
    InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    
    status = ZwOpenProcess(&hProcess, PROCESS_TERMINATE, &objAttr, &clientId);
    if (!NT_SUCCESS(status)) {
        KdPrint(("Arakne: ZwOpenProcess failed: 0x%x\n", status));
        return status;
    }
    
    status = ZwTerminateProcess(hProcess, 0);
    ZwClose(hProcess);
    
    return status;
}

// Create/Close dispatch
NTSTATUS DispatchCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS DispatchClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// IOCTL dispatch
NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;
    ULONG bytesIO = 0;
    
    ULONG ioctl = irpSp->Parameters.DeviceIoControl.IoControlCode;
    PVOID buffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG inLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
    
    switch (ioctl) {
    case IOCTL_ARAKNE_TERMINATE_PROCESS:
        if (buffer && inLen >= sizeof(ULONG)) {
            ULONG pid = *(PULONG)buffer;
            status = TerminateProcessByPid(pid);
            KdPrint(("Arakne: Kill PID %d = 0x%x\n", pid, status));
        }
        break;
        
    /* Nuke Mode Removed - Logic moved to User Mode Auto-Remediation
    case IOCTL_ARAKNE_NUKE_MODE:
        g_NukeMode = !g_NukeMode;
        KdPrint(("Arakne: Nuke Mode = %s\n", g_NukeMode ? "ON" : "OFF"));
        break;
    */
        
    case IOCTL_ARAKNE_SELF_DEFENSE:
        if (buffer && inLen >= sizeof(ULONG)) {
            g_ProtectedPID = *(PULONG)buffer;
            KdPrint(("Arakne: Protected PID = %d\n", g_ProtectedPID));
        }
        break;
        
    case IOCTL_ARAKNE_NETWORK_ISOLATE:
    {
        // Input: ULONG Action (0=OFF, 1=ON, 2=QUERY)
        // Output: ULONG CurrentState
        ULONG action = 2; // Default to query
        BOOLEAN checkState;

        // Verify Output Buffer
        if (!buffer || outLen < sizeof(ULONG)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        // Read Input Action
        if (inLen >= sizeof(ULONG)) {
            action = *(PULONG)buffer;
        }

        if (action == 1) {
            WFP_SetKillswitch(TRUE);
        } else if (action == 0) {
            WFP_SetKillswitch(FALSE);
        }

        // Return current state
        checkState = WFP_GetKillswitchState();
        *(PULONG)buffer = checkState ? 1 : 0;
        bytesIO = sizeof(ULONG);
        
        status = STATUS_SUCCESS;
        break;
    }
        
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }
    
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesIO;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

// Driver unload
VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symLink;
    
    KdPrint(("Arakne: Unloading...\n"));
    
    // Unregister WFP
    UnregisterWFPCallouts();

    // Unregister callbacks
    UnregisterProcessCallbacks();
    
    // Delete symbolic link
    RtlInitUnicodeString(&symLink, SYMLINK_NAME);
    IoDeleteSymbolicLink(&symLink);
    
    // Delete device
    if (g_DeviceObject) {
        IoDeleteDevice(g_DeviceObject);
    }
    
    KdPrint(("Arakne: Unloaded successfully.\n"));
}

// Driver entry
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    
    NTSTATUS status;
    UNICODE_STRING deviceName;
    UNICODE_STRING symLink;
    
    KdPrint(("Arakne: DriverEntry - Kernel Module Loading (v1.1 Auto-Remediate)...\n"));
    
    // Create device
    RtlInitUnicodeString(&deviceName, DEVICE_NAME);
    status = IoCreateDevice(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &g_DeviceObject
    );
    
    if (!NT_SUCCESS(status)) {
        KdPrint(("Arakne: IoCreateDevice failed: 0x%x\n", status));
        return status;
    }
    
    // Create symbolic link
    RtlInitUnicodeString(&symLink, SYMLINK_NAME);
    status = IoCreateSymbolicLink(&symLink, &deviceName);
    if (!NT_SUCCESS(status)) {
        KdPrint(("Arakne: IoCreateSymbolicLink failed: 0x%x\n", status));
        IoDeleteDevice(g_DeviceObject);
        return status;
    }
    
    // Set dispatch routines
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;
    DriverObject->DriverUnload = DriverUnload;
    
    // Register process callbacks
    status = RegisterProcessCallbacks();
    if (!NT_SUCCESS(status)) {
        KdPrint(("Arakne: RegisterProcessCallbacks failed (non-fatal): 0x%x\n", status));
    }
    
    // Register WFP Callouts (Network Killswitch)
    status = RegisterWFPCallouts(g_DeviceObject);
    if (!NT_SUCCESS(status)) {
         KdPrint(("Arakne: RegisterWFPCallouts failed: 0x%x\n", status));
         // Proceeding without WFP is risky if user relies on it, but we don't want to crash.
    }
    
    KdPrint(("Arakne: Driver loaded successfully! Ready for Auto-Remediation.\n"));
    return STATUS_SUCCESS;
}
