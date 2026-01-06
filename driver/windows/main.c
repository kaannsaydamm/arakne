#include <ntddk.h>
#include <wdf.h>
#include "ioctl.h"

#define DRIVER_TAG 'krnA'

// Global state for features
BOOLEAN g_NukeMode = FALSE;
ULONG g_ProtectedPID = 0;
extern BOOLEAN g_NetworkIsolate; // From wfp.c

// Function Prototypes
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD ArakneEvtDeviceAdd;
EVT_WDF_OBJECT_CONTEXT_CLEANUP ArakneEvtDriverContextCleanup;

// Forward Declaration for WFP and Callbacks
NTSTATUS RegisterWFPCallouts(WDFDEVICE Device);
NTSTATUS RegisterProcessCallbacks(void);
VOID UnregisterProcessCallbacks(void);

// Helper: Terminate process by PID
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
        KdPrint(("Arakne: ZwOpenProcess failed for PID %d: 0x%x\n", ProcessId, status));
        return status;
    }
    
    status = ZwTerminateProcess(hProcess, 0);
    ZwClose(hProcess);
    
    if (NT_SUCCESS(status)) {
        KdPrint(("Arakne: Successfully terminated PID %d\n", ProcessId));
    } else {
        KdPrint(("Arakne: ZwTerminateProcess failed: 0x%x\n", status));
    }
    
    return status;
}

// IOCTL Dispatch Routine
NTSTATUS ArakneDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);
    
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG controlCode = stack->Parameters.DeviceIoControl.IoControlCode;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG bytesIO = 0;

    switch (controlCode) {
        case IOCTL_ARAKNE_PING:
            KdPrint(("Arakne: PONG! Driver is alive.\n"));
            break;

        case IOCTL_ARAKNE_TERMINATE_PROCESS:
            {
                if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(ARAKNE_TERMINATE_REQUEST)) {
                    status = STATUS_BUFFER_TOO_SMALL;
                    break;
                }
                
                PARAKNE_TERMINATE_REQUEST input = (PARAKNE_TERMINATE_REQUEST)Irp->AssociatedIrp.SystemBuffer;
                if (input && input->ProcessId != 0) {
                    KdPrint(("Arakne: Request to KILL PID %d\n", input->ProcessId));
                    status = TerminateProcessByPid(input->ProcessId);
                }
            }
            break;

        case IOCTL_ARAKNE_NUKE_MODE:
             KdPrint(("Arakne: NUKE MODE TOGGLED\n"));
             g_NukeMode = !g_NukeMode;
             break;

        case IOCTL_ARAKNE_SELF_DEFENSE:
            {
                 if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(ARAKNE_SELF_DEFENSE_REQUEST)) {
                    status = STATUS_BUFFER_TOO_SMALL;
                    break;
                }
                PARAKNE_SELF_DEFENSE_REQUEST input = (PARAKNE_SELF_DEFENSE_REQUEST)Irp->AssociatedIrp.SystemBuffer;
                if (input) {
                    g_ProtectedPID = input->ProtectedPID;
                    KdPrint(("Arakne: Self-Defense Active for PID %d\n", g_ProtectedPID));
                }
            }
            break;

        case IOCTL_ARAKNE_NETWORK_ISOLATE:
            {
                if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(ARAKNE_NETWORK_REQUEST)) {
                    status = STATUS_BUFFER_TOO_SMALL;
                    break;
                }
                PARAKNE_NETWORK_REQUEST input = (PARAKNE_NETWORK_REQUEST)Irp->AssociatedIrp.SystemBuffer;
                if (input) {
                    g_NetworkIsolate = input->Isolate;
                    KdPrint(("Arakne: Network Isolation = %s\n", g_NetworkIsolate ? "ON" : "OFF"));
                }
            }
            break;

        case IOCTL_ARAKNE_ETW_SUBSCRIBE:
            KdPrint(("Arakne: ETW Subscription requested (handled in user-mode)\n"));
            // ETW is better handled in user-mode via TraceLogging
            // This IOCTL is reserved for future kernel-mode ETW integration
            break;

        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesIO;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}


NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status;
    WDF_DRIVER_CONFIG config;

    KdPrint(("Arakne: DriverEntry - Starting God Mode Kernel Module\n"));

    WDF_DRIVER_CONFIG_INIT(&config, ArakneEvtDeviceAdd);
    config.EvtDriverContextCleanup = ArakneEvtDriverContextCleanup;

    status = WdfDriverCreate(DriverObject,
                             RegistryPath,
                             WDF_NO_OBJECT_ATTRIBUTES,
                             &config,
                             WDF_NO_HANDLE
                             );

    if (!NT_SUCCESS(status)) {
        KdPrint(("Arakne: Error: WdfDriverCreate failed 0x%x\n", status));
        return status;
    }
    
    // Register IOCTL Dispatch
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ArakneDeviceControl;
    
    // Register Process Callbacks (Execution Monitoring)
    status = RegisterProcessCallbacks();
    if (!NT_SUCCESS(status)) {
         KdPrint(("Arakne: Warning: Failed to register Process Callbacks\n"));
    }
    
    KdPrint(("Arakne: Driver loaded successfully.\n"));
    return status;
}

NTSTATUS
ArakneEvtDeviceAdd(
    _In_    WDFDRIVER       Driver,
    _Inout_ PWDFDEVICE_INIT DeviceInit
    )
{
    NTSTATUS status;
    WDFDEVICE device;
    
    UNREFERENCED_PARAMETER(Driver);

    KdPrint(("Arakne: EvtDeviceAdd\n"));

    // We must create a device object to receive IOCTLs
    status = WdfDeviceCreate(&DeviceInit, WDF_NO_OBJECT_ATTRIBUTES, &device);
    if (!NT_SUCCESS(status)) {
        KdPrint(("Arakne: WdfDeviceCreate failed 0x%x\n", status));
        return status;
    }
    
    // Create Symbolic Link so User Mode can CreateFile("\\\\.\\Arakne")
    DECLARE_CONST_UNICODE_STRING(symbolicLinkName, L"\\DosDevices\\Arakne");
    status = WdfDeviceCreateSymbolicLink(device, &symbolicLinkName);
    if (!NT_SUCCESS(status)) {
        KdPrint(("Arakne: Failed to create symbolic link status 0x%x\n", status));
        return status;
    }

    // Initialize WFP Callouts (Network Killswitch)
    status = RegisterWFPCallouts(device);
    if (!NT_SUCCESS(status)) {
        KdPrint(("Arakne: WFP Registration failed (non-fatal): 0x%x\n", status));
        // Continue anyway - WFP is optional
    }

    return STATUS_SUCCESS;
}

VOID
ArakneEvtDriverContextCleanup(
    _In_ WDFOBJECT DriverObject
    )
{
    UNREFERENCED_PARAMETER(DriverObject);
    KdPrint(("Arakne: Context Cleanup - Unloading Driver\n"));
    
    UnregisterProcessCallbacks();
}
