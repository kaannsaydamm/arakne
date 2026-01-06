#include <ntddk.h>
#include <wdf.h>

#define DRIVER_TAG 'krnA'

// Function Prototypes
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD ArakneEvtDeviceAdd;
EVT_WDF_OBJECT_CONTEXT_CLEANUP ArakneEvtDriverContextCleanup;

// Forward Declaration for WFP and Callbacks
// NTSTATUS RegisterWFPCallouts(WDFDEVICE Device);
// NTSTATUS RegisterProcessCallbacks(void);

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
    
    // Register Process Callbacks (Execution Monitoring)
    // status = RegisterProcessCallbacks();
    
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

    status = WdfDeviceCreate(&DeviceInit, WDF_NO_OBJECT_ATTRIBUTES, &device);
    if (!NT_SUCCESS(status)) {
        KdPrint(("Arakne: WdfDeviceCreate failed 0x%x\n", status));
        return status;
    }
    
    // Initialize WFP Callouts here
    // RegisterWFPCallouts(device);

    return status;
}

VOID
ArakneEvtDriverContextCleanup(
    _In_ WDFOBJECT DriverObject
    )
{
    UNREFERENCED_PARAMETER(DriverObject);
    KdPrint(("Arakne: Context Cleanup - Unloading Driver\n"));
    
    // Unregister Callbacks
    // PsSetCreateProcessNotifyRoutine(ProcessCallback, TRUE);
}
