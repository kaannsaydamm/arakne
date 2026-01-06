#include <ntddk.h>
#include <wdf.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include <initguid.h>
#include "ioctl.h"

// -------------------------------------------------------------------------
// WFP Network Killswitch
// -------------------------------------------------------------------------

// GUID for our callout. Using a dummy GUID for example.
// Real usage requires uuidgen.
DEFINE_GUID(GUID_ARAKNE_CALLOUT_V4, 
    0xde39486a, 0xaa27, 0x4879, 0xb8, 0x5a, 0x22, 0xd0, 0x5d, 0x42, 0x47, 0x11);

// Global Switch
BOOLEAN g_NetworkIsolate = FALSE;

// Engine Handle
HANDLE g_EngineHandle = NULL;
UINT32 g_CalloutId = 0;

// Callout Routine: ClassifyFn
void ArakneClassifyFn(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER1* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut
    )
{
    UNREFERENCED_PARAMETER(inFixedValues);
    UNREFERENCED_PARAMETER(inMetaValues);
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    // Default: Permit
    
    if (g_NetworkIsolate) {
        // KILL SWITCH ENGAGED
        classifyOut->actionType = FWP_ACTION_BLOCK;
        classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE; // Prevent others from permitting
        // KdPrint(("Arakne: [NET] Valid Packet BLOCKED due to Lockdown.\n"));
    } else {
        classifyOut->actionType = FWP_ACTION_PERMIT;
    }
}

NTSTATUS NotifyFn(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID* filterKey,
    _Inout_ const FWPS_FILTER1* filter
    )
{
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

VOID FlowDeleteFn(
    _In_ UINT16 layerId,
    _In_ UINT32 calloutId,
    _In_ UINT64 flowContext
    )
{
    UNREFERENCED_PARAMETER(layerId);
    UNREFERENCED_PARAMETER(calloutId);
    UNREFERENCED_PARAMETER(flowContext);
}

NTSTATUS RegisterWFPCallouts(WDFDEVICE Device)
{
    NTSTATUS status;
    FWPS_CALLOUT0 callout = {0};
    FWPM_CALLOUT0 mCallout = {0};
    FWPM_FILTER0 filter = {0};
    FWPM_SESSION0 session = {0};

    UNREFERENCED_PARAMETER(Device);
    
    // 1. Open Engine
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &g_EngineHandle);
    if (!NT_SUCCESS(status)) {
        KdPrint(("Arakne: FwpmEngineOpen0 Failed 0x%x\n", status));
        return status;
    }

    // 2. Register Callout with BFE (Base Filtering Engine)
    callout.calloutKey = GUID_ARAKNE_CALLOUT_V4;
    callout.classifyFn = ArakneClassifyFn;
    callout.notifyFn = NotifyFn;
    callout.flowDeleteFn = FlowDeleteFn;
    // callout.flags = 0;

    // Use DeviceObject from WDFDEVICE if needed for registration, but basic example uses global.
    // status = FwpsCalloutRegister0(DeviceObject, &callout, &g_CalloutId); 
    // Simplified: Requires PDEVICE_OBJECT. WdfDeviceWdmGetDeviceObject(Device)
    PDEVICE_OBJECT wdmDevice = WdfDeviceWdmGetDeviceObject(Device);
    status = FwpsCalloutRegister0(wdmDevice, &callout, &g_CalloutId);

    if (!NT_SUCCESS(status)) {
         KdPrint(("Arakne: FwpsCalloutRegister0 Failed 0x%x\n", status));
         return status;
    }

    // 3. Add Callout to Engine
    FwpmTransactionBegin0(g_EngineHandle, 0);

    mCallout.calloutKey = GUID_ARAKNE_CALLOUT_V4;
    mCallout.displayData.name = L"Arakne Network Killswitch";
    mCallout.applicableLayer = FWPM_LAYER_ALE_AUTH_CONNECT_V4; // Outbound Connect V4
    
    status = FwpmCalloutAdd0(g_EngineHandle, &mCallout, NULL, NULL);
    if (!NT_SUCCESS(status)) {
        // If it exists, that's fine (STATUS_FWP_ALREADY_EXISTS)
         KdPrint(("Arakne: FwpmCalloutAdd0 Status 0x%x\n", status));
    }

    // 4. Add Filter that uses the callout
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.displayData.name = L"Arakne Outbound Filter";
    filter.action.type = FWP_ACTION_CALLOUT_TERMINATING; // or INSPECTION
    filter.action.calloutKey = GUID_ARAKNE_CALLOUT_V4;
    filter.weight.type = FWP_UINT8;
    filter.weight.uint8 = 0xF; // High weight
    
    status = FwpmFilterAdd0(g_EngineHandle, &filter, NULL, NULL);
    
    FwpmTransactionCommit0(g_EngineHandle);

    KdPrint(("Arakne: WFP Killswitch Registered.\n"));
    return STATUS_SUCCESS;
}
