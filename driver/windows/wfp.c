// WFP requires NDIS version macros BEFORE any NDIS/WFP headers
#define NDIS_SUPPORT_NDIS6 1
#define NDIS630 1

#include <ntddk.h>
#include <ndis.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include <initguid.h>
#include "ioctl.h"

// -------------------------------------------------------------------------
// WFP Network Killswitch
// -------------------------------------------------------------------------

// GUID for V4
DEFINE_GUID(GUID_ARAKNE_CALLOUT_V4, 
    0xde39486a, 0xaa27, 0x4879, 0xb8, 0x5a, 0x22, 0xd0, 0x5d, 0x42, 0x47, 0x11);
DEFINE_GUID(GUID_ARAKNE_FILTER_V4, 
    0xde39486a, 0xaa27, 0x4879, 0xb8, 0x5a, 0x22, 0xd0, 0x5d, 0x42, 0x47, 0x22);

// GUID for V6
DEFINE_GUID(GUID_ARAKNE_CALLOUT_V6, 
    0xde39486a, 0xaa27, 0x4879, 0xb8, 0x5a, 0x22, 0xd0, 0x5d, 0x42, 0x47, 0x33);
DEFINE_GUID(GUID_ARAKNE_FILTER_V6, 
    0xde39486a, 0xaa27, 0x4879, 0xb8, 0x5a, 0x22, 0xd0, 0x5d, 0x42, 0x47, 0x44);

// Global Switch
BOOLEAN g_NetworkIsolate = FALSE;

// Helper functions (exposed to main.c)
void WFP_SetKillswitch(BOOLEAN enable) {
    g_NetworkIsolate = enable;
    KdPrint(("Arakne: [WFP] Killswitch state changed to: %d\n", enable));
}

BOOLEAN WFP_GetKillswitchState() {
    return g_NetworkIsolate;
}

// Engine Handle
HANDLE g_EngineHandle = NULL;
UINT32 g_CalloutIdV4 = 0;
UINT32 g_CalloutIdV6 = 0;

// Callout Routine: ClassifyFn
extern ULONG g_ProtectedPID;

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
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    if (g_NetworkIsolate) {
        // EXEMPTION LOGIC: Allow Arakne itself to talk
        if (g_ProtectedPID != 0 && 
            FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_PROCESS_ID)) {
            
            if ((ULONG)inMetaValues->processId == g_ProtectedPID) {
                // Allow Arakne Traffic even if Killswitch is ON
                classifyOut->actionType = FWP_ACTION_PERMIT;
                return;
            }
        }

        // KILL SWITCH ENGAGED
        classifyOut->actionType = FWP_ACTION_BLOCK;
        classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE; // Prevent others from permitting
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

VOID UnregisterWFPCallouts()
{
    KdPrint(("Arakne: Unregistering WFP Callouts...\n"));

    if (g_EngineHandle) {
        FwpmTransactionBegin0(g_EngineHandle, 0);

        // Delete Filters
        FwpmFilterDeleteByKey0(g_EngineHandle, &GUID_ARAKNE_FILTER_V4);
        FwpmFilterDeleteByKey0(g_EngineHandle, &GUID_ARAKNE_FILTER_V6);

        // Delete Callouts from Engine
        FwpmCalloutDeleteByKey0(g_EngineHandle, &GUID_ARAKNE_CALLOUT_V4);
        FwpmCalloutDeleteByKey0(g_EngineHandle, &GUID_ARAKNE_CALLOUT_V6);

        FwpmTransactionCommit0(g_EngineHandle);
        
        // Unregister Callouts from WFP (Kernel)
        if (g_CalloutIdV4) {
             FwpsCalloutUnregisterById0(g_CalloutIdV4);
             g_CalloutIdV4 = 0;
        }
        if (g_CalloutIdV6) {
             FwpsCalloutUnregisterById0(g_CalloutIdV6);
             g_CalloutIdV6 = 0;
        }
        
        FwpmEngineClose0(g_EngineHandle);
        g_EngineHandle = NULL;
    }
}

NTSTATUS RegisterWFPCallouts(PDEVICE_OBJECT DeviceObject)
{
    NTSTATUS status;
    FWPS_CALLOUT0 callout = {0};
    FWPM_CALLOUT0 mCallout = {0};
    FWPM_FILTER0 filter = {0};
    FWPM_SESSION0 session = {0};

    UNREFERENCED_PARAMETER(DeviceObject);
    
    // 1. Open Engine
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &g_EngineHandle);
    if (!NT_SUCCESS(status)) {
        KdPrint(("Arakne: FwpmEngineOpen0 Failed 0x%x\n", status));
        return status;
    }

    // 2. Register Callouts
    callout.classifyFn = ArakneClassifyFn;
    callout.notifyFn = NotifyFn;
    callout.flowDeleteFn = FlowDeleteFn;
    
    // Register V4
    callout.calloutKey = GUID_ARAKNE_CALLOUT_V4;
    status = FwpsCalloutRegister0(DeviceObject, &callout, &g_CalloutIdV4);
    if (!NT_SUCCESS(status)) return status;

    // Register V6
    callout.calloutKey = GUID_ARAKNE_CALLOUT_V6;
    status = FwpsCalloutRegister0(DeviceObject, &callout, &g_CalloutIdV6);
    if (!NT_SUCCESS(status)) return status;


    // 3. Add Callouts to Engine
    FwpmTransactionBegin0(g_EngineHandle, 0);

    // V4 Callout
    mCallout.calloutKey = GUID_ARAKNE_CALLOUT_V4;
    mCallout.displayData.name = L"Arakne Outbound V4";
    mCallout.applicableLayer = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    FwpmCalloutAdd0(g_EngineHandle, &mCallout, NULL, NULL);

    // V6 Callout
    mCallout.calloutKey = GUID_ARAKNE_CALLOUT_V6;
    mCallout.displayData.name = L"Arakne Outbound V6";
    mCallout.applicableLayer = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
    FwpmCalloutAdd0(g_EngineHandle, &mCallout, NULL, NULL);

    // 4. Add Filters
    filter.weight.type = FWP_UINT8;
    filter.weight.uint8 = 0xF; 
    filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;

    // V4 Filter
    filter.filterKey = GUID_ARAKNE_FILTER_V4;
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.displayData.name = L"Arakne Filter V4";
    filter.action.calloutKey = GUID_ARAKNE_CALLOUT_V4;
    FwpmFilterAdd0(g_EngineHandle, &filter, NULL, NULL);

    // V6 Filter
    filter.filterKey = GUID_ARAKNE_FILTER_V6;
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
    filter.displayData.name = L"Arakne Filter V6";
    filter.action.calloutKey = GUID_ARAKNE_CALLOUT_V6;
    FwpmFilterAdd0(g_EngineHandle, &filter, NULL, NULL);
    
    FwpmTransactionCommit0(g_EngineHandle);

    KdPrint(("Arakne: WFP Killswitch Registered (IPv4 + IPv6).\n"));
    return STATUS_SUCCESS;
}
