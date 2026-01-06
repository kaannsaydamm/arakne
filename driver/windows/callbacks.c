#include <ntddk.h>
#include <wdf.h>
#include "ioctl.h"

// Globals from main.c
extern BOOLEAN g_NukeMode;
extern ULONG g_ProtectedPID;

// -------------------------------------------------------------------------
// 1. Process Blocking (PsSetCreateProcessNotifyRoutineEx)
// -------------------------------------------------------------------------

VOID
ProcessNotifyCallbackEx(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
    )
{
    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(ProcessId);

    if (CreateInfo) {
        // Process Creation Detected
        
        // 1. Nuke Mode Check - Block ALL non-whitelisted
        if (g_NukeMode) {
             KdPrint(("Arakne: [NUKE] Validating Process Creation: PID %d\n", HandleToULong(ProcessId)));
             // In production: Check against whitelist
             // For now, we don't block system processes
        }

        // 2. Block Specific Malware by name
        if (CreateInfo->ImageFileName) {
            if (wcsstr(CreateInfo->ImageFileName->Buffer, L"mimikatz") ||
                wcsstr(CreateInfo->ImageFileName->Buffer, L"cobalt") ||
                wcsstr(CreateInfo->ImageFileName->Buffer, L"meterpreter") ||
                wcsstr(CreateInfo->ImageFileName->Buffer, L"psexec")) {
                KdPrint(("Arakne: [BLOCK] Malicious Binary Detected: %wZ\n", CreateInfo->ImageFileName));
                CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
            }
        }
    }
}

// -------------------------------------------------------------------------
// 2. DLL Hunter (PsSetLoadImageNotifyRoutine)
// -------------------------------------------------------------------------

VOID
LoadImageNotifyCallback(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo
    )
{
    UNREFERENCED_PARAMETER(ImageInfo);
    UNREFERENCED_PARAMETER(ProcessId);
    
    if (FullImageName != NULL) {
        // Detect DLL Injection from suspicious paths
        if (wcsstr(FullImageName->Buffer, L"\\AppData\\Local\\Temp\\") ||
            wcsstr(FullImageName->Buffer, L"\\Roaming\\") ||
            wcsstr(FullImageName->Buffer, L"\\ProgramData\\")) {
             KdPrint(("Arakne: [WARN] Suspicious DLL Load: %wZ\n", FullImageName));
        }
    }
}

// -------------------------------------------------------------------------
// 3. Registry Guard (CmRegisterCallback)
// -------------------------------------------------------------------------

LARGE_INTEGER g_RegistryCookie;

NTSTATUS
RegistryCallback(
    _In_ PVOID CallbackContext,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2
    )
{
    UNREFERENCED_PARAMETER(CallbackContext);
    REG_NOTIFY_CLASS Operation = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;

    if (Operation == RegNtPreSetValueKey) {
        PREG_SET_VALUE_KEY_INFORMATION Info = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
        
        if (Info && Info->ValueName) {
            // Block writes to known persistence value names
            if (wcsstr(Info->ValueName->Buffer, L"Run") ||
                wcsstr(Info->ValueName->Buffer, L"RunOnce") ||
                wcsstr(Info->ValueName->Buffer, L"Userinit") ||
                wcsstr(Info->ValueName->Buffer, L"Shell")) {
                KdPrint(("Arakne: [BLOCK] Registry persistence attempt: %wZ\n", Info->ValueName));
                return STATUS_ACCESS_DENIED;
            }
        }
    }
    return STATUS_SUCCESS;
}


// -------------------------------------------------------------------------
// 4. Self-Defense (ObRegisterCallbacks)
// -------------------------------------------------------------------------

PVOID g_ObRegistrationHandle = NULL;

OB_PREOP_CALLBACK_STATUS
PreProcessCallback(
    _In_ PVOID RegistrationContext,
    _In_ POB_PRE_OPERATION_INFORMATION OperationInformation
    )
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    if (g_ProtectedPID == 0) return OB_PREOP_SUCCESS;

    PEPROCESS OpenedProcess = (PEPROCESS)OperationInformation->Object;
    HANDLE TargetPid = PsGetProcessId(OpenedProcess);

    // Protect Arakne's PID
    if ((ULONG)(ULONG_PTR)TargetPid == g_ProtectedPID) {
        // Allow self-access
        if (PsGetCurrentProcessId() != TargetPid) {
             // Strip dangerous access rights
             if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
                 OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= 
                     ~(PROCESS_TERMINATE | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD);
             } else {
                 OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= 
                     ~(PROCESS_TERMINATE | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD);
             }
             KdPrint(("Arakne: [DEFENSE] Blocked handle access to protected PID\n"));
        }
    }

    return OB_PREOP_SUCCESS;
}

// -------------------------------------------------------------------------
// Management
// -------------------------------------------------------------------------

NTSTATUS RegisterProcessCallbacks()
{
    NTSTATUS status;
    
    // 1. Process Blocking
    status = PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallbackEx, FALSE);
    if (!NT_SUCCESS(status)) {
        KdPrint(("Arakne: PsSetCreateProcessNotifyRoutineEx failed: 0x%x\n", status));
        return status;
    }
    
    // 2. DLL Hunter
    status = PsSetLoadImageNotifyRoutine(LoadImageNotifyCallback);
    if (!NT_SUCCESS(status)) {
        KdPrint(("Arakne: PsSetLoadImageNotifyRoutine failed: 0x%x\n", status));
        return status;
    }
    
    // 3. Registry Guard
    UNICODE_STRING Altitude = RTL_CONSTANT_STRING(L"320000");
    status = CmRegisterCallbackEx(RegistryCallback, &Altitude, NULL, NULL, &g_RegistryCookie, NULL);
    if (!NT_SUCCESS(status)) {
        KdPrint(("Arakne: CmRegisterCallbackEx failed: 0x%x (non-fatal)\n", status));
        // Continue - Registry guard is optional
    }
    
    // 4. Self-Defense (ObRegisterCallbacks)
    OB_CALLBACK_REGISTRATION obReg = {0};
    OB_OPERATION_REGISTRATION opReg = {0};
    
    obReg.Version = OB_FLT_REGISTRATION_VERSION;
    obReg.OperationRegistrationCount = 1;
    obReg.Altitude = RTL_CONSTANT_STRING(L"320000");
    obReg.RegistrationContext = NULL;
    obReg.OperationRegistration = &opReg;
    
    opReg.ObjectType = PsProcessType;
    opReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    opReg.PreOperation = PreProcessCallback;
    opReg.PostOperation = NULL;
    
    status = ObRegisterCallbacks(&obReg, &g_ObRegistrationHandle);
    if (!NT_SUCCESS(status)) {
        KdPrint(("Arakne: ObRegisterCallbacks failed: 0x%x (non-fatal)\n", status));
        // Continue - Self-defense is optional (requires signed driver)
    }
    
    KdPrint(("Arakne: All Callbacks Registered.\n"));
    return STATUS_SUCCESS;
}

VOID UnregisterProcessCallbacks()
{
    PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallbackEx, TRUE);
    PsRemoveLoadImageNotifyRoutine(LoadImageNotifyCallback);
    
    if (g_RegistryCookie.QuadPart != 0) {
        CmUnRegisterCallback(g_RegistryCookie);
    }
    
    if (g_ObRegistrationHandle != NULL) {
        ObUnRegisterCallbacks(g_ObRegistrationHandle);
    }
}
