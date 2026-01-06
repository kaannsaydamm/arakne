#include <ntddk.h>
#include <wdf.h>
#include "ioctl.h"

// Globals from main.c
extern BOOLEAN g_NukeMode;
extern ULONG g_ProtectedPID;

// Whitelist storage (populated via IOCTL)
static WCHAR g_Whitelist[MAX_WHITELIST_ENTRIES][MAX_PROCESS_NAME_LEN];
static ULONG g_WhitelistCount = 0;
static KSPIN_LOCK g_WhitelistLock;
static BOOLEAN g_WhitelistInitialized = FALSE;

// Initialize whitelist with critical system processes
VOID InitializeDefaultWhitelist()
{
    if (g_WhitelistInitialized) return;
    
    KeInitializeSpinLock(&g_WhitelistLock);
    
    // Default critical processes that should NEVER be blocked
    PCWSTR defaults[] = {
        L"smss.exe",
        L"csrss.exe",
        L"wininit.exe",
        L"services.exe",
        L"lsass.exe",
        L"svchost.exe",
        L"winlogon.exe",
        L"System",
        L"Registry",
        L"arakne.exe",
        L"MsMpEng.exe",
        L"MpCmdRun.exe"
    };
    
    for (ULONG i = 0; i < sizeof(defaults)/sizeof(defaults[0]) && i < MAX_WHITELIST_ENTRIES; i++) {
        RtlStringCchCopyW(g_Whitelist[i], MAX_PROCESS_NAME_LEN, defaults[i]);
        g_WhitelistCount++;
    }
    
    g_WhitelistInitialized = TRUE;
    KdPrint(("Arakne: Whitelist initialized with %d entries\n", g_WhitelistCount));
}

// Check if process name is whitelisted
BOOLEAN IsProcessWhitelisted(PUNICODE_STRING ImageFileName)
{
    if (!ImageFileName || !ImageFileName->Buffer) return FALSE;
    
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_WhitelistLock, &oldIrql);
    
    BOOLEAN found = FALSE;
    
    // Extract just the filename from full path
    PWCHAR lastSlash = wcsrchr(ImageFileName->Buffer, L'\\');
    PWCHAR fileName = lastSlash ? (lastSlash + 1) : ImageFileName->Buffer;
    
    for (ULONG i = 0; i < g_WhitelistCount && !found; i++) {
        if (_wcsicmp(fileName, g_Whitelist[i]) == 0) {
            found = TRUE;
        }
    }
    
    KeReleaseSpinLock(&g_WhitelistLock, oldIrql);
    return found;
}

// Update whitelist from user-mode
NTSTATUS UpdateWhitelist(PARAKNE_WHITELIST_REQUEST request)
{
    if (!request || request->EntryCount > MAX_WHITELIST_ENTRIES) {
        return STATUS_INVALID_PARAMETER;
    }
    
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_WhitelistLock, &oldIrql);
    
    // Clear existing and add new entries
    RtlZeroMemory(g_Whitelist, sizeof(g_Whitelist));
    g_WhitelistCount = 0;
    
    for (ULONG i = 0; i < request->EntryCount; i++) {
        RtlStringCchCopyW(g_Whitelist[i], MAX_PROCESS_NAME_LEN, request->Entries[i].ProcessName);
        g_WhitelistCount++;
    }
    
    KeReleaseSpinLock(&g_WhitelistLock, oldIrql);
    
    KdPrint(("Arakne: Whitelist updated with %d entries\n", g_WhitelistCount));
    return STATUS_SUCCESS;
}

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

    if (CreateInfo) {
        // Process Creation Detected
        
        // Initialize whitelist on first call
        InitializeDefaultWhitelist();
        
        // 1. Nuke Mode - Block ALL non-whitelisted processes
        if (g_NukeMode && CreateInfo->ImageFileName) {
            if (!IsProcessWhitelisted(CreateInfo->ImageFileName)) {
                KdPrint(("Arakne: [NUKE] BLOCKING non-whitelisted: %wZ\n", CreateInfo->ImageFileName));
                CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
                return;
            } else {
                KdPrint(("Arakne: [NUKE] Allowing whitelisted: %wZ\n", CreateInfo->ImageFileName));
            }
        }

        // 2. Block Known Malware (always active)
        if (CreateInfo->ImageFileName && CreateInfo->ImageFileName->Buffer) {
            PWCHAR lower = CreateInfo->ImageFileName->Buffer;
            
            // Convert to lowercase for comparison (simplified)
            if (wcsstr(lower, L"mimikatz") ||
                wcsstr(lower, L"MIMIKATZ") ||
                wcsstr(lower, L"cobalt") ||
                wcsstr(lower, L"COBALT") ||
                wcsstr(lower, L"meterpreter") ||
                wcsstr(lower, L"METERPRETER") ||
                wcsstr(lower, L"psexec") ||
                wcsstr(lower, L"PSEXEC") ||
                wcsstr(lower, L"beacon") ||
                wcsstr(lower, L"BEACON")) {
                KdPrint(("Arakne: [BLOCK] Malicious Binary: %wZ\n", CreateInfo->ImageFileName));
                CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
                return;
            }
        }
    } else {
        // Process Termination
        KdPrint(("Arakne: Process %d terminated\n", HandleToULong(ProcessId)));
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
    
    if (FullImageName != NULL && FullImageName->Buffer) {
        // Detect DLL Injection from suspicious paths
        if (wcsstr(FullImageName->Buffer, L"\\AppData\\Local\\Temp\\") ||
            wcsstr(FullImageName->Buffer, L"\\Roaming\\") ||
            wcsstr(FullImageName->Buffer, L"\\ProgramData\\") ||
            wcsstr(FullImageName->Buffer, L"\\Public\\")) {
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
        
        if (Info && Info->ValueName && Info->ValueName->Buffer) {
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
    
    // Initialize whitelist first
    InitializeDefaultWhitelist();
    
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
