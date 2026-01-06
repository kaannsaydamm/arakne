#include <ntddk.h>
#include <wdf.h>

// Globals
BOOLEAN g_MonitorProcesses = TRUE;

// Callback Routine
VOID
ProcessNotifyCallback(
    _In_ HANDLE ParentId,
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN Create
    )
{
    UNREFERENCED_PARAMETER(ParentId);

    if (Create) {
        // Process Creation Detected
        // In a real driver, we would inspect the ImageFileName here.
        // However, retrieving the name safely in a Create callback requires strict rules.
        
        // Example: Block anything named "mimikatz.exe" (Conceptual)
        // If (Match(ImageFileName, "mimikatz.exe")) {
        //     KdPrint(("Arakne: BLOCKED Malicious Process Execution! PID: %d\n", HandleToULong(ProcessId)));
        //     // To strictly block, we might need PsSetCreateProcessNotifyRoutineEx for STATUS_ACCESS_DENIED return
        // }
        
        if (g_MonitorProcesses) {
            KdPrint(("Arakne: Process Created. PID: %d\n", HandleToULong(ProcessId)));
        }
    } else {
        // Process Termination
        KdPrint(("Arakne: Process Terminated. PID: %d\n", HandleToULong(ProcessId)));
    }
}

NTSTATUS RegisterProcessCallbacks()
{
    NTSTATUS status;
    
    // Using standard routine for compatibility. For blocking, Ex version is needed.
    status = PsSetCreateProcessNotifyRoutine(ProcessNotifyCallback, FALSE);
    
    if (!NT_SUCCESS(status)) {
         KdPrint(("Arakne: Failed to register Process Callback: 0x%x\n", status));
         return status;
    }
    
    KdPrint(("Arakne: Process Callbacks Active.\n"));
    return STATUS_SUCCESS;
}

VOID UnregisterProcessCallbacks()
{
    PsSetCreateProcessNotifyRoutine(ProcessNotifyCallback, TRUE);
}
