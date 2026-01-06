package core

import (
	"strings"
)

// WhitelistManager handles the protection of critical system processes.
// Nuke Mode or not, these processes should NEVER be touched to avoid BSOD or system instability.
type WhitelistManager struct {
	CriticalProcs map[string]bool
}

var GlobalWhitelist *WhitelistManager

func init() {
	GlobalWhitelist = NewWhitelistManager()
}

func NewWhitelistManager() *WhitelistManager {
	return &WhitelistManager{
		CriticalProcs: map[string]bool{
			"smss.exe":                    true, // Session Manager
			"csrss.exe":                   true, // Client Server Runtime Process
			"wininit.exe":                 true, // Windows Initialization
			"services.exe":                true, // Service Control Manager
			"lsass.exe":                   true, // Local Security Authority (Careful with Dump)
			"lsm.exe":                     true, // Local Session Manager
			"svchost.exe":                 true, // Generic Host (Context dependent, but killing all is bad)
			"winlogon.exe":                true, // Windows Logon
			"explorer.exe":                false, // Shell (Can be killed, but annoying)
			"taskmgr.exe":                 false,
			"arakne.exe":                  true, // Self-protection logic
			"mpcmdrun.exe":                true, // Defender
			"msmpeng.exe":                 true, // Defender Service
			"nissrv.exe":                  true, // Network Inspection
		},
	}
}

// IsCritical checks if the process name is in the hardcoded safety list.
// name should be the base name (e.g., "csrss.exe").
func (w *WhitelistManager) IsCritical(name string) bool {
	lowerName := strings.ToLower(name)
	isCritical, exists := w.CriticalProcs[lowerName]
	return exists && isCritical
}

// IsWhitelisted checks if a process should be ignored (Critical or User Defined Safe).
func (w *WhitelistManager) IsWhitelisted(name string) bool {
	return w.IsCritical(name)
}
