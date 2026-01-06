package utils

import (
	"os"
	"os/user"
	"runtime"
)

// IsAdmin checks if the current process has administrative/root privileges
func IsAdmin() bool {
	if runtime.GOOS == "windows" {
		// On Windows, we can check if we can open the physical drive
		_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
		if err != nil {
			return false
		}
		return true
	} 
	// Unix-like systems (Linux, macOS)
	currentUser, err := user.Current()
	if err != nil {
		return false
	}
	// UID 0 is root
	return currentUser.Uid == "0"
}
