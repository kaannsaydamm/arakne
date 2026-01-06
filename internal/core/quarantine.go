package core

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// QuarantineJail manages the isolation of threats
type QuarantineJail struct {
	JailPath string
}

func NewQuarantineJail(path string) *QuarantineJail {
	if path == "" {
		// Default to a hidden folder in program data or root
		path = "C:\\ArakneJail"
		if os.PathSeparator == '/' {
			path = "/var/lib/arakne/jail"
		}
	}
	return &QuarantineJail{JailPath: path}
}

// Lockup moves a threat to the jail and neutralizes it (XOR encoding)
func (q *QuarantineJail) Lockup(sourcePath string) error {
	// 1. Ensure Jail exists with strict permissions (0700)
	if _, err := os.Stat(q.JailPath); os.IsNotExist(err) {
		err := os.MkdirAll(q.JailPath, 0700)
		if err != nil {
			return fmt.Errorf("failed to create jail: %v", err)
		}
	}

	// 2. Generate Jail Filename (Timestamp + Original Name + .quarantine)
	_, filename := filepath.Split(sourcePath)
	timestamp := time.Now().Format("20060102_150405")
	destName := fmt.Sprintf("%s_%s.quarantine", timestamp, filename)
	destPath := filepath.Join(q.JailPath, destName)

	// 3. Move and XOR Encode
	// We don't just move; we read, encode, write, then delete source.
	// This defeats "Resurrection" scripts that watch for file handles.
	
	srcFile, err := os.Open(sourcePath)
	if err != nil {
		return fmt.Errorf("failed to open source threat: %v", err)
	}
	defer srcFile.Close()

	dstFile, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("failed to create jail cell: %v", err)
	}
	defer dstFile.Close()

	// XOR Key (Simplistic neutralization)
	key := byte(0xAA)
	
	buf := make([]byte, 4096)
	for {
		n, err := srcFile.Read(buf)
		if n > 0 {
			// Encrypt buffer in place
			for i := 0; i < n; i++ {
				buf[i] ^= key
			}
			dstFile.Write(buf[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}

	// 4. Delete Source ("Nuke")
	srcFile.Close() // Close before delete
	err = os.Remove(sourcePath)
	if err != nil {
		return fmt.Errorf("failed to delete original threat (persistence?): %v", err)
	}

	fmt.Printf("[+] THREAT JAILED: %s -> %s\n", sourcePath, destPath)
	return nil
}
