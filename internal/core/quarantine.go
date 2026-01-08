package core

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// QuarantineJail manages the isolation of threats
type QuarantineJail struct {
	JailPath string
}

func NewQuarantineJail(path string) *QuarantineJail {
	if path == "" {
		// Default to C:\Arakne\Quarantine
		path = QuarantineDir
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

// Restore extracts a file from quarantine and restores it to original location
func (q *QuarantineJail) Restore(quarantineFile string) (string, error) {
	// Full path to quarantine file
	srcPath := filepath.Join(q.JailPath, quarantineFile)

	// Check if file exists
	if _, err := os.Stat(srcPath); os.IsNotExist(err) {
		return "", fmt.Errorf("quarantine file not found: %s", quarantineFile)
	}

	// Parse original filename from quarantine name
	// Format: YYYYMMDD_HHMMSS_originalname.quarantine
	baseName := filepath.Base(quarantineFile)
	if !strings.HasSuffix(baseName, ".quarantine") {
		return "", fmt.Errorf("not a quarantine file: %s", baseName)
	}

	// Remove .quarantine suffix
	baseName = strings.TrimSuffix(baseName, ".quarantine")

	// Extract original filename (after first two underscores: date_time_filename)
	parts := strings.SplitN(baseName, "_", 3)
	originalName := baseName
	if len(parts) >= 3 {
		originalName = parts[2]
	}

	// Restore to Downloads folder (safe location)
	restorePath := filepath.Join(os.Getenv("USERPROFILE"), "Downloads", "Restored_"+originalName)

	// Read encrypted file
	srcFile, err := os.Open(srcPath)
	if err != nil {
		return "", fmt.Errorf("failed to open quarantine file: %v", err)
	}
	defer srcFile.Close()

	// Create restored file
	dstFile, err := os.Create(restorePath)
	if err != nil {
		return "", fmt.Errorf("failed to create restored file: %v", err)
	}
	defer dstFile.Close()

	// XOR Key (same as encryption)
	key := byte(0xAA)

	// Decrypt and write
	buf := make([]byte, 4096)
	for {
		n, err := srcFile.Read(buf)
		if n > 0 {
			// Decrypt buffer in place (XOR is reversible)
			for i := 0; i < n; i++ {
				buf[i] ^= key
			}
			dstFile.Write(buf[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
	}

	fmt.Printf("[+] RESTORED: %s -> %s\n", quarantineFile, restorePath)
	return restorePath, nil
}

// ListQuarantine returns list of quarantined files
func (q *QuarantineJail) ListQuarantine() ([]string, error) {
	files := []string{}

	entries, err := os.ReadDir(q.JailPath)
	if err != nil {
		if os.IsNotExist(err) {
			return files, nil
		}
		return nil, err
	}

	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".quarantine") {
			files = append(files, entry.Name())
		}
	}

	return files, nil
}
