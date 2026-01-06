package core

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// BagHandler manages forensic evidence collection
type BagHandler struct {
	CaseID      string
	StoragePath string
}

func NewBagHandler(caseID string) *BagHandler {
	return &BagHandler{
		CaseID:      caseID,
		StoragePath: "C:\\ArakneEvidence",
	}
}

func (b *BagHandler) Collect(filePath string) error {
	// 1. Ensure storage exists
	caseDir := filepath.Join(b.StoragePath, b.CaseID)
	os.MkdirAll(caseDir, 0755)

	// 2. Hash Original
	hash, err := hashFile(filePath)
	if err != nil {
		fmt.Printf("[-] Failed to hash evidence %s: %v\n", filePath, err)
		return err
	}
	fmt.Printf("[*] Evidence Hashed (%s): %s\n", filePath, hash)

	// 3. Copy to Bag
	_, filename := filepath.Split(filePath)
	destPath := filepath.Join(caseDir, filename)
	
	err = copyFile(filePath, destPath)
	if err != nil {
		return err
	}

	fmt.Printf("[+] Evidence Secured: %s\n", destPath)
	return nil
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	return err
}
