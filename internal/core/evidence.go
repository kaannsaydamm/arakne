package core

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// BagHandler manages the collection of forensics artifacts
type BagHandler struct {
	CaseID  string
	BagPath string
}

func NewBagHandler(caseID string) *BagHandler {
	// Create a dir for the case
	path := filepath.Join(EvidenceDir, caseID)
	os.MkdirAll(path, 0755)
	return &BagHandler{
		CaseID:  caseID,
		BagPath: path,
	}
}

func (b *BagHandler) Collect(targetPath string) error {
	// Copy file to bag
	fmt.Printf("[BAG] Collecting evidence: %s\n", targetPath)

	info, err := os.Stat(targetPath)
	if err != nil {
		return err
	}

	if info.IsDir() {
		// recursive copy omitted for brevity
		return nil
	}

	dest := filepath.Join(b.BagPath, filepath.Base(targetPath))
	return copyFile(targetPath, dest)
}

func (b *BagHandler) Seal() (string, error) {
	// Zip the bag
	zipName := b.BagPath + ".zip"
	fmt.Printf("[BAG] Sealing evidence into %s\n", zipName)

	outFile, err := os.Create(zipName)
	if err != nil {
		return "", err
	}
	defer outFile.Close()

	w := zip.NewWriter(outFile)
	defer w.Close()

	// Walk and zip
	err = filepath.Walk(b.BagPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		relPath, _ := filepath.Rel(b.BagPath, path)
		f, err := w.Create(relPath)
		if err != nil {
			return err
		}

		fileContent, err := os.Open(path)
		if err != nil {
			return err
		}
		defer fileContent.Close()

		_, err = io.Copy(f, fileContent)
		return err
	})

	return zipName, err
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}
