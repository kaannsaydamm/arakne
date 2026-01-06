package windows

import (
	"arakne/internal/core"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
)

// BrowserScanner checks for malicious extensions
type BrowserScanner struct{}

func NewBrowserScanner() *BrowserScanner {
	return &BrowserScanner{}
}

func (b *BrowserScanner) Name() string {
	return "Browser Forensics"
}

func (b *BrowserScanner) Run() ([]core.Threat, error) {
	fmt.Println("[*] Scanning Web Browsers (Extensions)...")
	threats := []core.Threat{}

	// Check Chrome Extensions
	home, _ := os.UserHomeDir()
	chromePath := filepath.Join(home, "AppData\\Local\\Google\\Chrome\\User Data\\Default\\Extensions")

	files, err := ioutil.ReadDir(chromePath)
	if err == nil {
		for _, f := range files {
			if f.IsDir() {
				// ID is the folder name
				id := f.Name()
				// Check against bad list
				if isMaliciousExtension(id) {
					fmt.Printf("[!] MALICIOUS EXTENSION: %s\n", id)
					threats = append(threats, core.Threat{
						Name:        "Malicious Browser Extension",
						Description: "Known malicious Chrome extension ID found.",
						Level:       core.LevelCritical,
						Details:     map[string]interface{}{"ID": id},
					})
				}
			}
		}
	}

	return threats, nil
}

func isMaliciousExtension(id string) bool {
	// Sample bad ID
	bad := map[string]bool{
		"aapbdbdomjkkjkaonfhkkikfgjllcleb": true, // Google Translate (Example) - obviously false positive for demo
		"dhdgffkkebhmkfjojejmpbldmpobfkfo": true, // Tampermonkey (Example)
	}
	return bad[id]
}
