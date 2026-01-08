package windows

import (
	"arakne/internal/core"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// BrowserScanner checks for malicious extensions with deep analysis
type BrowserScanner struct {
	Threats []core.Threat
}

func NewBrowserScanner() *BrowserScanner {
	return &BrowserScanner{}
}

func (b *BrowserScanner) Name() string {
	return "Browser Forensics"
}

func (b *BrowserScanner) Run() ([]core.Threat, error) {
	fmt.Println("[*] Scanning Web Browsers (Deep Analysis)...")
	b.Threats = []core.Threat{}

	home, _ := os.UserHomeDir()

	// Scan Chrome
	chromePath := filepath.Join(home, "AppData", "Local", "Google", "Chrome", "User Data", "Default", "Extensions")
	b.scanExtensionDir(chromePath, "Chrome")

	// Scan Edge
	edgePath := filepath.Join(home, "AppData", "Local", "Microsoft", "Edge", "User Data", "Default", "Extensions")
	b.scanExtensionDir(edgePath, "Edge")

	// Scan Firefox
	firefoxPath := filepath.Join(home, "AppData", "Roaming", "Mozilla", "Firefox", "Profiles")
	b.scanFirefoxProfiles(firefoxPath)

	fmt.Printf("[+] Browser scan complete. Found %d threats.\n", len(b.Threats))
	return b.Threats, nil
}

func (b *BrowserScanner) scanExtensionDir(basePath, browser string) {
	exts, err := ioutil.ReadDir(basePath)
	if err != nil {
		return
	}

	for _, ext := range exts {
		if !ext.IsDir() {
			continue
		}

		extID := ext.Name()
		extPath := filepath.Join(basePath, extID)

		// Find version folders
		versions, _ := ioutil.ReadDir(extPath)
		for _, ver := range versions {
			if !ver.IsDir() {
				continue
			}

			versionPath := filepath.Join(extPath, ver.Name())
			b.analyzeExtension(versionPath, extID, browser)
		}
	}
}

func (b *BrowserScanner) analyzeExtension(extPath, extID, browser string) {
	// 1. Parse manifest.json
	manifestPath := filepath.Join(extPath, "manifest.json")
	manifestData, err := ioutil.ReadFile(manifestPath)
	if err != nil {
		return
	}

	var manifest map[string]interface{}
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return
	}

	extName := "Unknown"
	if name, ok := manifest["name"].(string); ok {
		extName = name
	}

	// Check dangerous permissions
	dangerousPerms := b.checkPermissions(manifest)
	if len(dangerousPerms) > 0 {
		b.Threats = append(b.Threats, core.Threat{
			Name:        "Dangerous Extension Permissions",
			Description: fmt.Sprintf("[%s] %s requests: %s", browser, extName, strings.Join(dangerousPerms, ", ")),
			Level:       core.LevelMedium,
			FilePath:    manifestPath,
			Details: map[string]interface{}{
				"extID":       extID,
				"name":        extName,
				"permissions": dangerousPerms,
			},
		})
	}

	// 2. Scan JavaScript files for obfuscation
	jsFiles := []string{
		filepath.Join(extPath, "background.js"),
		filepath.Join(extPath, "background.bundle.js"),
		filepath.Join(extPath, "content.js"),
		filepath.Join(extPath, "popup.js"),
	}

	// Also check from manifest background scripts
	if bg, ok := manifest["background"].(map[string]interface{}); ok {
		if scripts, ok := bg["scripts"].([]interface{}); ok {
			for _, s := range scripts {
				if script, ok := s.(string); ok {
					jsFiles = append(jsFiles, filepath.Join(extPath, script))
				}
			}
		}
		if sw, ok := bg["service_worker"].(string); ok {
			jsFiles = append(jsFiles, filepath.Join(extPath, sw))
		}
	}

	for _, jsFile := range jsFiles {
		threats := b.scanJavaScriptFile(jsFile, extName, browser)
		b.Threats = append(b.Threats, threats...)
	}

	// 3. Check against known malicious extension IDs
	if isMaliciousExtension(extID) {
		b.Threats = append(b.Threats, core.Threat{
			Name:        "Known Malicious Extension",
			Description: fmt.Sprintf("[%s] %s is in malware database", browser, extName),
			Level:       core.LevelCritical,
			FilePath:    extPath,
			Details:     map[string]interface{}{"extID": extID},
		})
	}
}

func (b *BrowserScanner) checkPermissions(manifest map[string]interface{}) []string {
	dangerous := []string{}

	dangerousPermsSet := map[string]bool{
		"<all_urls>":            true,
		"*://*/*":               true,
		"http://*/*":            true,
		"https://*/*":           true,
		"webRequest":            true,
		"webRequestBlocking":    true,
		"debugger":              true,
		"nativeMessaging":       true,
		"clipboardRead":         true,
		"clipboardWrite":        true,
		"cookies":               true,
		"management":            true,
		"proxy":                 true,
		"privacy":               true,
		"declarativeNetRequest": true,
	}

	// Check permissions
	if perms, ok := manifest["permissions"].([]interface{}); ok {
		for _, p := range perms {
			if perm, ok := p.(string); ok {
				if dangerousPermsSet[perm] {
					dangerous = append(dangerous, perm)
				}
			}
		}
	}

	// Check host_permissions (MV3)
	if hostPerms, ok := manifest["host_permissions"].([]interface{}); ok {
		for _, p := range hostPerms {
			if perm, ok := p.(string); ok {
				if strings.Contains(perm, "*") || strings.Contains(perm, "<all_urls>") {
					dangerous = append(dangerous, perm)
				}
			}
		}
	}

	return dangerous
}

func (b *BrowserScanner) scanJavaScriptFile(filePath, extName, browser string) []core.Threat {
	threats := []core.Threat{}

	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return threats
	}

	content := string(data)

	// Obfuscation patterns
	obfuscationPatterns := []struct {
		pattern     string
		description string
		level       core.ThreatLevel
	}{
		{`eval\s*\(`, "eval() execution - code injection risk", core.LevelHigh},
		{`new\s+Function\s*\(`, "Dynamic function creation", core.LevelHigh},
		{`atob\s*\(`, "Base64 decoding - possible payload", core.LevelMedium},
		{`btoa\s*\(`, "Base64 encoding", core.LevelLow},
		{`unescape\s*\(`, "String unescaping - obfuscation", core.LevelMedium},
		{`String\.fromCharCode`, "Character code conversion - obfuscation", core.LevelMedium},
		{`document\.write\s*\(`, "DOM manipulation", core.LevelMedium},
		{`innerHTML\s*=`, "innerHTML modification", core.LevelLow},
		{`chrome\.webRequest`, "Network request interception", core.LevelMedium},
		{`XMLHttpRequest|fetch\s*\(`, "Network requests", core.LevelLow},
		{`localStorage|sessionStorage`, "Storage access", core.LevelLow},
		{`\\x[0-9a-fA-F]{2}`, "Hex-escaped strings", core.LevelMedium},
		{`\\u[0-9a-fA-F]{4}`, "Unicode-escaped strings", core.LevelLow},
		{`[a-zA-Z0-9+/=]{100,}`, "Long base64 string (possible payload)", core.LevelHigh},
		{`_0x[a-fA-F0-9]+`, "Obfuscated variable names", core.LevelHigh},
		{`\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}`, "Heavy hex encoding", core.LevelHigh},
	}

	for _, p := range obfuscationPatterns {
		re := regexp.MustCompile(p.pattern)
		matches := re.FindAllString(content, 5)

		if len(matches) > 0 {
			// High severity patterns get reported
			if p.level >= core.LevelMedium {
				threats = append(threats, core.Threat{
					Name:        "Suspicious Extension Code",
					Description: fmt.Sprintf("[%s] %s: %s (%d occurrences)", browser, extName, p.description, len(matches)),
					Level:       p.level,
					FilePath:    filePath,
					Details: map[string]interface{}{
						"pattern":  p.pattern,
						"matches":  len(matches),
						"severity": p.level,
					},
				})
			}
		}
	}

	// Check for suspicious URLs
	urlPatterns := []string{
		`https?://[a-zA-Z0-9]{20,}\.`, // Long random subdomain
		`\.tk/|\.ml/|\.ga/|\.cf/`,     // Suspicious TLDs
		`pastebin\.com|paste\.ee`,     // Paste sites
		`discord\.com/api/webhooks`,   // Discord webhook exfil
		`telegram\.org/bot`,           // Telegram bot
	}

	for _, urlP := range urlPatterns {
		re := regexp.MustCompile(urlP)
		if re.MatchString(content) {
			threats = append(threats, core.Threat{
				Name:        "Suspicious URL in Extension",
				Description: fmt.Sprintf("[%s] %s contains suspicious URL pattern", browser, extName),
				Level:       core.LevelHigh,
				FilePath:    filePath,
			})
			break
		}
	}

	return threats
}

func (b *BrowserScanner) scanFirefoxProfiles(profilesPath string) {
	profiles, err := ioutil.ReadDir(profilesPath)
	if err != nil {
		return
	}

	for _, profile := range profiles {
		if !profile.IsDir() {
			continue
		}

		extPath := filepath.Join(profilesPath, profile.Name(), "extensions")
		exts, _ := ioutil.ReadDir(extPath)

		for _, ext := range exts {
			// Firefox extensions are XPI files or folders
			if strings.HasSuffix(ext.Name(), ".xpi") || ext.IsDir() {
				fmt.Printf("    [+] Firefox extension: %s\n", ext.Name())
			}
		}
	}
}

func isMaliciousExtension(id string) bool {
	// Known malicious extension IDs (sample list)
	bad := map[string]bool{
		// Fake ad blockers
		"gighmmpiobklfepjocnamgkkbiglidom": true, // Fake AdBlock
		// Data stealers
		"cfhdojbkjhnklbpkdaibdccddilifddb": true, // Malicious clone
		// Cryptominers
		"oofiananboodjbbmdelgdommihjbkfag": true,
	}
	return bad[id]
}
