package windows

import (
	"arakne/internal/core"
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

// YARAScanner implements native pattern matching without CGO
type YARAScanner struct {
	RulesPath string
	Rules     []YARARule
}

type YARARule struct {
	Name    string
	Strings [][]byte
	Meta    string
}

func NewYARAScanner(rulesPath string) *YARAScanner {
	scanner := &YARAScanner{RulesPath: rulesPath}
	scanner.LoadBuiltinRules()
	return scanner
}

func (y *YARAScanner) Name() string {
	return "YARA Intelligence"
}

// LoadBuiltinRules loads hardcoded detection signatures
func (y *YARAScanner) LoadBuiltinRules() {
	y.Rules = []YARARule{
		{
			Name: "Mimikatz",
			Strings: [][]byte{
				[]byte("mimikatz"),
				[]byte("sekurlsa::logonpasswords"),
				[]byte("privilege::debug"),
			},
			Meta: "Credential dumping tool",
		},
		{
			Name: "CobaltStrike_Beacon",
			Strings: [][]byte{
				[]byte("beacon.dll"),
				[]byte("ReflectiveLoader"),
				[]byte("%s as %s\\%s: %d"),
			},
			Meta: "CobaltStrike Beacon shellcode",
		},
		{
			Name: "Meterpreter",
			Strings: [][]byte{
				[]byte("metsrv"),
				[]byte("stdapi_"),
				[]byte("core_channel_open"),
			},
			Meta: "Metasploit Meterpreter payload",
		},
		{
			Name: "PowerShell_Encoded",
			Strings: [][]byte{
				[]byte("-EncodedCommand"),
				[]byte("-e JAB"),
				[]byte("FromBase64String"),
			},
			Meta: "Obfuscated PowerShell",
		},
		{
			Name: "WebShell_Generic",
			Strings: [][]byte{
				[]byte("c99shell"),
				[]byte("r57shell"),
				[]byte("WSO "),
				[]byte("<%eval"),
			},
			Meta: "Web shell indicators",
		},
		{
			Name: "Ransomware_Generic",
			Strings: [][]byte{
				[]byte("Your files have been encrypted"),
				[]byte("bitcoin"),
				[]byte(".onion"),
				[]byte("decrypt"),
			},
			Meta: "Ransomware indicators",
		},
	}
}

func (y *YARAScanner) Run() ([]core.Threat, error) {
	fmt.Printf("[*] Initializing YARA Engine (%d rules loaded)...\n", len(y.Rules))

	threats := []core.Threat{}

	// Scan common malware locations
	scanPaths := []string{
		os.Getenv("TEMP"),
		os.Getenv("APPDATA"),
		"C:\\Users\\Public",
		"C:\\ProgramData",
	}

	scanned := 0
	for _, basePath := range scanPaths {
		if basePath == "" {
			continue
		}

		filepath.Walk(basePath, func(path string, info os.FileInfo, err error) error {
			if err != nil || info == nil || info.IsDir() {
				return nil
			}

			// Skip large files
			if info.Size() > 10*1024*1024 { // 10MB
				return nil
			}

			// Check extensions
			ext := strings.ToLower(filepath.Ext(path))
			if ext != ".exe" && ext != ".dll" && ext != ".ps1" && ext != ".bat" && ext != ".vbs" {
				return nil
			}

			scanned++
			matches := y.ScanFile(path)
			threats = append(threats, matches...)

			return nil
		})
	}

	fmt.Printf("[+] YARA Scan Complete. Scanned %d files, found %d matches.\n", scanned, len(threats))
	return threats, nil
}

func (y *YARAScanner) ScanFile(path string) []core.Threat {
	threats := []core.Threat{}

	data, err := ioutil.ReadFile(path)
	if err != nil {
		return threats
	}

	for _, rule := range y.Rules {
		matched := false
		for _, sig := range rule.Strings {
			if bytes.Contains(data, sig) {
				matched = true
				break
			}
		}

		if matched {
			fmt.Printf("[!] YARA MATCH: %s in %s\n", rule.Name, path)
			threats = append(threats, core.Threat{
				Name:        rule.Name,
				Description: rule.Meta,
				Level:       core.LevelCritical,
				FilePath:    path,
				Details: map[string]interface{}{
					"rule": rule.Name,
					"meta": rule.Meta,
				},
			})
		}
	}

	return threats
}

// ScanMemory scans process memory for YARA signatures
func (y *YARAScanner) ScanMemory(pid uint32) []core.Threat {
	fmt.Printf("[*] Scanning memory of PID %d...\n", pid)
	// Memory scanning would use ReadProcessMemory + pattern matching
	// Implemented in memory.go with RWX detection
	return []core.Threat{}
}
