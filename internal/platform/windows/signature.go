package windows

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

var (
	wintrust           = syscall.NewLazyDLL("wintrust.dll")
	procWinVerifyTrust = wintrust.NewProc("WinVerifyTrust")

	crypt32                        = syscall.NewLazyDLL("crypt32.dll")
	procCryptQueryObject           = crypt32.NewProc("CryptQueryObject")
	procCertGetNameString          = crypt32.NewProc("CertGetNameStringW")
	procCertFreeCertificateContext = crypt32.NewProc("CertFreeCertificateContext")
)

// WINTRUST_DATA structure (simplified)
type WINTRUST_DATA struct {
	CbStruct           uint32
	PolicyCallbackData uintptr
	SIPClientData      uintptr
	UIChoice           uint32
	RevocationChecks   uint32
	UnionChoice        uint32
	FileInfoPtr        uintptr
	StateAction        uint32
	StateData          uintptr
	URLReference       uintptr
	ProvFlags          uint32
	UIContext          uint32
	SignatureSettings  uintptr
}

type WINTRUST_FILE_INFO struct {
	CbStruct     uint32
	FilePath     *uint16
	FileHandle   syscall.Handle
	KnownSubject uintptr
}

// Constants
const (
	TRUST_E_NOSIGNATURE         = 0x800B0100
	TRUST_E_EXPLICIT_DISTRUST   = 0x800B0111
	TRUST_E_SUBJECT_NOT_TRUSTED = 0x800B0004
	CRYPT_E_SECURITY_SETTINGS   = 0x80092026

	WTD_UI_NONE            = 2
	WTD_REVOKE_NONE        = 0
	WTD_CHOICE_FILE        = 1
	WTD_STATEACTION_VERIFY = 1
	WTD_STATEACTION_CLOSE  = 2

	CERT_NAME_SIMPLE_DISPLAY_TYPE = 4
	CERT_NAME_ISSUER_FLAG         = 1
)

// SignatureInfo holds certificate information
type SignatureInfo struct {
	IsSigned     bool
	IsValid      bool
	Signer       string
	Issuer       string
	IsTrusted    bool
	ErrorMessage string
}

// Trusted publishers (major software vendors)
var trustedPublishers = map[string]bool{
	"microsoft":  true,
	"google":     true,
	"mozilla":    true,
	"discord":    true,
	"slack":      true,
	"spotify":    true,
	"adobe":      true,
	"nvidia":     true,
	"amd":        true,
	"intel":      true,
	"valve":      true,
	"steam":      true,
	"bluestacks": true,
	"notion":     true,
	"dropbox":    true,
	"zoom":       true,
	"logitech":   true,
	"razer":      true,
	"corsair":    true,
	"msi":        true,
	"asus":       true,
	"dell":       true,
	"hp":         true,
	"lenovo":     true,
	"samsung":    true,
	"openvpn":    true,
	"anydesk":    true,
	"teamviewer": true,
	"telegram":   true,
	"whatsapp":   true,
	"meta":       true,
	"facebook":   true,
	"apple":      true,
}

// VerifySignature checks if an executable is digitally signed and trusted
func VerifySignature(filePath string) SignatureInfo {
	info := SignatureInfo{}

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		info.ErrorMessage = "File not found"
		return info
	}

	// Convert path to UTF16
	pathPtr, err := syscall.UTF16PtrFromString(filePath)
	if err != nil {
		info.ErrorMessage = err.Error()
		return info
	}

	// Setup WINTRUST_FILE_INFO
	fileInfo := WINTRUST_FILE_INFO{
		CbStruct: uint32(unsafe.Sizeof(WINTRUST_FILE_INFO{})),
		FilePath: pathPtr,
	}

	// WINTRUST_ACTION_GENERIC_VERIFY_V2 GUID
	actionGUID := syscall.GUID{
		Data1: 0xaac56b,
		Data2: 0xcd44,
		Data3: 0x11d0,
		Data4: [8]byte{0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee},
	}

	// Setup WINTRUST_DATA
	wintrustData := WINTRUST_DATA{
		CbStruct:         uint32(unsafe.Sizeof(WINTRUST_DATA{})),
		UIChoice:         WTD_UI_NONE,
		RevocationChecks: WTD_REVOKE_NONE,
		UnionChoice:      WTD_CHOICE_FILE,
		FileInfoPtr:      uintptr(unsafe.Pointer(&fileInfo)),
		StateAction:      WTD_STATEACTION_VERIFY,
		ProvFlags:        0,
	}

	// Call WinVerifyTrust
	ret, _, _ := procWinVerifyTrust.Call(
		uintptr(syscall.InvalidHandle),
		uintptr(unsafe.Pointer(&actionGUID)),
		uintptr(unsafe.Pointer(&wintrustData)),
	)

	status := uint32(ret)

	// Cleanup
	wintrustData.StateAction = WTD_STATEACTION_CLOSE
	procWinVerifyTrust.Call(
		uintptr(syscall.InvalidHandle),
		uintptr(unsafe.Pointer(&actionGUID)),
		uintptr(unsafe.Pointer(&wintrustData)),
	)

	// Interpret result
	switch status {
	case 0: // Success
		info.IsSigned = true
		info.IsValid = true
	case 0x800B0100: // TRUST_E_NOSIGNATURE
		info.IsSigned = false
		info.ErrorMessage = "No signature"
	case 0x800B0111: // TRUST_E_EXPLICIT_DISTRUST
		info.IsSigned = true
		info.IsValid = false
		info.ErrorMessage = "Explicitly distrusted"
	case 0x800B0004: // TRUST_E_SUBJECT_NOT_TRUSTED
		info.IsSigned = true
		info.IsValid = false
		info.ErrorMessage = "Subject not trusted"
	default:
		info.IsSigned = true
		info.IsValid = false
		info.ErrorMessage = fmt.Sprintf("Verification failed: 0x%X", status)
	}

	// Get signer name if signed
	if info.IsSigned {
		info.Signer = GetSignerName(filePath)
		info.IsTrusted = IsSignerTrusted(info.Signer)
	}

	return info
}

// GetSignerName extracts the signer name from a signed file
func GetSignerName(filePath string) string {
	// Use PowerShell to get signer (simpler than raw Crypt32 API)
	cmd := fmt.Sprintf(`(Get-AuthenticodeSignature '%s').SignerCertificate.Subject`, filePath)
	output, err := runPowerShellCommand(cmd)
	if err != nil {
		return ""
	}

	// Parse CN= from subject
	output = strings.TrimSpace(output)
	for _, part := range strings.Split(output, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "CN=") {
			return strings.TrimPrefix(part, "CN=")
		}
	}

	return output
}

// IsSignerTrusted checks if the signer is in our trusted publishers list
func IsSignerTrusted(signer string) bool {
	if signer == "" {
		return false
	}

	lowerSigner := strings.ToLower(signer)

	// Check against trusted publishers
	for publisher := range trustedPublishers {
		if strings.Contains(lowerSigner, publisher) {
			return true
		}
	}

	// Also trust Microsoft/Windows signed
	if strings.Contains(lowerSigner, "microsoft") ||
		strings.Contains(lowerSigner, "windows") {
		return true
	}

	return false
}

// IsExecutableTrusted is the main function to check if a process/file is legitimate
// Verification order: System Path -> Known JIT -> Signature -> Online Hash Check
func IsExecutableTrusted(execPath string) (bool, string) {
	// Skip if path is empty
	if execPath == "" {
		return false, "empty path"
	}

	// Normalize path
	execPath = strings.Trim(execPath, `"`)

	// If path has arguments, extract just the exe
	if idx := strings.Index(strings.ToLower(execPath), ".exe"); idx != -1 {
		execPath = execPath[:idx+4]
	}

	// Expand environment variables
	execPath = os.ExpandEnv(execPath)

	// Convert to lowercase for comparison
	lowerPath := strings.ToLower(execPath)
	lowerName := strings.ToLower(filepath.Base(execPath))

	// STEP 0: Whitelist system directories (Windows, System32, etc.)
	// These are protected by Windows and can be trusted
	systemPaths := []string{
		"c:\\windows\\system32",
		"c:\\windows\\syswow64",
		"c:\\windows\\winsxs",
		"c:\\windows\\explorer.exe",
		"c:\\program files\\",
		"c:\\program files (x86)\\",
	}

	for _, sp := range systemPaths {
		if strings.HasPrefix(lowerPath, sp) {
			return true, "system path"
		}
	}

	// STEP 0.5: Known JIT applications that use RWX legitimately
	jitApps := []string{
		"chrome", "msedge", "firefox", "brave", "zen", "opera",
		"powershell", "pwsh", "node", "java", "javaw",
		"code", "devenv", "antigravity", "cursor",
		"discord", "slack", "spotify", "teams",
		"dotnet", "python", "ruby", "go", "rustc",
		"vmmem", "vmware", "virtualbox",
	}

	for _, jit := range jitApps {
		if strings.Contains(lowerName, jit) {
			return true, "known JIT application"
		}
	}

	// Check if file exists
	if _, err := os.Stat(execPath); os.IsNotExist(err) {
		// Try to find in PATH or Program Files
		execPath = findExecutable(execPath)
		if execPath == "" {
			return false, "file not found"
		}
	}

	// Step 1: Verify digital signature
	sigInfo := VerifySignature(execPath)

	if sigInfo.IsSigned && sigInfo.IsValid && sigInfo.IsTrusted {
		return true, fmt.Sprintf("trusted signer: %s", sigInfo.Signer)
	}

	// Step 2: Online Hash Intelligence Check
	// Even if not signed or signed by unknown, check hash databases
	verdict := checkOnlineHash(execPath)

	if verdict.IsKnownBad {
		// MALWARE DETECTED!
		return false, fmt.Sprintf("MALWARE: %s (Source: %s)", verdict.MalwareName, verdict.Source)
	}

	if verdict.IsKnownGood {
		// Known good from NIST NSRL
		return true, fmt.Sprintf("known good: %s", verdict.Source)
	}

	// Step 3: If signed but not in trusted list, still trust it
	if sigInfo.IsSigned && sigInfo.IsValid {
		return true, fmt.Sprintf("signed by: %s", sigInfo.Signer)
	}

	// Unknown: Not signed, not in malware DB, not in NSRL
	if !sigInfo.IsSigned {
		return false, "unsigned"
	}

	return false, sigInfo.ErrorMessage
}

// HashVerdict for online check result
type HashVerdict struct {
	IsKnownBad  bool
	IsKnownGood bool
	MalwareName string
	Source      string
}

// checkOnlineHash performs online hash verification
func checkOnlineHash(filePath string) HashVerdict {
	verdict := HashVerdict{}

	// Calculate file hash
	hash, err := calculateFileSHA256(filePath)
	if err != nil {
		return verdict
	}

	// Check MalwareBazaar first (is it bad?)
	isBad, malwareName := checkMalwareBazaarAPI(hash)
	if isBad {
		verdict.IsKnownBad = true
		verdict.MalwareName = malwareName
		verdict.Source = "MalwareBazaar"
		return verdict
	}

	// Check Circl.lu NSRL (is it known good?)
	isGood, source := checkCirclLuAPI(hash)
	if isGood {
		verdict.IsKnownGood = true
		verdict.Source = source
		return verdict
	}

	return verdict
}

// calculateFileSHA256 computes SHA256 hash
func calculateFileSHA256(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// checkMalwareBazaarAPI checks abuse.ch MalwareBazaar
// API Key provided for better access
func checkMalwareBazaarAPI(sha256Hash string) (bool, string) {
	client := &http.Client{Timeout: 5 * time.Second}

	data := url.Values{}
	data.Set("query", "get_info")
	data.Set("hash", sha256Hash)

	req, err := http.NewRequest("POST", "https://mb-api.abuse.ch/api/v1/", strings.NewReader(data.Encode()))
	if err != nil {
		return false, ""
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("API-KEY", "bbc8603b16431ec877bfaa92fb0d45d9bd2705c1951d1798")
	req.Header.Set("User-Agent", "Arakne-EDR/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return false, ""
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var result struct {
		QueryStatus string `json:"query_status"`
		Data        []struct {
			Signature string `json:"signature"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return false, ""
	}

	if result.QueryStatus == "ok" && len(result.Data) > 0 {
		sig := result.Data[0].Signature
		if sig == "" {
			sig = "Generic Malware"
		}
		return true, sig
	}

	return false, ""
}

// checkCirclLuAPI checks NIST NSRL via Circl.lu (FREE, NO KEY REQUIRED)
// Rate limit: IP-based, adding delay between requests recommended
func checkCirclLuAPI(sha256Hash string) (bool, string) {
	client := &http.Client{Timeout: 5 * time.Second}

	req, err := http.NewRequest("GET", fmt.Sprintf("https://hashlookup.circl.lu/lookup/sha256/%s", sha256Hash), nil)
	if err != nil {
		return false, ""
	}
	req.Header.Set("User-Agent", "Arakne-EDR/1.0")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return false, ""
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		body, _ := io.ReadAll(resp.Body)
		var result struct {
			Vendor      string `json:"vendor"`
			ProductName string `json:"ProductName"`
		}
		if json.Unmarshal(body, &result) == nil && result.Vendor != "" {
			return true, fmt.Sprintf("NSRL (%s)", result.Vendor)
		}
		return true, "NSRL (Known Good)"
	}

	return false, ""
}

// findExecutable tries to locate an executable
func findExecutable(name string) string {
	// Common locations
	locations := []string{
		os.Getenv("ProgramFiles"),
		os.Getenv("ProgramFiles(x86)"),
		os.Getenv("LocalAppData"),
		os.Getenv("AppData"),
		os.Getenv("SystemRoot") + "\\System32",
	}

	baseName := filepath.Base(name)

	for _, loc := range locations {
		if loc == "" {
			continue
		}
		// Walk first level looking for the file
		matches, _ := filepath.Glob(filepath.Join(loc, "*", baseName))
		if len(matches) > 0 {
			return matches[0]
		}
		// Direct check
		direct := filepath.Join(loc, baseName)
		if _, err := os.Stat(direct); err == nil {
			return direct
		}
	}

	return ""
}

// runPowerShellCommand runs a PowerShell command and returns output
func runPowerShellCommand(cmd string) (string, error) {
	psCmd := syscall.NewLazyDLL("shell32.dll")
	_ = psCmd // Placeholder

	// Use exec.Command equivalent via os/exec reimplementation
	// For simplicity, we use a file-based approach

	// Create temp script
	tmpFile := os.TempDir() + "\\arakne_sig_check.ps1"
	script := fmt.Sprintf(`$ErrorActionPreference='SilentlyContinue'; %s`, cmd)
	os.WriteFile(tmpFile, []byte(script), 0644)
	defer os.Remove(tmpFile)

	// Execute and capture output
	outputFile := os.TempDir() + "\\arakne_sig_output.txt"
	defer os.Remove(outputFile)

	// Run PowerShell
	execCmd := fmt.Sprintf(`powershell -NoProfile -ExecutionPolicy Bypass -File "%s" > "%s"`, tmpFile, outputFile)

	cmdPtr, _ := syscall.UTF16PtrFromString(execCmd)

	var si syscall.StartupInfo
	var pi syscall.ProcessInformation
	si.Cb = uint32(unsafe.Sizeof(si))
	si.Flags = syscall.STARTF_USESHOWWINDOW
	si.ShowWindow = 0 // SW_HIDE

	err := syscall.CreateProcess(
		nil,
		cmdPtr,
		nil,
		nil,
		false,
		0x08000000, // CREATE_NO_WINDOW
		nil,
		nil,
		&si,
		&pi,
	)

	if err != nil {
		return "", err
	}

	syscall.WaitForSingleObject(pi.Process, syscall.INFINITE)
	syscall.CloseHandle(pi.Process)
	syscall.CloseHandle(pi.Thread)

	// Read output
	data, err := os.ReadFile(outputFile)
	if err != nil {
		return "", err
	}

	return string(data), nil
}
