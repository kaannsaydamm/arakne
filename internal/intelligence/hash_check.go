package intelligence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// HashVerdict represents the result of hash verification
type HashVerdict struct {
	Hash        string
	IsKnownBad  bool   // Found in MalwareBazaar
	IsKnownGood bool   // Found in NIST NSRL (via Circl.lu)
	MalwareName string // If IsKnownBad, the malware family name
	Source      string // Which source gave this result
	Error       string // Any error during lookup
}

// Intelligence manages online hash verification
type Intelligence struct {
	client     *http.Client
	cache      map[string]HashVerdict
	cacheMutex sync.RWMutex
	enabled    bool
}

var Global *Intelligence
// VerifySignatureCallback is a hook for checking digital signatures (set by platform/windows)
var VerifySignatureCallback func(filePath string) (isSigned bool, signer string, err error)

func init() {
	Global = NewIntelligence()
}

func NewIntelligence() *Intelligence {
	return &Intelligence{
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		cache:   make(map[string]HashVerdict),
		enabled: true,
	}
}

// CalculateFileSHA256 computes SHA256 hash of a file
func CalculateFileSHA256(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

// VerifyHash checks a hash against databases
// Tiered Logic:
// 1. Local Whitelist (Fastest) -> If Found & Clean -> PASS
// 2. Certificate Check (Managed by Caller)
// 3. MalwareBazaar (Known Bad / Online) -> If Bad -> NUKE
// 4. Circl.lu (Known Good / NSRL) -> If Good -> PASS
func (i *Intelligence) VerifyHash(sha256Hash string, filePath string) HashVerdict {
	if !i.enabled {
		return HashVerdict{Hash: sha256Hash, Error: "Intelligence disabled"}
	}

	sha256Hash = strings.ToLower(sha256Hash)

	// Memory Cache
	i.cacheMutex.RLock()
	if cached, ok := i.cache[sha256Hash]; ok {
		i.cacheMutex.RUnlock()
		return cached
	}
	i.cacheMutex.RUnlock()

	verdict := HashVerdict{Hash: sha256Hash}

	// --- TIER 1: Local Whitelist (Local DB) ---
	if GlobalDB != nil {
		// If known GOOD in local DB
		if isGood, desc := GlobalDB.IsKnownGood(sha256Hash); isGood {
			verdict.IsKnownGood = true
			verdict.Source = "Tier 1: Local Whitelist (" + desc + ")"
			i.cacheResult(sha256Hash, verdict)
			return verdict // PASS
		}
		// If known BAD in local DB (which comes from MalwareBazaar dump)
		if isBad, name := GlobalDB.IsKnownBad(sha256Hash); isBad {
			verdict.IsKnownBad = true
			verdict.MalwareName = name
			verdict.Source = "Tier 3: MalwareBazaar (Local Cache)"
			i.cacheResult(sha256Hash, verdict)
			return verdict // NUKE
		}
	}

	// --- TIER 2: Certificate Check ---
	// Implemented via Dependency Injection to avoid import cycles.
	if filePath != "" && VerifySignatureCallback != nil {
		isSigned, signer, err := VerifySignatureCallback(filePath)
		if err == nil && isSigned {
			verdict.IsKnownGood = true
			verdict.Source = "Tier 2: Digital Signature (" + signer + ")"
			i.cacheResult(sha256Hash, verdict)
			return verdict // PASS
		}
	}

	// --- TIER 3: MalwareBazaar (Online API) ---
	// Verify against Online MalwareBazaar (if not found in local cache)
	// Actually, our LocalDB *IS* MalwareBazaar dump + Manual additions.
	// Online check is fallback or fresh check?
	// User: "MalwareBazaar (Kötü mü?): Hash'i sor." -> Implies querying MB.
	isBad, malwareName := i.checkMalwareBazaar(sha256Hash)
	if isBad {
		verdict.IsKnownBad = true
		verdict.MalwareName = malwareName
		verdict.Source = "Tier 3: MalwareBazaar (Online)"
		i.cacheResult(sha256Hash, verdict)

		// Add to local DB for future
		if GlobalDB != nil {
			GlobalDB.AddKnownBad(sha256Hash, malwareName)
		}
		return verdict // NUKE
	}

	// --- TIER 4: Circl.lu (Known Good / NSRL) ---
	isGood, prodName := i.checkCirclLU(sha256Hash)
	if isGood {
		verdict.IsKnownGood = true
		verdict.Source = "Tier 4: Circl.lu (NSRL: " + prodName + ")"
		i.cacheResult(sha256Hash, verdict)

		// Add to local DB
		if GlobalDB != nil {
			GlobalDB.AddKnownGood(sha256Hash, prodName)
		}
		return verdict // PASS
	}

	// If nothing found
	verdict.Source = "Unknown"
	i.cacheResult(sha256Hash, verdict)
	return verdict
}

// checkMalwareBazaar queries abuse.ch MalwareBazaar API
// FREE, NO API KEY, NO RATE LIMIT (reasonable use)
func (i *Intelligence) checkMalwareBazaar(sha256 string) (bool, string) {
	apiURL := "https://mb-api.abuse.ch/api/v1/"

	data := url.Values{}
	data.Set("query", "get_info")
	data.Set("hash", sha256)

	req, err := http.NewRequest("POST", apiURL, strings.NewReader(data.Encode()))
	if err != nil {
		return false, ""
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := i.client.Do(req)
	if err != nil {
		return false, ""
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, ""
	}

	// Parse response
	var result struct {
		QueryStatus string `json:"query_status"`
		Data        []struct {
			SHA256Hash     string `json:"sha256_hash"`
			Signature      string `json:"signature"`       // Malware family (e.g., "CobaltStrike")
			DeliveryMethod string `json:"delivery_method"` // How it spreads
			FileName       string `json:"file_name"`
			FileType       string `json:"file_type"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return false, ""
	}

	// hash_not_found = Not in malware database (good sign)
	if result.QueryStatus == "hash_not_found" {
		return false, ""
	}

	// ok = Found! This is MALWARE
	if result.QueryStatus == "ok" && len(result.Data) > 0 {
		signature := result.Data[0].Signature
		if signature == "" {
			signature = "Generic Malware"
		}
		return true, signature
	}

	return false, ""
}

// checkCirclLU queries Circl.lu hashlookup API (NIST NSRL database)
// FREE, NO API KEY, NO RATE LIMIT
// NSRL = National Software Reference Library - known legitimate software
func (i *Intelligence) checkCirclLU(sha256 string) (bool, string) {
	apiURL := fmt.Sprintf("https://hashlookup.circl.lu/lookup/sha256/%s", sha256)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return false, ""
	}
	req.Header.Set("Accept", "application/json")

	resp, err := i.client.Do(req)
	if err != nil {
		return false, ""
	}
	defer resp.Body.Close()

	// 404 = Not found in NSRL (doesn't mean bad, just unknown)
	if resp.StatusCode == 404 {
		return false, ""
	}

	// 200 = Found in NSRL (Known Good Software!)
	if resp.StatusCode == 200 {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return true, "NSRL (Known Good)"
		}

		var result struct {
			FileName     string `json:"FileName"`
			ProductName  string `json:"ProductName"`
			OpSystemCode string `json:"OpSystemCode"`
			Vendor       string `json:"vendor"`
		}

		if err := json.Unmarshal(body, &result); err == nil {
			source := "NSRL"
			if result.Vendor != "" {
				source = fmt.Sprintf("NSRL (%s)", result.Vendor)
			} else if result.ProductName != "" {
				source = fmt.Sprintf("NSRL (%s)", result.ProductName)
			}
			return true, source
		}

		return true, "NSRL (Known Good)"
	}

	return false, ""
}

// cacheResult stores a verdict in cache
func (i *Intelligence) cacheResult(hash string, verdict HashVerdict) {
	i.cacheMutex.Lock()
	defer i.cacheMutex.Unlock()
	i.cache[hash] = verdict
}

// VerifyFile calculates hash and verifies in one step
func (i *Intelligence) VerifyFile(filePath string) HashVerdict {
	hash, err := CalculateFileSHA256(filePath)
	if err != nil {
		return HashVerdict{Error: err.Error()}
	}
	// Pass filePath for Tier 2 check
	return i.VerifyHash(hash, filePath)
}

// Enable enables online intelligence
func (i *Intelligence) Enable() {
	i.enabled = true
}

// Disable disables online intelligence (offline mode)
func (i *Intelligence) Disable() {
	i.enabled = false
}

// ClearCache clears the hash cache
func (i *Intelligence) ClearCache() {
	i.cacheMutex.Lock()
	defer i.cacheMutex.Unlock()
	i.cache = make(map[string]HashVerdict)
}

// PrintVerdict prints a verdict in a human-readable format
func (v HashVerdict) String() string {
	if v.Error != "" {
		return fmt.Sprintf("[ERROR] %s", v.Error)
	}
	if v.IsKnownBad {
		return fmt.Sprintf("[MALWARE] %s (Source: %s)", v.MalwareName, v.Source)
	}
	if v.IsKnownGood {
		return fmt.Sprintf("[CLEAN] Known Good (Source: %s)", v.Source)
	}
	return "[UNKNOWN] Not in any database"
}
