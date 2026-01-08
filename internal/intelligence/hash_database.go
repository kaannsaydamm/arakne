package intelligence

import (
	"arakne/internal/core"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// HashDatabase manages local cache of known-good and known-bad hashes
type HashDatabase struct {
	KnownGood   map[string]string `json:"known_good"` // hash -> description
	KnownBad    map[string]string `json:"known_bad"`  // hash -> malware name
	LastUpdated time.Time         `json:"last_updated"`
	Version     string            `json:"version"`
	mutex       sync.RWMutex
	cacheFile   string
	isOnline    bool
}

var GlobalDB *HashDatabase

// InitHashDatabase initializes the hash database with auto-update
func InitHashDatabase() *HashDatabase {
	db := &HashDatabase{
		KnownGood: make(map[string]string),
		KnownBad:  make(map[string]string),
		Version:   "1.0",
	}

	// Set cache file path
	db.cacheFile = filepath.Join(core.IntelligenceDir, "hash_database.json")

	// Try to update from online sources
	if db.checkInternet() {
		fmt.Println("[*] Internet connection detected. Updating hash database...")
		db.isOnline = true
		db.updateFromOnline()
	} else {
		fmt.Println("[!] No internet. Using cached hash database...")
		db.isOnline = false
		db.loadFromCache()
	}

	GlobalDB = db

	// Launch background update for large datasets (MalwareBazaar)
	if db.isOnline {
		UpdateMalwareBazaar(db)
	}

	return db
}

// checkInternet tests if internet is available
func (db *HashDatabase) checkInternet() bool {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("https://hashlookup.circl.lu/info")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}

// updateFromOnline downloads fresh hash data from CIRCL
func (db *HashDatabase) updateFromOnline() {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	// Get database info from CIRCL
	client := &http.Client{Timeout: 30 * time.Second}

	// Get CIRCL database info
	resp, err := client.Get("https://hashlookup.circl.lu/info")
	if err != nil {
		fmt.Printf("[!] Failed to fetch CIRCL info: %v\n", err)
		db.loadFromCacheUnsafe()
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var info struct {
		NSRLSha256Count int    `json:"nsrl-sha256-count"`
		TotalEntries    int    `json:"total-entries"`
		Version         string `json:"version"`
	}
	json.Unmarshal(body, &info)

	// Update version info
	db.Version = fmt.Sprintf("CIRCL-NSRL-%s", info.Version)
	db.LastUpdated = time.Now()

	fmt.Printf("[+] CIRCL Database: %d SHA256 entries\n", info.NSRLSha256Count)

	// For efficiency, we don't download the entire database
	// Instead, we rely on real-time API lookups
	// But we cache our lookup results locally

	// Load any existing cache and merge
	db.loadFromCacheUnsafe()

	// Save updated cache
	db.saveToCacheUnsafe()

	fmt.Printf("[+] Hash database updated. Version: %s\n", db.Version)
}

// loadFromCache loads the database from local cache
func (db *HashDatabase) loadFromCache() {
	db.mutex.Lock()
	defer db.mutex.Unlock()
	db.loadFromCacheUnsafe()
}

// loadFromCacheUnsafe loads without locking (internal use)
func (db *HashDatabase) loadFromCacheUnsafe() {
	data, err := os.ReadFile(db.cacheFile)
	if err != nil {
		fmt.Println("[i] No cache file found. Starting fresh.")
		return
	}

	var cached HashDatabase
	if err := json.Unmarshal(data, &cached); err != nil {
		fmt.Printf("[!] Cache file corrupted: %v\n", err)
		return
	}

	db.KnownGood = cached.KnownGood
	db.KnownBad = cached.KnownBad
	db.LastUpdated = cached.LastUpdated
	db.Version = cached.Version

	if db.KnownGood == nil {
		db.KnownGood = make(map[string]string)
	}
	if db.KnownBad == nil {
		db.KnownBad = make(map[string]string)
	}

	fmt.Printf("[+] Loaded %d known-good, %d known-bad hashes from cache\n",
		len(db.KnownGood), len(db.KnownBad))
	fmt.Printf("[i] Cache version: %s (Updated: %s)\n",
		db.Version, db.LastUpdated.Format("2006-01-02 15:04"))
}

// saveToCacheUnsafe saves to cache without locking
func (db *HashDatabase) saveToCacheUnsafe() {
	data, err := json.MarshalIndent(db, "", "  ")
	if err != nil {
		return
	}
	os.WriteFile(db.cacheFile, data, 0644)
}

// SaveToCache saves the current database to cache
func (db *HashDatabase) SaveToCache() {
	db.mutex.Lock()
	defer db.mutex.Unlock()
	db.saveToCacheUnsafe()
}

// AddKnownGood adds a hash to the known-good list
func (db *HashDatabase) AddKnownGood(hash, description string) {
	db.mutex.Lock()
	defer db.mutex.Unlock()
	db.KnownGood[hash] = description
	db.saveToCacheUnsafe()
}

// AddKnownBad adds a hash to the known-bad list
func (db *HashDatabase) AddKnownBad(hash, malwareName string) {
	db.mutex.Lock()
	defer db.mutex.Unlock()
	db.KnownBad[hash] = malwareName
	db.saveToCacheUnsafe()
}

// MergeKnownBad adds multiple hashes to known-bad list (efficient)
func (db *HashDatabase) MergeKnownBad(newBad map[string]string) {
	db.mutex.Lock()
	defer db.mutex.Unlock()
	for k, v := range newBad {
		db.KnownBad[k] = v
	}
	db.LastUpdated = time.Now()
	// Don't save immediately if huge, or save manually?
	// We'll save.
	db.saveToCacheUnsafe()
}

// IsKnownGood checks if a hash is in the known-good list
func (db *HashDatabase) IsKnownGood(hash string) (bool, string) {
	db.mutex.RLock()
	defer db.mutex.RUnlock()
	if desc, ok := db.KnownGood[hash]; ok {
		return true, desc
	}
	return false, ""
}

// IsKnownBad checks if a hash is in the known-bad list
func (db *HashDatabase) IsKnownBad(hash string) (bool, string) {
	db.mutex.RLock()
	defer db.mutex.RUnlock()
	if name, ok := db.KnownBad[hash]; ok {
		return true, name
	}
	return false, ""
}

// ClearCache clears the hash database cache
func (db *HashDatabase) ClearCache() {
	db.mutex.Lock()
	defer db.mutex.Unlock()
	db.KnownGood = make(map[string]string)
	db.KnownBad = make(map[string]string)
	os.Remove(db.cacheFile)
	fmt.Println("[+] Hash database cache cleared.")
}

// LookupHashOnline queries the CIRCL Hash Lookup API for a given SHA256 hash.
func (db *HashDatabase) LookupHashOnline(hash string) (bool, string) {
	if !db.isOnline {
		return false, ""
	}

	// Rate limiting check (simple sleep for now, better would be token bucket)
	time.Sleep(200 * time.Millisecond)

	url := fmt.Sprintf("https://hashlookup.circl.lu/lookup/sha256/%s", hash)
	resp, err := http.Get(url)
	if err != nil {
		fmt.Printf("    [!] API Error: %v\n", err)
		return false, ""
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		// Not found in clean database
		return false, ""
	}

	if resp.StatusCode == 200 {
		var result struct {
			FileName    string `json:"FileName"`
			ProductName string `json:"ProductName"`
			FileSize    int    `json:"FileSize"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err == nil {
			desc := fmt.Sprintf("%s (%s)", result.FileName, result.ProductName)
			// Cache positive result
			db.AddKnownGood(hash, desc)
			return true, desc
		}
	}

	return false, ""
}

// GetStats returns database statistics
func (db *HashDatabase) GetStats() string {
	db.mutex.RLock()
	defer db.mutex.RUnlock()
	return fmt.Sprintf("Known Good: %d, Known Bad: %d, Version: %s, Updated: %s",
		len(db.KnownGood), len(db.KnownBad), db.Version,
		db.LastUpdated.Format("2006-01-02 15:04"))
}
