package windows

import (
	"arakne/internal/core"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"

	"golang.org/x/sys/windows/registry"
)

// ShimCacheParser analyzes Application Compatibility Cache
type ShimCacheParser struct {
	Entries []ShimCacheEntry
}

type ShimCacheEntry struct {
	Path         string
	LastModified time.Time
	ExecFlag     bool
}

func NewShimCacheParser() *ShimCacheParser {
	return &ShimCacheParser{}
}

func (s *ShimCacheParser) Name() string {
	return "ShimCache (AppCompatCache) Analyzer"
}

func (s *ShimCacheParser) Run() ([]core.Threat, error) {
	fmt.Println("[*] Parsing AppCompatCache (Shimcache)...")
	threats := []core.Threat{}

	// Read from registry
	entries, err := s.readAppCompatCache()
	if err != nil {
		fmt.Printf("    [-] Failed to read AppCompatCache: %v\n", err)
		return threats, err
	}

	s.Entries = entries
	fmt.Printf("[+] Parsed %d shimcache entries.\n", len(entries))

	// Analyze for suspicious entries
	susPatterns := []string{
		"\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\",
		"psexec", "mimikatz", "procdump", "wce", "gsecdump",
		"\\public\\", "\\downloads\\",
	}

	for _, entry := range entries {
		lower := strings.ToLower(entry.Path)
		for _, pattern := range susPatterns {
			if strings.Contains(lower, pattern) {
				threats = append(threats, core.Threat{
					Name:        "Suspicious Shimcache Entry",
					Description: fmt.Sprintf("Execution evidence: %s", entry.Path),
					Level:       core.LevelMedium,
					FilePath:    entry.Path,
					Details: map[string]interface{}{
						"lastModified": entry.LastModified.String(),
						"executed":     entry.ExecFlag,
					},
				})
				break
			}
		}
	}

	return threats, nil
}

func (s *ShimCacheParser) readAppCompatCache() ([]ShimCacheEntry, error) {
	entries := []ShimCacheEntry{}

	// Open AppCompatCache registry key
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`,
		registry.QUERY_VALUE)
	if err != nil {
		return entries, fmt.Errorf("cannot open AppCompatCache key: %v", err)
	}
	defer key.Close()

	// Read the binary data
	data, _, err := key.GetBinaryValue("AppCompatCache")
	if err != nil {
		return entries, fmt.Errorf("cannot read AppCompatCache value: %v", err)
	}

	if len(data) < 128 {
		return entries, fmt.Errorf("AppCompatCache data too small")
	}

	// Parse header (Windows 10 format)
	// Signature at offset 0 should be 0x30 (Win10) or 0xEE/0xEF (Win7/8)
	signature := binary.LittleEndian.Uint32(data[0:4])

	switch signature {
	case 0x30, 0x34: // Windows 10
		entries = s.parseWin10Format(data)
	case 0xEE, 0xEF: // Windows 7/8
		entries = s.parseWin7Format(data)
	default:
		fmt.Printf("    [!] Unknown shimcache signature: 0x%X\n", signature)
	}

	return entries, nil
}

func (s *ShimCacheParser) parseWin10Format(data []byte) []ShimCacheEntry {
	entries := []ShimCacheEntry{}

	// Windows 10 format: header is 48 bytes
	offset := 48
	maxEntries := 500

	for i := 0; i < maxEntries && offset < len(data)-12; i++ {
		// Each entry: signature (4) + unknown (4) + data_size (4) + path_size (2)
		if offset+12 > len(data) {
			break
		}

		sig := binary.LittleEndian.Uint32(data[offset : offset+4])
		if sig != 0x73746310 { // "10ts" signature
			offset += 4
			continue
		}

		if offset+12 > len(data) {
			break
		}

		pathSize := int(binary.LittleEndian.Uint16(data[offset+8 : offset+10]))
		if pathSize == 0 || pathSize > 1024 || offset+12+pathSize > len(data) {
			offset += 4
			continue
		}

		// Extract path (UTF-16LE)
		pathBytes := data[offset+12 : offset+12+pathSize]
		path := decodeUTF16(pathBytes)

		if path != "" && len(path) > 3 {
			entries = append(entries, ShimCacheEntry{
				Path:     path,
				ExecFlag: true, // Win10 doesn't store this separately
			})
		}

		offset += 12 + pathSize + 8 // Move to next entry
	}

	return entries
}

func (s *ShimCacheParser) parseWin7Format(data []byte) []ShimCacheEntry {
	entries := []ShimCacheEntry{}

	// Windows 7 format: header is 128 bytes, then entries
	numEntries := binary.LittleEndian.Uint32(data[4:8])
	if numEntries > 1024 {
		numEntries = 1024
	}

	offset := 128
	for i := uint32(0); i < numEntries && offset < len(data)-32; i++ {
		pathLen := int(binary.LittleEndian.Uint16(data[offset : offset+2]))
		if pathLen > 520 || offset+8+pathLen > len(data) {
			break
		}

		pathOffset := int(binary.LittleEndian.Uint32(data[offset+4 : offset+8]))
		if pathOffset < len(data) && pathOffset+pathLen <= len(data) {
			pathBytes := data[pathOffset : pathOffset+pathLen]
			path := decodeUTF16(pathBytes)
			if path != "" {
				entries = append(entries, ShimCacheEntry{Path: path})
			}
		}

		offset += 32 // Fixed entry size for Win7
	}

	return entries
}

func decodeUTF16(b []byte) string {
	if len(b) < 2 {
		return ""
	}

	u16 := make([]uint16, len(b)/2)
	for i := 0; i < len(u16); i++ {
		u16[i] = binary.LittleEndian.Uint16(b[i*2:])
	}

	// Remove null terminator
	for i, v := range u16 {
		if v == 0 {
			u16 = u16[:i]
			break
		}
	}

	return string(utf16.Decode(u16))
}
