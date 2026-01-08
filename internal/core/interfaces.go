package core

// ThreatLevel defines the severity of a finding
type ThreatLevel int

const (
	LevelInfo ThreatLevel = iota
	LevelLow
	LevelMedium
	LevelSuspicious
	LevelHigh
	LevelMalicious
	LevelCritical
)

// ThreatType defines the category of the threat
type ThreatType int

const (
	ThreatTypeFile     ThreatType = iota // Default
	ThreatTypeProcess                    // Running Process
	ThreatTypeRegistry                   // Registry Key/Value
	ThreatTypeConfig                     // System Configuration (BIOS/UEFI)
)

// Threat represents a detected security issue
type Threat struct {
	Name        string
	Description string
	FilePath    string
	FileHash    string // SHA256
	Level       ThreatLevel
	Type        ThreatType
	Score       int // 0-100
	Details     map[string]interface{}
}

// Scanner is the interface that all detection modules must implement
type Scanner interface {
	Name() string
	Run() ([]Threat, error)
}

// Remediator is the interface for fixing/cleaning threats
type Remediator interface {
	Name() string
	Remediate(threat Threat) error
	Rollback() error
}

// EvidenceBag defines how artifacts are collected for forensic analysis
type EvidenceBag interface {
	Collect(path string) error
	Seal() (string, error) // Returns path to the sealed zip/container
}
