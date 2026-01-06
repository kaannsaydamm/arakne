package core

// ThreatLevel defines the severity of a finding
type ThreatLevel int

const (
	LevelInfo ThreatLevel = iota
	LevelSuspicious
	LevelMalicious
	LevelCritical
)

// Threat represents a detected security issue
type Threat struct {
	Name        string
	Description string
	FilePath    string
	Level       ThreatLevel
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
