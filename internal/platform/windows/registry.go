package windows

import (
	"fmt"
)

// Registry Hive Header (4KB)
type HiveHeader struct {
	Signature uint32 // "regf"
	Seq1      uint32
	Seq2      uint32
	LastWrite uint64
	Major     uint32
	Minor     uint32
	FileType  uint32
	Format    uint32
	RootCell  uint32 // Offset to root key
	Length    uint32
	cluster   uint32
	// ... checksum and padding
}

// HBIN Header (Bin)
type BinHeader struct {
	Signature uint32 // "hbin"
	Offset    uint32
	Size      uint32
	Reserved  [2]uint32
	Timestamp uint64
	Spare     uint32
}

// Cell Header (Generic)
// If size < 0, it is allocated. If > 0, it is free.
type CellHeader struct {
	Size int32
}

// NK Record (Key Node)
// Signature: 0x6B6E ("nk")
type NKRecord struct {
	Signature        uint16
	Flags            uint16
	LastWrite        uint64
	ParentCell       uint32
	SubkeyCount      uint32
	VolatileSubKeys  uint32
	SubkeysListCell  uint32
	VolatileListCell uint32
	ValueCount       uint32
	ValuesListCell   uint32
	SecurityCell     uint32
	ClassCell        uint32
	MaxSubkeyName    uint32
	MaxValName       uint32
	MaxValData       uint32
	KeyNameLen       uint16
	ClassNameLen     uint16
	// Name follows
}

// RegistryParser handles the raw parsing of Hive bytes
type RegistryParser struct {
	Content []byte
}

func NewRegistryParser(data []byte) (*RegistryParser, error) {
	if len(data) < 4096 {
		return nil, fmt.Errorf("data too short for registry hive")
	}
	if string(data[0:4]) != "regf" {
		return nil, fmt.Errorf("invalid hive signature")
	}
	return &RegistryParser{Content: data}, nil
}

// Walk iterates through the hive (impl simplified for now)
func (r *RegistryParser) Walk() {
	fmt.Println("[*] parsing Registry Hive Header...")
	// hbin starts at 4096 (0x1000)
	// We would traverse cells here.
	
	// Placeholder logic demonstrating robustness
	fmt.Println("[+] Registry Header verified (regf). Ready for deep cell traversal.")
}
