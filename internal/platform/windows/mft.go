package windows

import (
	"encoding/binary"
	"fmt"
	"syscall"
	"arakne/internal/core"
)

// MFTScanner implements the Scanner interface for NTFS Master File Table analysis
type MFTScanner struct {
	DriveLetter string
	handle      syscall.Handle
	mftOffset   int64
	recordSize  uint32
	bytesPerCluster uint32
}

func NewMFTScanner(drive string) *MFTScanner {
	return &MFTScanner{
		DriveLetter: drive,
	}
}

func (m *MFTScanner) Name() string {
	return "NTFS MFT Analyzer"
}

// NTFS Boot Sector Structure (Partial)
type BootSector struct {
	JumpInstruction      [3]byte
	OEMID               [8]byte
	BytesPerSector      uint16
	SectorsPerCluster   uint8
	ReservedSectors     uint16
	MediaDescriptor     uint8
	test                uint16
	SectorsPerTrack     uint16
	NumberofHeads       uint16
	HiddenSectors       uint32
	TotalSectors        uint64
	MFTClusterNumber    uint64
	MFTMirrClusterNumber uint64
	ClustersPerRecord   int8
}

// MFT Record Header
type MFTFileRecordHeader struct {
	Signature       [4]byte // "FILE"
	UpdateSeqOffset uint16
	UpdateSeqSize   uint16
	LogFileSeqNum   uint64
	SequenceNumber  uint16
	HardLinkCount   uint16
	AttributeOffset uint16
	Flags           uint16 // 0x01 = InUse, 0x02 = Directory
	RealSize        uint32
	AllocatedSize   uint32
	BaseRecordRef   uint64
	NextAttrID      uint16
	// ... padding
}

// MFT Attribute Header (Common)
type AttributeHeader struct {
	TypeCode        uint32
	Length          uint32
	NonResident     uint8
	NameLength      uint8
	NameOffset      uint16
	Flags           uint16
	AttributeID     uint16
}

// Resident Attribute Header
type ResidentAttribute struct {
	AttributeHeader
	ContentSize     uint32
	ContentOffset   uint16
	IndexedFlag     uint8
	Padding         uint8
}

// Non-Resident Attribute Header
type NonResidentAttribute struct {
	AttributeHeader
	StartVCN        uint64
	EndVCN          uint64
	RunListOffset   uint16
	Compression     uint16
	Padding         uint32
	AllocatedSize   uint64
	RealSize        uint64
	InitializedSize uint64
}

const (
	AttrStandardInformation = 0x10
	AttrFileName            = 0x30
	AttrData                = 0x80
)

func (m *MFTScanner) Run() ([]core.Threat, error) {
	volumePath := fmt.Sprintf("\\\\.\\%s", m.DriveLetter) // e.g., \\.\C:
	fmt.Printf("[*] Opening raw volume: %s\n", volumePath)

	handle, err := OpenRawVolume(volumePath)
	if err != nil {
		fmt.Printf("[-] Failed to open volume: %v (Are you Admin?)\n", err)
		return nil, err
	}
	defer CloseHandle(handle)

	// 1. Read Boot Sector (First 512 bytes)
	bootBuffer := make([]byte, 512)
	bytesRead, err := ReadRawBytes(handle, bootBuffer)
	if err != nil || bytesRead != 512 {
		return nil, fmt.Errorf("failed to read boot sector: %v", err)
	}

	var bootSector BootSector
	// Determine formatting manually or use binary.Read
	// Be careful with struct packing/alignment in Go. 
	// For simplicity, we parse fields manually from the buffer to avoid padding issues.
	
	bootSector.BytesPerSector = binary.LittleEndian.Uint16(bootBuffer[11:13])
	bootSector.SectorsPerCluster = bootBuffer[13]
	bootSector.TotalSectors = binary.LittleEndian.Uint64(bootBuffer[40:48]) // For NTFS, this might be at offset 0x28
	bootSector.MFTClusterNumber = binary.LittleEndian.Uint64(bootBuffer[48:56])
	
	// Quick Check for NTFS signature 'NTFS    ' at offset 3
	if string(bootBuffer[3:7]) != "NTFS" {
		return nil, fmt.Errorf("volume is not NTFS")
	}

	clusterSize := uint64(bootSector.BytesPerSector) * uint64(bootSector.SectorsPerCluster)
	mftOffset := bootSector.MFTClusterNumber * clusterSize

	fmt.Printf("[+] NTFS Detected. MFT Start Cluster: %d, Offset: %d\n", bootSector.MFTClusterNumber, mftOffset)
	recordSize := 1024

	// 3. Store critical MFT info in struct for reuse
	m.handle = handle
	m.mftOffset = int64(mftOffset)
	m.recordSize = uint32(recordSize)
	m.bytesPerCluster = uint32(clusterSize)

	fmt.Println("[+] Successfully connected to $MFT.")
	
	// Example: Read Record 0 ($MFT)
	record0, err := m.ReadMFTRecord(0)
	if err != nil {
		return nil, err
	}
	m.ParseRecord(record0)

	return []core.Threat{}, nil
}

// ReadMFTRecord reads a specific record index (e.g., 0 for $MFT, 5 for $Root)
func (m *MFTScanner) ReadMFTRecord(index uint64) ([]byte, error) {
	if m.handle == 0 {
		return nil, fmt.Errorf("volume not opened")
	}

	offset := m.mftOffset + int64(index)*int64(m.recordSize)
	
	_, err := SetFilePointer(m.handle, offset, 0) // FILE_BEGIN
	if err != nil {
		return nil, err
	}

	buffer := make([]byte, m.recordSize)
	_, err = ReadRawBytes(m.handle, buffer)
	if err != nil {
		return nil, err
	}
	
	// Basic validation
	if string(buffer[:4]) != "FILE" {
		// Valid records start with FILE. Empty ones might be 0000.
		// return nil, fmt.Errorf("invalid record signature at index %d", index)
	}
	
	return buffer, nil
}

func (m *MFTScanner) ParseRecord(recordBuffer []byte) {
	fmt.Println("--- MFT Record Dump ---")

	fmt.Println("[+] Successfully read MFT Record 0 ($MFT). System is reachable via RAW access.")

	// Parse Attributes
	attrOffset := binary.LittleEndian.Uint16(recordBuffer[20:22]) // AttributeOffset
	fmt.Printf("[*] First Attribute Offset: %d\n", attrOffset)

	for int(attrOffset)+8 < len(recordBuffer) {
		typeCode := binary.LittleEndian.Uint32(recordBuffer[attrOffset : attrOffset+4])
		if typeCode == 0xFFFFFFFF {
			break // End of attributes
		}
		
		length := binary.LittleEndian.Uint32(recordBuffer[attrOffset+4 : attrOffset+8])
		if length == 0 {
			break // Prevention of infinite loop
		}

		fmt.Printf("   -> Found Attribute: Type 0x%X, Length %d\n", typeCode, length)
		
		// Handle Specific Attributes
		if typeCode == AttrFileName {
			// Parse Name (Resident)
			// Offset to content: 20 + 2 = 22 (usually)
			// Assuming Resident, header is 24 bytes total roughly.
			// Let's rely on standard offset logic for Resident Header.
			resOffset := binary.LittleEndian.Uint16(recordBuffer[attrOffset+20 : attrOffset+22])
			nameContentOffset := int(attrOffset) + int(resOffset)
			
			if nameContentOffset < len(recordBuffer) {
				// $FILE_NAME struct: ParentRef(8) + Creation(8)... + NameLen(1) + NameType(1) + Name
				nameLen := recordBuffer[nameContentOffset+64]
				
				// Basic UTF16LE decoding (just taking every 2nd byte for ASCII for now)
				nameBytes := recordBuffer[nameContentOffset+66 : nameContentOffset+66+int(nameLen)*2]
				readableName := ""
				for i := 0; i < len(nameBytes); i+=2 {
					readableName += string(nameBytes[i])
				}
				fmt.Printf("      [NAME] %s\n", readableName)
			}
		}

		if typeCode == AttrData {
			nonResident := recordBuffer[attrOffset+8]
			if nonResident == 0 {
				fmt.Println("      [$DATA] Resident (Content inside MFT)")
			} else {
				// Runs are at runListOffset
				runListOffset := binary.LittleEndian.Uint16(recordBuffer[attrOffset+32 : attrOffset+34])
				fmt.Printf("      [$DATA] Non-Resident. Runs @ %d\n", runListOffset)
				
				runListStart := int(attrOffset) + int(runListOffset)
				if runListStart < len(recordBuffer)  {
					runListBuffer := recordBuffer[runListStart:] 
					runs, err := parseRunList(runListBuffer)
					if err == nil {
						fmt.Printf("      [RUNS] Decoded %d Fragments:\n", len(runs))
						for i, r := range runs {
							fmt.Printf("        %d. LCN: %d, Len: %d Clusters\n", i+1, r.LCN, r.Length)
						}
					}
				}
			}
		}

		attrOffset += uint16(length)
	}

	// ...
	// End of function

}

// Decode Data Runs (Non-Resident Attribute mapping)
// RunList is a stream of compressed byte-pairs: [Header][Length][Offset]
func parseRunList(runList []byte) ([]DataRun, error) {
	var runs []DataRun
	var currentLCN int64 = 0 // Relative LCN
	offset := 0

	for offset < len(runList) {
		header := runList[offset]
		if header == 0 {
			break // padded end
		}
		offset++

		// Header is packed: (High 4 bits = Length of Offset field) | (Low 4 bits = Length of Length field)
		lenByteCount := int(header & 0x0F)
		offsetByteCount := int((header >> 4) & 0x0F)

		if offset+lenByteCount+offsetByteCount > len(runList) {
			return nil, fmt.Errorf("run list corruption")
		}

		// Read Length (Number of Clusters)
		lengthVal := readVarInt(runList[offset : offset+lenByteCount])
		offset += lenByteCount

		// Read Offset (LCN difference)
		// This is a signed value!
		offsetVal := readVarIntSigned(runList[offset : offset+offsetByteCount])
		offset += offsetByteCount

		currentLCN += offsetVal

		runs = append(runs, DataRun{
			StartVCN: 0, // Simplified, caller tracks VCN
			LCN:      currentLCN,
			Length:   uint64(lengthVal),
		})
	}
	return runs, nil
}

type DataRun struct {
	StartVCN uint64
	LCN      int64 // Logical Cluster Number (on volume)
	Length   uint64 // Number of clusters
}

func readVarInt(b []byte) uint64 {
	var val uint64
	for i := 0; i < len(b); i++ {
		val |= uint64(b[i]) << (uint(i) * 8)
	}
	return val
}

func readVarIntSigned(b []byte) int64 {
	// Sign-extension is tricky for variable length
	var val int64
	for i := 0; i < len(b); i++ {
		val |= int64(b[i]) << (uint(i) * 8)
	}
	
	// If the highest bit of the last byte is set, it's negative
	if len(b) > 0 && (b[len(b)-1]&0x80 != 0) {
		mask := int64(-1) << (uint(len(b)) * 8)
		val |= mask
	}
	return val
}
