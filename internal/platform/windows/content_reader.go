package windows

import (
	"fmt"
)

// ReadContent reads the actual file data from disk based on runs (Non-Resident)
// size is the real size of the file (or max bytes to read)
func (m *MFTScanner) ReadContent(runs []DataRun, size int64) ([]byte, error) {
	if m.handle == 0 {
		return nil, fmt.Errorf("volume not opened")
	}

	resultBuffer := make([]byte, 0, size)
	bytesRemaining := size
	
	for _, run := range runs {
		if bytesRemaining <= 0 {
			break
		}

		// Calculate run size in bytes
		runSizeBytes := int64(run.Length) * int64(m.bytesPerCluster)
		
		// If LCN is 0, it might be sparse (zeros), but usually LCN 0 is boot sector.
		// Sparse files have specific encoding (negative offset leading to 0? No, just 0 offset sometimes depending on parser)
		// For now assume standard runs.

		// Read the cluster(s)
		// Offset = LCN * BytesPerCluster
		diskOffset := run.LCN * int64(m.bytesPerCluster)
		
		// Determine how much to read from this run
		toRead := runSizeBytes
		if toRead > bytesRemaining {
			toRead = bytesRemaining
		}

		// Seek and Read
		chunk, err := m.readChunks(diskOffset, toRead)
		if err != nil {
			return nil, fmt.Errorf("failed to read run at LCN %d: %v", run.LCN, err)
		}

		resultBuffer = append(resultBuffer, chunk...)
		bytesRemaining -= int64(len(chunk))
	}

	return resultBuffer, nil
}

// readChunks is a helper wrapper around raw ReadFile with seeking
func (m *MFTScanner) readChunks(offset int64, length int64) ([]byte, error) {
	_, err := SetFilePointer(m.handle, offset, 0)
	if err != nil {
		return nil, err
	}

	buffer := make([]byte, length)
	bytesRead, err := ReadRawBytes(m.handle, buffer)
	if err != nil {
		return nil, err
	}

	// It's possible we read less if EOF or error, but raw disk usually returns requested if valid range
	return buffer[:bytesRead], nil
}

// ReadResidentContent extracts data directly from the MFT record buffer
func ReadResidentContent(record []byte, attrOffset uint16, contentOffset uint16, contentSize uint32) []byte {
	start := uint32(attrOffset) + uint32(contentOffset)
	end := start + contentSize
	if end > uint32(len(record)) {
		return nil
	}
	return record[start:end]
}
