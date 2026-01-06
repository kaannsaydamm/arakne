package linux

import (
	"arakne/internal/core"
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
)

// MemfdHunter detects fileless malware using memfd_create
type MemfdHunter struct {
	Threats []core.Threat
}

func NewMemfdHunter() *MemfdHunter {
	return &MemfdHunter{}
}

func (m *MemfdHunter) Name() string {
	return "Memfd Fileless Malware Hunter"
}

func (m *MemfdHunter) Run() ([]core.Threat, error) {
	fmt.Println("[*] Scanning for memfd-based fileless malware...")
	m.Threats = []core.Threat{}

	// Scan all processes
	files, err := ioutil.ReadDir("/proc")
	if err != nil {
		return m.Threats, err
	}

	for _, f := range files {
		pid, err := strconv.Atoi(f.Name())
		if err != nil {
			continue
		}

		m.scanProcessMaps(pid)
		m.scanProcessFDs(pid)
	}

	fmt.Printf("[+] Memfd scan complete. Found %d suspicious regions.\n", len(m.Threats))
	return m.Threats, nil
}

func (m *MemfdHunter) scanProcessMaps(pid int) {
	mapsPath := fmt.Sprintf("/proc/%d/maps", pid)
	file, err := os.Open(mapsPath)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		// Look for memfd mappings
		// Format: address perms offset dev inode pathname
		// memfd shows as /memfd:name (deleted) or just memfd:
		if strings.Contains(line, "memfd:") {
			perms := ""
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				perms = parts[1]
			}

			// Check for executable memfd (very suspicious)
			if strings.Contains(perms, "x") {
				m.Threats = append(m.Threats, core.Threat{
					Name:        "Executable Memfd Region",
					Description: fmt.Sprintf("PID %d has executable memfd mapping", pid),
					Level:       core.LevelCritical,
					Details: map[string]interface{}{
						"pid":   pid,
						"perms": perms,
						"line":  line,
					},
				})
			}
		}

		// Also check for anonymous executable regions (RWX)
		if strings.Contains(line, "rwxp") && !strings.Contains(line, "/") {
			m.Threats = append(m.Threats, core.Threat{
				Name:        "Anonymous RWX Region",
				Description: fmt.Sprintf("PID %d has anonymous RWX memory (possible shellcode)", pid),
				Level:       core.LevelHigh,
				Details: map[string]interface{}{
					"pid":  pid,
					"line": line,
				},
			})
		}
	}
}

func (m *MemfdHunter) scanProcessFDs(pid int) {
	fdPath := fmt.Sprintf("/proc/%d/fd", pid)
	fds, err := ioutil.ReadDir(fdPath)
	if err != nil {
		return
	}

	for _, fd := range fds {
		linkPath := fmt.Sprintf("/proc/%d/fd/%s", pid, fd.Name())
		target, err := os.Readlink(linkPath)
		if err != nil {
			continue
		}

		// Check for memfd file descriptors
		if strings.HasPrefix(target, "/memfd:") {
			m.Threats = append(m.Threats, core.Threat{
				Name:        "Memfd File Descriptor",
				Description: fmt.Sprintf("PID %d has open memfd: %s", pid, target),
				Level:       core.LevelHigh,
				Details: map[string]interface{}{
					"pid":    pid,
					"fd":     fd.Name(),
					"target": target,
				},
			})
		}

		// Check for deleted files still open
		if strings.Contains(target, "(deleted)") && !strings.Contains(target, ".so") {
			m.Threats = append(m.Threats, core.Threat{
				Name:        "Deleted File Handle",
				Description: fmt.Sprintf("PID %d has open handle to deleted file: %s", pid, target),
				Level:       core.LevelMedium,
				Details: map[string]interface{}{
					"pid":    pid,
					"target": target,
				},
			})
		}
	}
}
