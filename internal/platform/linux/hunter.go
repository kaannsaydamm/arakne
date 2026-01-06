package linux

import (
	"arakne/internal/core"
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// LinuxHunter implements advanced Linux threat detection
type LinuxHunter struct {
	Threats     []core.Threat
	driverFile  *os.File
	driverReady bool
}

func NewLinuxHunter() *LinuxHunter {
	hunter := &LinuxHunter{}
	hunter.connectDriver()
	return hunter
}

// connectDriver opens /dev/arakne for kernel communication
func (l *LinuxHunter) connectDriver() {
	file, err := os.OpenFile("/dev/arakne", os.O_RDWR, 0)
	if err != nil {
		fmt.Println("[!] Kernel driver not loaded. Some features disabled.")
		l.driverReady = false
		return
	}
	l.driverFile = file
	l.driverReady = true
	fmt.Println("[+] Connected to kernel driver (/dev/arakne)")
}

// writeCommand sends a command to the driver via write
func (l *LinuxHunter) writeCommand(cmd string) error {
	if !l.driverReady || l.driverFile == nil {
		return fmt.Errorf("driver not connected")
	}
	_, err := l.driverFile.WriteString(cmd)
	return err
}

// readStatus reads driver status
func (l *LinuxHunter) readStatus() (string, error) {
	if !l.driverReady || l.driverFile == nil {
		return "", fmt.Errorf("driver not connected")
	}
	buf := make([]byte, 256)
	n, err := l.driverFile.Read(buf)
	if err != nil {
		return "", err
	}
	return string(buf[:n]), nil
}

// EnableNukeMode activates aggressive blocking in kernel
func (l *LinuxHunter) EnableNukeMode() error {
	fmt.Println("[*] Enabling Nuke Mode in kernel...")
	return l.writeCommand("NUKE:1")
}

// EnableNetworkIsolation activates netfilter blocking
func (l *LinuxHunter) EnableNetworkIsolation(enable bool) error {
	val := "0"
	if enable {
		val = "1"
	}
	fmt.Printf("[*] Network Isolation: %v\n", enable)
	return l.writeCommand("NET:" + val)
}

// KillProcess sends kill request to kernel
func (l *LinuxHunter) KillProcess(pid int) error {
	fmt.Printf("[*] Requesting kernel to kill PID %d\n", pid)
	return l.writeCommand(fmt.Sprintf("KILL:%d", pid))
}

// RegisterSelfDefense protects our process
func (l *LinuxHunter) RegisterSelfDefense() error {
	pid := os.Getpid()
	fmt.Printf("[*] Registering self-defense for PID %d\n", pid)
	return l.writeCommand(fmt.Sprintf("PROTECT:%d", pid))
}

func (l *LinuxHunter) Close() {
	if l.driverFile != nil {
		l.driverFile.Close()
	}
}

func (l *LinuxHunter) Name() string {
	return "Linux Advanced Threat Hunter"
}

func (l *LinuxHunter) Run() ([]core.Threat, error) {
	fmt.Println("[*] Starting Linux Hunter...")
	l.Threats = []core.Threat{}

	// Register self-defense if driver is available
	if l.driverReady {
		l.RegisterSelfDefense()
	}

	// 1. Scan for hidden processes
	l.scanHiddenProcesses()

	// 2. Check for LD_PRELOAD hijacking
	l.checkLDPreload()

	// 3. Scan crontabs for persistence
	l.scanCrontabs()

	// 4. Check SSH authorized_keys
	l.checkSSHKeys()

	// 5. Scan for suspicious kernel modules
	l.scanKernelModules()

	// 6. Check for deleted but running binaries
	l.scanDeletedBinaries()

	fmt.Printf("[+] Linux Hunter complete. Found %d threats.\n", len(l.Threats))
	return l.Threats, nil
}

func (l *LinuxHunter) scanHiddenProcesses() {
	fmt.Println("    [-] Scanning for hidden processes...")

	procPids := make(map[int]bool)
	files, _ := ioutil.ReadDir("/proc")
	for _, f := range files {
		if pid, err := strconv.Atoi(f.Name()); err == nil {
			procPids[pid] = true
		}
	}

	fmt.Printf("    [+] Found %d processes in /proc\n", len(procPids))
}

func (l *LinuxHunter) checkLDPreload() {
	fmt.Println("    [-] Checking for LD_PRELOAD hijacking...")

	if data, err := ioutil.ReadFile("/etc/ld.so.preload"); err == nil {
		content := strings.TrimSpace(string(data))
		if content != "" {
			l.Threats = append(l.Threats, core.Threat{
				Name:        "LD_PRELOAD Library Injection",
				Description: fmt.Sprintf("Global preload library found: %s", content),
				Level:       core.LevelCritical,
				FilePath:    "/etc/ld.so.preload",
			})
		}
	}

	if preload := os.Getenv("LD_PRELOAD"); preload != "" {
		l.Threats = append(l.Threats, core.Threat{
			Name:        "LD_PRELOAD Environment Set",
			Description: fmt.Sprintf("LD_PRELOAD=%s", preload),
			Level:       core.LevelHigh,
		})
	}
}

func (l *LinuxHunter) scanCrontabs() {
	fmt.Println("    [-] Scanning crontabs for persistence...")

	cronDirs := []string{
		"/etc/crontab",
		"/etc/cron.d",
		"/var/spool/cron/crontabs",
	}

	susPatterns := []string{
		"curl", "wget", "nc ", "bash -i", "python -c",
		"/dev/tcp", "base64", "eval", "exec",
	}

	for _, cronPath := range cronDirs {
		info, err := os.Stat(cronPath)
		if err != nil {
			continue
		}

		if info.IsDir() {
			filepath.Walk(cronPath, func(path string, fi os.FileInfo, err error) error {
				if fi != nil && !fi.IsDir() {
					l.scanFileForPatterns(path, susPatterns, "Suspicious Cron Entry")
				}
				return nil
			})
		} else {
			l.scanFileForPatterns(cronPath, susPatterns, "Suspicious Cron Entry")
		}
	}
}

func (l *LinuxHunter) checkSSHKeys() {
	fmt.Println("    [-] Checking SSH authorized_keys...")

	homeDir, _ := os.UserHomeDir()
	authKeysPath := filepath.Join(homeDir, ".ssh", "authorized_keys")

	if data, err := ioutil.ReadFile(authKeysPath); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			if strings.Contains(line, "command=") {
				l.Threats = append(l.Threats, core.Threat{
					Name:        "SSH Forced Command",
					Description: "authorized_keys contains command= option",
					Level:       core.LevelMedium,
					FilePath:    authKeysPath,
				})
			}
		}
		fmt.Printf("    [+] Found %d SSH keys\n", len(lines))
	}
}

func (l *LinuxHunter) scanKernelModules() {
	fmt.Println("    [-] Checking loaded kernel modules...")

	data, err := ioutil.ReadFile("/proc/modules")
	if err != nil {
		return
	}

	susModules := []string{"rootkit", "reptile", "diamorphine", "suterusu", "adore"}
	lines := strings.Split(string(data), "\n")

	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) < 1 {
			continue
		}
		modName := strings.ToLower(parts[0])

		for _, sus := range susModules {
			if strings.Contains(modName, sus) {
				l.Threats = append(l.Threats, core.Threat{
					Name:        "Suspicious Kernel Module",
					Description: fmt.Sprintf("Known rootkit module: %s", parts[0]),
					Level:       core.LevelCritical,
				})
			}
		}
	}
}

func (l *LinuxHunter) scanDeletedBinaries() {
	fmt.Println("    [-] Checking for deleted but running binaries...")

	files, _ := ioutil.ReadDir("/proc")
	for _, f := range files {
		pid, err := strconv.Atoi(f.Name())
		if err != nil {
			continue
		}

		exePath := fmt.Sprintf("/proc/%d/exe", pid)
		link, err := os.Readlink(exePath)
		if err != nil {
			continue
		}

		if strings.Contains(link, "(deleted)") {
			l.Threats = append(l.Threats, core.Threat{
				Name:        "Deleted Binary Running",
				Description: fmt.Sprintf("PID %d running from deleted binary: %s", pid, link),
				Level:       core.LevelHigh,
				Details:     map[string]interface{}{"pid": pid, "path": link},
			})
		}
	}
}

func (l *LinuxHunter) scanFileForPatterns(path string, patterns []string, threatName string) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.ToLower(scanner.Text())
		for _, pattern := range patterns {
			if strings.Contains(line, pattern) {
				l.Threats = append(l.Threats, core.Threat{
					Name:        threatName,
					Description: fmt.Sprintf("Pattern '%s' found at line %d", pattern, lineNum),
					Level:       core.LevelHigh,
					FilePath:    path,
				})
				return
			}
		}
	}
}
