package system

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/ziozzang/bongsu/internal/shared/models"
)

func CollectHostInfo() (*models.Host, error) {
	hostname, _ := os.Hostname()

	h := &models.Host{
		ID:       deriveHostID(),
		Hostname: hostname,
		Arch:     runtime.GOARCH,
	}

	h.OSName, h.OSVersion = getOSInfo()
	h.Kernel = getKernel()
	h.CPUModel, h.CPUCores = getCPUInfo()
	h.MemoryMB = getMemoryMB()
	h.IPAddress = getIPAddress()

	return h, nil
}

func deriveHostID() string {
	machineID, err := os.ReadFile("/etc/machine-id")
	if err == nil && len(bytes.TrimSpace(machineID)) > 0 {
		return strings.TrimSpace(string(machineID))
	}
	dbusMachineID, err := os.ReadFile("/var/lib/dbus/machine-id")
	if err == nil && len(bytes.TrimSpace(dbusMachineID)) > 0 {
		return strings.TrimSpace(string(dbusMachineID))
	}
	hostname, _ := os.Hostname()
	if isTemporaryHostname(hostname) {
		if ip := getIPAddress(); ip != "" {
			return "ip:" + ip
		}
	}
	return hostname
}

func isTemporaryHostname(hostname string) bool {
	name := strings.ToUpper(strings.TrimSpace(hostname))
	if !strings.HasPrefix(name, "TEMP-") {
		return false
	}
	rest := strings.TrimPrefix(name, "TEMP-")
	if rest == "" {
		return false
	}
	for _, r := range rest {
		if (r < '0' || r > '9') && (r < 'A' || r > 'F') && r != '-' {
			return false
		}
	}
	return true
}

func getOSInfo() (string, string) {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "unknown", ""
	}
	var name, ver string
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		val := strings.Trim(parts[1], `"`)
		switch parts[0] {
		case "NAME":
			name = val
		case "VERSION_ID":
			ver = val
		}
	}
	return name, ver
}

func getKernel() string {
	out, err := exec.Command("uname", "-r").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func getCPUInfo() (string, int) {
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return "unknown", 0
	}
	var model string
	cores := 0
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "model name") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				model = strings.TrimSpace(parts[1])
			}
		}
		if strings.HasPrefix(line, "processor") {
			cores++
		}
	}
	return model, cores
}

func getMemoryMB() int64 {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				kb, err := strconv.ParseInt(fields[1], 10, 64)
				if err == nil {
					return kb / 1024
				}
			}
		}
	}
	return 0
}

func getIPAddress() string {
	out, err := exec.Command("hostname", "-I").Output()
	if err != nil {
		return ""
	}
	fields := strings.Fields(strings.TrimSpace(string(out)))
	if len(fields) > 0 {
		return fields[0]
	}
	return ""
}

func CollectUsers() ([]models.UserAccount, error) {
	out, err := exec.Command("awk", "-F:", "{print $1,$3,$4,$6,$7}", "/etc/passwd").Output()
	if err != nil {
		return nil, err
	}

	var users []models.UserAccount
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		uid, _ := strconv.Atoi(fields[1])
		gid, _ := strconv.Atoi(fields[2])
		users = append(users, models.UserAccount{
			Username: fields[0],
			UID:      uid,
			GID:      gid,
			HomeDir:  fields[3],
			Shell:    fields[4],
		})
	}
	return users, nil
}

func CollectProcesses() ([]models.ProcessSnapshot, error) {
	out, err := exec.Command("ps", "aux", "--sort=-pcpu").Output()
	if err != nil {
		return nil, err
	}

	var procs []models.ProcessSnapshot
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for i, line := range lines {
		if i == 0 {
			continue // header
		}
		fields := strings.Fields(line)
		if len(fields) < 11 {
			continue
		}
		pid, _ := strconv.Atoi(fields[1])
		cpu, _ := strconv.ParseFloat(fields[2], 64)
		mem, _ := strconv.ParseFloat(fields[3], 64)
		procs = append(procs, models.ProcessSnapshot{
			PID:      pid,
			Name:     fields[10],
			Cmdline:  strings.Join(fields[10:], " "),
			User:     fields[0],
			CPUUsage: cpu,
			MemUsage: mem,
		})
	}
	return procs, nil
}

func GetRunningContainers() ([]models.ContainerAsset, error) {
	out, err := exec.Command("docker", "ps", "--format", "{{.ID}}").Output()
	if err != nil {
		return nil, fmt.Errorf("docker ps: %w", err)
	}
	var containers []models.ContainerAsset
	for _, id := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if id == "" {
			continue
		}
		c, err := inspectDockerContainer(id)
		if err != nil {
			containers = append(containers, models.ContainerAsset{
				Runtime:     "docker",
				ContainerID: id,
				Name:        id,
				State:       "running",
			})
			continue
		}
		containers = append(containers, c)
	}
	return containers, nil
}

func inspectDockerContainer(id string) (models.ContainerAsset, error) {
	out, err := exec.Command("docker", "inspect", id).Output()
	if err != nil {
		return models.ContainerAsset{}, err
	}
	var data []struct {
		ID     string `json:"Id"`
		Name   string `json:"Name"`
		Image  string `json:"Image"`
		Config struct {
			Image  string            `json:"Image"`
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
		State struct {
			Status    string `json:"Status"`
			StartedAt string `json:"StartedAt"`
		} `json:"State"`
	}
	if err := json.Unmarshal(out, &data); err != nil {
		return models.ContainerAsset{}, err
	}
	if len(data) == 0 {
		return models.ContainerAsset{}, fmt.Errorf("empty docker inspect")
	}
	name := strings.TrimPrefix(data[0].Name, "/")
	labels, _ := json.Marshal(data[0].Config.Labels)
	var startedAt *time.Time
	if t, err := time.Parse(time.RFC3339Nano, data[0].State.StartedAt); err == nil && !t.IsZero() {
		startedAt = &t
	}
	return models.ContainerAsset{
		Runtime:     "docker",
		ContainerID: data[0].ID,
		Name:        name,
		ImageName:   data[0].Config.Image,
		ImageID:     data[0].Image,
		State:       data[0].State.Status,
		Labels:      string(labels),
		StartedAt:   startedAt,
	}, nil
}
