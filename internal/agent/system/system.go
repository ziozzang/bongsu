package system

import (
	"bytes"
	"context"
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

const defaultCommandTimeout = 30 * time.Second

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
	out, err := commandOutput("uname", "-r")
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
	out, err := commandOutput("hostname", "-I")
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
	out, err := commandOutput("awk", "-F:", "{print $1,$3,$4,$6,$7}", "/etc/passwd")
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
	out, err := commandOutput("ps", "aux", "--sort=-pcpu")
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

// GetRunningContainers enumerates containers across every runtime CLI found
// on the host: docker, podman, nerdctl (docker-compatible CLIs), and crictl
// (CRI/kubernetes nodes). Containers seen by more than one CLI (e.g. nerdctl
// and crictl on the same containerd) are deduplicated by container ID.
func GetRunningContainers() ([]models.ContainerAsset, error) {
	var containers []models.ContainerAsset
	var errs []string
	seen := map[string]bool{}
	available := 0
	dedup := func(list []models.ContainerAsset) {
		for _, c := range list {
			key := containerDedupKey(c.ContainerID)
			if key == "" || seen[key] {
				continue
			}
			seen[key] = true
			containers = append(containers, c)
		}
	}
	for _, rt := range []string{"docker", "podman", "nerdctl"} {
		if _, err := exec.LookPath(rt); err != nil {
			continue
		}
		available++
		list, err := dockerCompatContainers(rt)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", rt, err))
			continue
		}
		dedup(list)
	}
	if _, err := exec.LookPath("crictl"); err == nil {
		available++
		list, err := crictlContainers()
		if err != nil {
			errs = append(errs, fmt.Sprintf("crictl: %v", err))
		} else {
			dedup(list)
		}
	}
	if available == 0 {
		return nil, fmt.Errorf("no container runtime CLI found (docker, podman, nerdctl, crictl)")
	}
	if len(containers) == 0 && len(errs) > 0 {
		return nil, fmt.Errorf("container enumeration failed: %s", strings.Join(errs, "; "))
	}
	for _, e := range errs {
		fmt.Fprintf(os.Stderr, "warning: container runtime %s\n", e)
	}
	return containers, nil
}

func containerDedupKey(id string) string {
	id = strings.TrimSpace(id)
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func dockerCompatContainers(bin string) ([]models.ContainerAsset, error) {
	out, err := commandOutput(bin, "ps", "--format", "{{.ID}}")
	if err != nil {
		return nil, fmt.Errorf("%s ps: %w", bin, err)
	}
	var containers []models.ContainerAsset
	for _, id := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if id == "" {
			continue
		}
		c, err := inspectDockerCompatContainer(bin, id)
		if err != nil {
			containers = append(containers, models.ContainerAsset{
				Runtime:     bin,
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

// crictlContainers enumerates CRI-managed containers (containerd/cri-o on
// kubernetes nodes) and preserves pod metadata via the CRI labels.
func crictlContainers() ([]models.ContainerAsset, error) {
	out, err := commandOutput("crictl", "ps", "-o", "json")
	if err != nil {
		return nil, fmt.Errorf("crictl ps: %w", err)
	}
	var data struct {
		Containers []struct {
			ID       string `json:"id"`
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
			Image struct {
				Image string `json:"image"`
			} `json:"image"`
			ImageRef  string            `json:"imageRef"`
			State     string            `json:"state"`
			CreatedAt string            `json:"createdAt"`
			Labels    map[string]string `json:"labels"`
		} `json:"containers"`
	}
	if err := json.Unmarshal(out, &data); err != nil {
		return nil, fmt.Errorf("crictl ps parse: %w", err)
	}
	var containers []models.ContainerAsset
	for _, c := range data.Containers {
		state := strings.ToLower(strings.TrimPrefix(c.State, "CONTAINER_"))
		labels, _ := json.Marshal(c.Labels)
		var startedAt *time.Time
		if ns, err := strconv.ParseInt(strings.TrimSpace(c.CreatedAt), 10, 64); err == nil && ns > 0 {
			t := time.Unix(0, ns)
			startedAt = &t
		}
		name := c.Metadata.Name
		if pod := c.Labels["io.kubernetes.pod.name"]; pod != "" {
			name = pod + "/" + name
		}
		containers = append(containers, models.ContainerAsset{
			Runtime:     "cri",
			ContainerID: c.ID,
			Name:        name,
			ImageName:   c.Image.Image,
			ImageID:     c.ImageRef,
			State:       state,
			Labels:      string(labels),
			StartedAt:   startedAt,
		})
	}
	return containers, nil
}

func inspectDockerCompatContainer(bin, id string) (models.ContainerAsset, error) {
	out, err := commandOutput(bin, "inspect", id)
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
		return models.ContainerAsset{}, fmt.Errorf("empty %s inspect", bin)
	}
	name := strings.TrimPrefix(data[0].Name, "/")
	labels, _ := json.Marshal(data[0].Config.Labels)
	var startedAt *time.Time
	if t, err := time.Parse(time.RFC3339Nano, data[0].State.StartedAt); err == nil && !t.IsZero() {
		startedAt = &t
	}
	return models.ContainerAsset{
		Runtime:     bin,
		ContainerID: data[0].ID,
		Name:        name,
		ImageName:   data[0].Config.Image,
		ImageID:     data[0].Image,
		State:       data[0].State.Status,
		Labels:      string(labels),
		StartedAt:   startedAt,
	}, nil
}

func commandOutput(name string, args ...string) ([]byte, error) {
	timeout := commandTimeout()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("%s timed out after %s", name, timeout)
	}
	return out, err
}

func commandTimeout() time.Duration {
	raw := strings.TrimSpace(os.Getenv("BONGSU_AGENT_COMMAND_TIMEOUT_SECONDS"))
	if raw == "" {
		return defaultCommandTimeout
	}
	seconds, err := strconv.Atoi(raw)
	if err != nil || seconds <= 0 {
		return defaultCommandTimeout
	}
	if seconds > 300 {
		seconds = 300
	}
	return time.Duration(seconds) * time.Second
}
