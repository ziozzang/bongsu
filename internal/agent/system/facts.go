package system

import (
	"bufio"
	"bytes"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

// CollectFacts gathers comprehensive, unstructured host metadata directly from
// /proc, /sys, and /etc — no external binaries. Every section degrades
// gracefully: unreadable sources are simply omitted so the function never
// fails. The result is a nested map serialized to the host's facts JSONB,
// letting the fact schema evolve without migrations.
func CollectFacts() map[string]any {
	facts := map[string]any{
		"agent": map[string]any{
			"go_version": runtime.Version(),
			"goarch":     runtime.GOARCH,
			"goos":       runtime.GOOS,
			"num_cpu":    runtime.NumCPU(),
		},
	}
	addIfNotEmpty(facts, "os_release", parseKeyValueFile("/etc/os-release"))
	addIfNotEmpty(facts, "lsb_release", parseKeyValueFile("/etc/lsb-release"))
	addIfNotEmpty(facts, "kernel", collectKernelFacts())
	addIfNotEmpty(facts, "cpu", collectCPUFacts())
	addIfNotEmpty(facts, "memory", collectMemoryFacts())
	addIfNotEmpty(facts, "dmi", collectDMIFacts())
	addIfNotEmpty(facts, "virtualization", collectVirtFacts())
	addIfNotEmpty(facts, "network", collectNetworkFacts())
	addIfNotEmpty(facts, "filesystems", collectMountFacts())
	addIfNotEmpty(facts, "system", collectSystemFacts())
	addIfNotEmpty(facts, "release_files", collectReleaseFiles())
	return facts
}

// CollectContainerFacts gathers the distro-identity facts that live inside a
// container's own filesystem (os-release, lsb-release, distro release markers).
// Host-level facts (cpu, memory, dmi, kernel, network) are deliberately omitted
// — those belong to the host kernel, not the container rootfs. root is the
// container's merged rootfs path.
func CollectContainerFacts(root string) map[string]any {
	if root == "" {
		return nil
	}
	facts := map[string]any{}
	addIfNotEmpty(facts, "os_release", parseKeyValueFile(filepath.Join(root, "etc/os-release")))
	addIfNotEmpty(facts, "lsb_release", parseKeyValueFile(filepath.Join(root, "etc/lsb-release")))
	addIfNotEmpty(facts, "release_files", collectReleaseFilesAt(root))
	return facts
}

func addIfNotEmpty(dst map[string]any, key string, val any) {
	switch v := val.(type) {
	case nil:
		return
	case map[string]any:
		if len(v) == 0 {
			return
		}
	case []any:
		if len(v) == 0 {
			return
		}
	case []map[string]any:
		if len(v) == 0 {
			return
		}
	case string:
		if v == "" {
			return
		}
	}
	dst[key] = val
}

func parseKeyValueFile(path string) map[string]any {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	out := map[string]any{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
		if key != "" {
			out[strings.ToLower(key)] = val
		}
	}
	return out
}

func collectKernelFacts() map[string]any {
	out := map[string]any{}
	if v := readTrim("/proc/sys/kernel/osrelease"); v != "" {
		out["release"] = v
	}
	if v := readTrim("/proc/sys/kernel/version"); v != "" {
		out["version"] = v
	}
	if v := readTrim("/proc/sys/kernel/hostname"); v != "" {
		out["hostname"] = v
	}
	if v := readTrim("/proc/cmdline"); v != "" {
		out["cmdline"] = v
	}
	return out
}

func collectCPUFacts() map[string]any {
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return nil
	}
	out := map[string]any{}
	logical := 0
	physIDs := map[string]bool{}
	coreIDs := map[string]bool{}
	flags := ""
	var model, vendor, mhz, cacheSize string
	var curPhys string
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		switch key {
		case "processor":
			logical++
		case "model name":
			model = val
		case "vendor_id":
			vendor = val
		case "cpu MHz":
			mhz = val
		case "cache size":
			cacheSize = val
		case "physical id":
			curPhys = val
			physIDs[val] = true
		case "core id":
			coreIDs[curPhys+":"+val] = true
		case "flags", "Features":
			if flags == "" {
				flags = val
			}
		}
	}
	if model != "" {
		out["model"] = model
	}
	if vendor != "" {
		out["vendor"] = vendor
	}
	out["logical_cpus"] = logical
	if len(physIDs) > 0 {
		out["sockets"] = len(physIDs)
	}
	if len(coreIDs) > 0 {
		out["physical_cores"] = len(coreIDs)
	}
	if mhz != "" {
		out["mhz"] = mhz
	}
	if cacheSize != "" {
		out["cache_size"] = cacheSize
	}
	if flags != "" {
		ff := strings.Fields(flags)
		sort.Strings(ff)
		out["flags"] = ff
	}
	return out
}

func collectMemoryFacts() map[string]any {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return nil
	}
	out := map[string]any{}
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		fields := strings.Fields(strings.TrimSpace(parts[1]))
		if len(fields) == 0 {
			continue
		}
		kb, err := strconv.ParseInt(fields[0], 10, 64)
		if err != nil {
			continue
		}
		switch strings.TrimSpace(parts[0]) {
		case "MemTotal":
			out["total_mb"] = kb / 1024
		case "MemAvailable":
			out["available_mb"] = kb / 1024
		case "MemFree":
			out["free_mb"] = kb / 1024
		case "SwapTotal":
			out["swap_total_mb"] = kb / 1024
		case "SwapFree":
			out["swap_free_mb"] = kb / 1024
		}
	}
	return out
}

// collectDMIFacts reads hardware identity from sysfs. Serial/UUID fields are
// often root-readable only; unreadable entries are simply skipped.
func collectDMIFacts() map[string]any {
	base := "/sys/class/dmi/id"
	fields := map[string]string{
		"sys_vendor":      "system_vendor",
		"product_name":    "product_name",
		"product_version": "product_version",
		"product_serial":  "product_serial",
		"product_uuid":    "product_uuid",
		"board_vendor":    "board_vendor",
		"board_name":      "board_name",
		"bios_vendor":     "bios_vendor",
		"bios_version":    "bios_version",
		"bios_date":       "bios_date",
		"chassis_vendor":  "chassis_vendor",
		"chassis_type":    "chassis_type",
	}
	out := map[string]any{}
	for file, key := range fields {
		if v := readTrim(filepath.Join(base, file)); v != "" {
			out[key] = v
		}
	}
	return out
}

// collectVirtFacts reports a best-effort guess of whether the host is bare
// metal, a VM, or a container, based on DMI strings and well-known files.
func collectVirtFacts() map[string]any {
	out := map[string]any{}
	if _, err := os.Stat("/.dockerenv"); err == nil {
		out["container"] = "docker"
	}
	if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		s := string(data)
		switch {
		case strings.Contains(s, "kubepods"):
			out["container"] = "kubernetes"
		case strings.Contains(s, "docker"):
			out["container"] = "docker"
		case strings.Contains(s, "lxc"):
			out["container"] = "lxc"
		case strings.Contains(s, "containerd"):
			out["container"] = "containerd"
		}
	}
	vendor := strings.ToLower(readTrim("/sys/class/dmi/id/sys_vendor") + " " + readTrim("/sys/class/dmi/id/product_name"))
	switch {
	case strings.Contains(vendor, "kvm") || strings.Contains(vendor, "qemu"):
		out["hypervisor"] = "kvm"
	case strings.Contains(vendor, "vmware"):
		out["hypervisor"] = "vmware"
	case strings.Contains(vendor, "virtualbox"):
		out["hypervisor"] = "virtualbox"
	case strings.Contains(vendor, "microsoft") || strings.Contains(vendor, "hyper-v"):
		out["hypervisor"] = "hyper-v"
	case strings.Contains(vendor, "xen"):
		out["hypervisor"] = "xen"
	case strings.Contains(vendor, "amazon") || strings.Contains(vendor, "ec2"):
		out["hypervisor"] = "aws"
	case strings.Contains(vendor, "google"):
		out["hypervisor"] = "gcp"
	}
	return out
}

func collectNetworkFacts() map[string]any {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var list []map[string]any
	for _, iface := range ifaces {
		entry := map[string]any{"name": iface.Name}
		if iface.HardwareAddr != nil && iface.HardwareAddr.String() != "" {
			entry["mac"] = iface.HardwareAddr.String()
		}
		entry["up"] = iface.Flags&net.FlagUp != 0
		entry["loopback"] = iface.Flags&net.FlagLoopback != 0
		if iface.MTU > 0 {
			entry["mtu"] = iface.MTU
		}
		var addrs []string
		if as, err := iface.Addrs(); err == nil {
			for _, a := range as {
				addrs = append(addrs, a.String())
			}
		}
		if len(addrs) > 0 {
			entry["addresses"] = addrs
		}
		list = append(list, entry)
	}
	out := map[string]any{}
	if len(list) > 0 {
		out["interfaces"] = list
	}
	if v := readTrim("/etc/resolv.conf"); v != "" {
		var ns []string
		for _, line := range strings.Split(v, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "nameserver") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					ns = append(ns, fields[1])
				}
			}
		}
		if len(ns) > 0 {
			out["nameservers"] = ns
		}
	}
	return out
}

// collectMountFacts reports real (non-virtual) filesystems with their device
// and mount point. Pseudo filesystems (proc, sysfs, cgroup, tmpfs, etc.) are
// skipped to keep the fact blob meaningful.
func collectMountFacts() []map[string]any {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return nil
	}
	defer f.Close()
	skip := map[string]bool{
		"proc": true, "sysfs": true, "cgroup": true, "cgroup2": true,
		"tmpfs": true, "devtmpfs": true, "devpts": true, "mqueue": true,
		"hugetlbfs": true, "debugfs": true, "tracefs": true, "securityfs": true,
		"pstore": true, "bpf": true, "configfs": true, "fusectl": true,
		"binfmt_misc": true, "autofs": true, "ramfs": true, "nsfs": true,
		"overlay": true, "squashfs": true,
	}
	var out []map[string]any
	scanner := bufio.NewScanner(f)
	seen := map[string]bool{}
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}
		dev, mnt, fstype := fields[0], fields[1], fields[2]
		if skip[fstype] || !strings.HasPrefix(dev, "/") {
			continue
		}
		key := dev + " " + mnt
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, map[string]any{
			"device":      dev,
			"mount_point": mnt,
			"fstype":      fstype,
		})
	}
	return out
}

func collectSystemFacts() map[string]any {
	out := map[string]any{}
	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) > 0 {
			if secs, err := strconv.ParseFloat(fields[0], 64); err == nil {
				out["uptime_seconds"] = int64(secs)
			}
		}
	}
	if v := readTrim("/proc/loadavg"); v != "" {
		if fields := strings.Fields(v); len(fields) >= 3 {
			out["load_average"] = []string{fields[0], fields[1], fields[2]}
		}
	}
	if v := readTrim("/proc/sys/kernel/random/boot_id"); v != "" {
		out["boot_id"] = v
	}
	if v := readTrim("/etc/timezone"); v != "" {
		out["timezone"] = v
	}
	return out
}

// collectReleaseFiles captures the raw contents of any /etc/*-release and
// /etc/*_version files not already structured above — distro-specific markers
// that don't follow the os-release key=value form.
func collectReleaseFiles() map[string]any {
	return collectReleaseFilesAt("/")
}

func collectReleaseFilesAt(root string) map[string]any {
	out := map[string]any{}
	candidates := []string{
		"etc/redhat-release", "etc/centos-release", "etc/system-release",
		"etc/alpine-release", "etc/debian_version", "etc/SuSE-release",
		"etc/oracle-release", "etc/rocky-release", "etc/almalinux-release",
	}
	for _, rel := range candidates {
		if v := readTrim(filepath.Join(root, rel)); v != "" {
			out[filepath.Base(rel)] = v
		}
	}
	return out
}

func readTrim(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(bytes.TrimSpace(data))
}
