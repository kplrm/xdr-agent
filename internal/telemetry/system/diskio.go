package system

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// DiskIOSample holds raw cumulative counters for one block device from /proc/diskstats.
type DiskIOSample struct {
	ReadSectors  uint64
	WriteSectors uint64
	ReadOps      uint64
	WriteOps     uint64
}

// DiskIODelta is the throughput and IOPS computed over one interval,
// summed across all tracked devices.
type DiskIODelta struct {
	ReadBytes  uint64
	WriteBytes uint64
	ReadOps    uint64
	WriteOps   uint64
}

// DiskSpaceInfo describes free/used space for a single mount point.
type DiskSpaceInfo struct {
	Mount     string
	Total     uint64
	Free      uint64
	UsedBytes uint64
	UsedPct   float64
}

const sectorSize = 512

// ReadDiskIO reads /proc/diskstats and returns cumulative sector/op counters
// per block device. Only whole-disk entries (minor number == 0) are included;
// loop and ram devices are always excluded.
func ReadDiskIO(procRoot string) (map[string]DiskIOSample, error) {
	path := procRoot + "/diskstats"
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	result := make(map[string]DiskIOSample)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 14 {
			continue
		}
		name := fields[2]
		// Skip virtual/optical devices
		if strings.HasPrefix(name, "loop") ||
			strings.HasPrefix(name, "ram") ||
			strings.HasPrefix(name, "sr") {
			continue
		}
		// Only keep whole-disk entries (minor == 0 means the disk itself, not a partition)
		minor, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil || minor != 0 {
			continue
		}

		readOps, _ := strconv.ParseUint(fields[3], 10, 64)
		readSectors, _ := strconv.ParseUint(fields[5], 10, 64)
		writeOps, _ := strconv.ParseUint(fields[7], 10, 64)
		writeSectors, _ := strconv.ParseUint(fields[9], 10, 64)

		result[name] = DiskIOSample{
			ReadSectors:  readSectors,
			WriteSectors: writeSectors,
			ReadOps:      readOps,
			WriteOps:     writeOps,
		}
	}
	return result, scanner.Err()
}

// SumDiskIODelta computes the total read/write bytes and ops across all devices
// since the previous snapshot. Counter wraps and missing devices are ignored.
func SumDiskIODelta(prev, curr map[string]DiskIOSample) DiskIODelta {
	var delta DiskIODelta
	for name, c := range curr {
		p, ok := prev[name]
		if !ok {
			continue
		}
		if c.ReadSectors >= p.ReadSectors {
			delta.ReadBytes += (c.ReadSectors - p.ReadSectors) * sectorSize
		}
		if c.WriteSectors >= p.WriteSectors {
			delta.WriteBytes += (c.WriteSectors - p.WriteSectors) * sectorSize
		}
		if c.ReadOps >= p.ReadOps {
			delta.ReadOps += c.ReadOps - p.ReadOps
		}
		if c.WriteOps >= p.WriteOps {
			delta.WriteOps += c.WriteOps - p.WriteOps
		}
	}
	return delta
}

// ReadDiskSpace calls statfs on each mount path and returns space stats.
// Paths that are not mounted or cannot be stat-ed are silently skipped.
func ReadDiskSpace(mounts []string) []DiskSpaceInfo {
	var result []DiskSpaceInfo
	for _, m := range mounts {
		var st syscall.Statfs_t
		if err := syscall.Statfs(m, &st); err != nil {
			continue
		}
		blockSize := uint64(st.Bsize)
		total := st.Blocks * blockSize
		free := st.Bavail * blockSize          // available to unprivileged user
		used := total - (st.Bfree * blockSize) // used by all users

		usedPct := 0.0
		if total > 0 {
			usedPct = round2(float64(used) / float64(total) * 100.0)
		}
		result = append(result, DiskSpaceInfo{
			Mount:     m,
			Total:     total,
			Free:      free,
			UsedBytes: used,
			UsedPct:   usedPct,
		})
	}
	return result
}
