package system

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// NetIOSample holds raw cumulative counters for one network interface from /proc/net/dev.
type NetIOSample struct {
	InBytes   uint64
	OutBytes  uint64
	InErrors  uint64
	OutErrors uint64
}

// NetIODelta is the bytes/errors transferred in one interval, summed across
// all non-loopback interfaces.
type NetIODelta struct {
	InBytes   uint64
	OutBytes  uint64
	InErrors  uint64
	OutErrors uint64
}

// ReadNetIO parses /proc/net/dev and returns cumulative counters per interface.
// The loopback "lo" interface is excluded.
func ReadNetIO(procRoot string) (map[string]NetIOSample, error) {
	path := procRoot + "/net/dev"
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	result := make(map[string]NetIOSample)
	scanner := bufio.NewScanner(f)

	// Skip the two header lines ("Inter-|..." and " face |bytes...")
	scanner.Scan()
	scanner.Scan()

	for scanner.Scan() {
		line := scanner.Text()
		colonIdx := strings.Index(line, ":")
		if colonIdx < 0 {
			continue
		}
		name := strings.TrimSpace(line[:colonIdx])
		if name == "lo" {
			continue
		}

		// Fields after the colon:
		// [0]=rx_bytes [1]=rx_packets [2]=rx_errs [3]=rx_drop ...
		// [8]=tx_bytes [9]=tx_packets [10]=tx_errs [11]=tx_drop ...
		fields := strings.Fields(line[colonIdx+1:])
		if len(fields) < 16 {
			continue
		}

		inBytes, _ := strconv.ParseUint(fields[0], 10, 64)
		inErrors, _ := strconv.ParseUint(fields[2], 10, 64)
		outBytes, _ := strconv.ParseUint(fields[8], 10, 64)
		outErrors, _ := strconv.ParseUint(fields[10], 10, 64)

		result[name] = NetIOSample{
			InBytes:   inBytes,
			OutBytes:  outBytes,
			InErrors:  inErrors,
			OutErrors: outErrors,
		}
	}
	return result, scanner.Err()
}

// SumNetIODelta computes the total in/out bytes and errors across all interfaces
// since the previous snapshot. Counter wraps and new interfaces are ignored.
func SumNetIODelta(prev, curr map[string]NetIOSample) NetIODelta {
	var delta NetIODelta
	for name, c := range curr {
		p, ok := prev[name]
		if !ok {
			continue
		}
		if c.InBytes >= p.InBytes {
			delta.InBytes += c.InBytes - p.InBytes
		}
		if c.OutBytes >= p.OutBytes {
			delta.OutBytes += c.OutBytes - p.OutBytes
		}
		if c.InErrors >= p.InErrors {
			delta.InErrors += c.InErrors - p.InErrors
		}
		if c.OutErrors >= p.OutErrors {
			delta.OutErrors += c.OutErrors - p.OutErrors
		}
	}
	return delta
}
