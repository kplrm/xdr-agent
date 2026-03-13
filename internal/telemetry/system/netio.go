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
	InBytes     uint64
	OutBytes    uint64
	InErrors    uint64
	OutErrors   uint64
	InPackets   uint64
	OutPackets  uint64
	InDrops     uint64
	OutDrops    uint64
	InMulticast uint64
}

// NetIODelta is the bytes/errors/packets transferred in one interval, summed across
// all non-loopback interfaces.  Per-interface deltas are also available in ByInterface.
type NetIODelta struct {
	InBytes    uint64
	OutBytes   uint64
	InErrors   uint64
	OutErrors  uint64
	InPackets  uint64
	OutPackets uint64
	InDrops    uint64
	OutDrops   uint64

	// ByInterface contains the per-interface deltas for all active interfaces.
	ByInterface map[string]NetIOSample
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
		inPackets, _ := strconv.ParseUint(fields[1], 10, 64)
		inErrors, _ := strconv.ParseUint(fields[2], 10, 64)
		inDrops, _ := strconv.ParseUint(fields[3], 10, 64)
		inMulticast, _ := strconv.ParseUint(fields[7], 10, 64)
		outBytes, _ := strconv.ParseUint(fields[8], 10, 64)
		outPackets, _ := strconv.ParseUint(fields[9], 10, 64)
		outErrors, _ := strconv.ParseUint(fields[10], 10, 64)
		outDrops, _ := strconv.ParseUint(fields[11], 10, 64)

		result[name] = NetIOSample{
			InBytes:     inBytes,
			OutBytes:    outBytes,
			InErrors:    inErrors,
			OutErrors:   outErrors,
			InPackets:   inPackets,
			OutPackets:  outPackets,
			InDrops:     inDrops,
			OutDrops:    outDrops,
			InMulticast: inMulticast,
		}
	}
	return result, scanner.Err()
}

// SumNetIODelta computes the total in/out bytes, packets, errors, and drops across
// all interfaces since the previous snapshot.  Counter wraps and new interfaces
// are ignored.  Per-interface deltas are included in ByInterface.
func SumNetIODelta(prev, curr map[string]NetIOSample) NetIODelta {
	delta := NetIODelta{
		ByInterface: make(map[string]NetIOSample),
	}
	for name, c := range curr {
		p, ok := prev[name]
		if !ok {
			continue
		}
		ifDelta := NetIOSample{}
		if c.InBytes >= p.InBytes {
			d := c.InBytes - p.InBytes
			delta.InBytes += d
			ifDelta.InBytes = d
		}
		if c.OutBytes >= p.OutBytes {
			d := c.OutBytes - p.OutBytes
			delta.OutBytes += d
			ifDelta.OutBytes = d
		}
		if c.InErrors >= p.InErrors {
			d := c.InErrors - p.InErrors
			delta.InErrors += d
			ifDelta.InErrors = d
		}
		if c.OutErrors >= p.OutErrors {
			d := c.OutErrors - p.OutErrors
			delta.OutErrors += d
			ifDelta.OutErrors = d
		}
		if c.InPackets >= p.InPackets {
			d := c.InPackets - p.InPackets
			delta.InPackets += d
			ifDelta.InPackets = d
		}
		if c.OutPackets >= p.OutPackets {
			d := c.OutPackets - p.OutPackets
			delta.OutPackets += d
			ifDelta.OutPackets = d
		}
		if c.InDrops >= p.InDrops {
			d := c.InDrops - p.InDrops
			delta.InDrops += d
			ifDelta.InDrops = d
		}
		if c.OutDrops >= p.OutDrops {
			d := c.OutDrops - p.OutDrops
			delta.OutDrops += d
			ifDelta.OutDrops = d
		}
		delta.ByInterface[name] = ifDelta
	}
	return delta
}
