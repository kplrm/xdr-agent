package identity

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"
)

type State struct {
	AgentID             string   `json:"agent_id"`
	MachineID           string   `json:"machine_id"`
	Hostname            string   `json:"hostname"`
	Architecture        string   `json:"architecture"`
	OSType              string   `json:"os_type"`
	IPAddresses         []string `json:"ip_addresses"`
	Enrolled            bool     `json:"enrolled"`
	EnrollmentID        string   `json:"enrollment_id,omitempty"`
	LastEnrollAt        string   `json:"last_enroll_at,omitempty"`
	LastEnrollErr       string   `json:"last_enroll_error,omitempty"`
	LoadedRuleCount     int      `json:"loaded_rule_count,omitempty"`
	LastYaraInventoryAt string   `json:"last_yara_inventory_at,omitempty"`
}

func Ensure(path string) (State, error) {
	state, err := load(path)

	// If state file exists and is valid, refresh dynamic fields and return
	if err == nil {
		updated, changed := refresh(state)
		if changed {
			if err := save(path, updated); err != nil {
				return State{}, err
			}
		}
		return updated, nil
	}

	// Failed for a reason other than “file does not exist”, e.g. permission error or invalid content
	if !os.IsNotExist(err) {
		return State{}, err
	}

	// State file does not exist, create new state and save it
	newState, err := buildInitialState()
	if err != nil {
		return State{}, err
	}
	if err := save(path, newState); err != nil {
		return State{}, err
	}

	return newState, nil
}

func Save(path string, state State) error {
	return save(path, state)
}

func MarkEnrollment(state State, enrollmentID string, err error) State {
	state.Enrolled = err == nil
	if err == nil {
		state.EnrollmentID = enrollmentID
		state.LastEnrollAt = time.Now().UTC().Format(time.RFC3339)
		state.LastEnrollErr = ""
		return state
	}

	state.LastEnrollErr = err.Error()
	return state
}

func buildInitialState() (State, error) {
	agentID, err := randomID(16)
	if err != nil {
		return State{}, fmt.Errorf("generate agent id: %w", err)
	}

	hostname, _ := os.Hostname()

	return State{
		AgentID:      agentID,
		MachineID:    readMachineID(),
		Hostname:     hostname,
		Architecture: runtime.GOARCH,
		OSType:       runtime.GOOS,
		IPAddresses:  listIPAddresses(),
		Enrolled:     false,
	}, nil
}

func refresh(state State) (State, bool) {
	changed := false
	machineID := readMachineID()
	ipAddresses := listIPAddresses()
	hostname, _ := os.Hostname()

	if state.MachineID != machineID {
		state.MachineID = machineID
		changed = true
	}
	if state.Hostname != hostname {
		state.Hostname = hostname
		changed = true
	}
	if strings.Join(state.IPAddresses, ",") != strings.Join(ipAddresses, ",") {
		state.IPAddresses = ipAddresses
		changed = true
	}

	if state.Architecture == "" {
		state.Architecture = runtime.GOARCH
		changed = true
	}
	if state.OSType == "" {
		state.OSType = runtime.GOOS
		changed = true
	}

	return state, changed
}

func load(path string) (State, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return State{}, err
	}

	var state State
	if err := json.Unmarshal(content, &state); err != nil {
		return State{}, fmt.Errorf("parse state %s: %w", path, err)
	}
	if state.AgentID == "" {
		return State{}, fmt.Errorf("invalid state %s: missing agent_id", path)
	}

	return state, nil
}

func save(path string, state State) error {
	content, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}

	if err := os.WriteFile(path, content, 0o640); err != nil {
		return fmt.Errorf("write state %s: %w", path, err)
	}

	return nil
}

// readMachineID attempts to read the machine ID from common locations and returns "unknown" if not found.
func readMachineID() string {
	files := []string{"/etc/machine-id", "/var/lib/dbus/machine-id"}
	for _, file := range files {
		content, err := os.ReadFile(file)
		if err == nil {
			value := strings.TrimSpace(string(content))
			if value != "" {
				return value
			}
		}
	}
	return "unknown"
}

func listIPAddresses() []string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	addresses := make([]string, 0, 8)
	for _, nic := range interfaces {
		if nic.Flags&net.FlagLoopback != 0 || nic.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := nic.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || ipNet.IP.IsLoopback() {
				continue
			}
			if ipNet.IP.To4() == nil {
				continue
			}
			addresses = append(addresses, ipNet.IP.String())
		}
	}

	sort.Strings(addresses)
	if len(addresses) == 0 {
		addresses = append(addresses, "127.0.0.1")
	}
	return addresses
}

func randomID(size int) (string, error) {
	buffer := make([]byte, size)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return hex.EncodeToString(buffer), nil
}
