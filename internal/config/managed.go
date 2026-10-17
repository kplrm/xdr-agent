package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"reflect"
	"sort"
	"strings"
)

// ManagedConfig is an authoritative snapshot of the policy's supported overrides.
// An absent snapshot is handled by the caller and never changes local settings.
type ManagedConfig struct {
	SchemaVersion int                        `json:"schema_version"`
	Revision      string                     `json:"revision"`
	Settings      map[string]json.RawMessage `json:"settings"`
}

func managedDefault(key string) (interface{}, bool) {
	switch key {
	case "internal_networks":
		return DefaultInternalNetworks(), true
	case "process_scan_interval_seconds", "network_scan_interval_seconds":
		return 1, true
	case "telemetry_ship_interval_seconds":
		return 30, true
	default:
		return nil, false
	}
}

// ApplyManaged validates the complete policy before atomically persisting only
// its allowlisted fields. Local identity, credentials and unknown fields survive.
// Removing a previously managed key restores its packaged default; a key that
// was never managed remains local. The caller hot-applies the returned settings.
func ApplyManaged(path string, current Config, managed ManagedConfig) (Config, bool, error) {
	if managed.SchemaVersion != 1 {
		return current, false, fmt.Errorf("unsupported managed configuration schema %d", managed.SchemaVersion)
	}
	if strings.TrimSpace(managed.Revision) == "" || len(managed.Revision) > 256 {
		return current, false, fmt.Errorf("managed configuration revision must contain 1–256 characters")
	}
	if managed.Settings == nil {
		return current, false, fmt.Errorf("managed configuration settings must be an object")
	}
	values := make(map[string]interface{}, len(managed.Settings))
	for key, raw := range managed.Settings {
		if _, ok := managedDefault(key); !ok {
			return current, false, fmt.Errorf("unsupported managed configuration setting %q", key)
		}
		if key == "internal_networks" {
			var networks []string
			if err := json.Unmarshal(raw, &networks); err != nil || networks == nil || len(networks) > 256 {
				return current, false, fmt.Errorf("internal_networks must be an array of at most 256 CIDRs")
			}
			for _, cidr := range networks {
				if _, _, err := net.ParseCIDR(cidr); err != nil {
					return current, false, fmt.Errorf("invalid internal_networks CIDR %q", cidr)
				}
			}
			values[key] = networks
			continue
		}
		var seconds int
		if err := json.Unmarshal(raw, &seconds); err != nil || seconds < 1 || seconds > 86400 {
			return current, false, fmt.Errorf("%s must be an integer between 1 and 86400 seconds", key)
		}
		values[key] = seconds
	}

	for _, key := range current.ManagedConfigKeys {
		if _, overridden := values[key]; !overridden {
			if value, supported := managedDefault(key); supported {
				values[key] = value
			}
		}
	}
	next := current
	for key, value := range values {
		switch key {
		case "internal_networks":
			next.InternalNetworks = value.([]string)
		case "process_scan_interval_seconds":
			next.ProcessScanIntervalSeconds = value.(int)
		case "network_scan_interval_seconds":
			next.NetworkScanIntervalSeconds = value.(int)
		case "telemetry_ship_interval_seconds":
			next.TelemetryShipIntervalSeconds = value.(int)
		}
	}
	next.ManagedConfigKeys = make([]string, 0, len(managed.Settings))
	for key := range managed.Settings {
		next.ManagedConfigKeys = append(next.ManagedConfigKeys, key)
	}
	sort.Strings(next.ManagedConfigKeys)
	next.ManagedConfigRevision = managed.Revision
	next.ManagedConfigError = ""

	content, err := os.ReadFile(path)
	if err != nil {
		return current, false, fmt.Errorf("read managed config %s: %w", path, err)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(content, &document); err != nil || document == nil {
		return current, false, fmt.Errorf("local configuration must be a JSON object")
	}
	for key, value := range values {
		document[key], _ = json.Marshal(value)
	}
	document["managed_config_revision"], _ = json.Marshal(next.ManagedConfigRevision)
	document["managed_config_keys"], _ = json.Marshal(next.ManagedConfigKeys)
	data, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return current, false, fmt.Errorf("marshal managed config: %w", err)
	}
	data = append(data, '\n')
	if !bytes.Equal(content, data) {
		if err := saveJSON(path, data); err != nil {
			return current, false, err
		}
	}
	return next, !reflect.DeepEqual(current, next), nil
}
