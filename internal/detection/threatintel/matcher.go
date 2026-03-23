// Package threatintel provides threat intelligence matching capabilities.
// It compares observed indicators (file hashes, IPs, domains, URLs) against
// known threat indicators from various intelligence sources.
package threatintel

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"xdr-agent/internal/events"
)

type Matcher struct {
	hashes  map[string]string
	ipv4    map[string]string
	domains map[string]string
	urls    map[string]string
}

func NewMatcher(dir string) (*Matcher, error) {
	m := &Matcher{
		hashes:  map[string]string{},
		ipv4:    map[string]string{},
		domains: map[string]string{},
		urls:    map[string]string{},
	}

	files, err := filepath.Glob(filepath.Join(dir, "*.txt"))
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		if err := m.loadSimpleFile(f); err != nil {
			return nil, err
		}
	}

	return m, nil
}

func (m *Matcher) loadSimpleFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	base := strings.ToLower(filepath.Base(path))
	target := m.hashes
	switch {
	case strings.Contains(base, "ip"):
		target = m.ipv4
	case strings.Contains(base, "domain"):
		target = m.domains
	case strings.Contains(base, "url"):
		target = m.urls
	}

	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		target[strings.ToLower(line)] = path
	}
	return s.Err()
}

func (m *Matcher) Match(event events.Event) (indicatorType, indicatorValue, source string, ok bool) {
	if event.Payload == nil {
		return "", "", "", false
	}
	if v, ok := stringPayload(event, "file.sha256", "sha256", "hash"); ok {
		if src, found := m.hashes[strings.ToLower(v)]; found {
			return "sha256", v, src, true
		}
	}
	if v, ok := stringPayload(event, "destination.ip", "ip", "remote_ip"); ok {
		if src, found := m.ipv4[strings.ToLower(v)]; found {
			return "ipv4", v, src, true
		}
	}
	if v, ok := stringPayload(event, "destination.domain", "domain"); ok {
		if src, found := m.domains[strings.ToLower(v)]; found {
			return "domain", v, src, true
		}
	}
	if v, ok := stringPayload(event, "url"); ok {
		if src, found := m.urls[strings.ToLower(v)]; found {
			return "url", v, src, true
		}
	}
	return "", "", "", false
}

func stringPayload(event events.Event, keys ...string) (string, bool) {
	for _, k := range keys {
		if v, ok := event.Payload[k]; ok {
			s, _ := v.(string)
			if s != "" {
				return s, true
			}
		}
	}
	return "", false
}
