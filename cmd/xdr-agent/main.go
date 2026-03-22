// xdr-agent - Modular XDR endpoint security agent for Linux
// Copyright (C) 2026  Diego A. Guillen-Rosaperez
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, version 3 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"xdr-agent/internal/buildinfo"
	"xdr-agent/internal/config"
	"xdr-agent/internal/controlplane"
	"xdr-agent/internal/service"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "xdr-agent error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) < 2 {
		return runCommand("run", os.Args[1:])
	}

	switch os.Args[1] {
	case "run", "enroll", "remove", "version", "completion", "defense-posture":
		return runCommand(os.Args[1], os.Args[2:])
	case "-h", "--help", "help":
		printHelp()
		return nil
	default:
		return fmt.Errorf("unknown command %q", os.Args[1])
	}
}

func runCommand(command string, args []string) error {
	switch command {
	case "version":
		fmt.Println(buildinfo.Version)
		return nil
	case "completion":
		if len(args) != 1 || args[0] != "bash" {
			return fmt.Errorf("usage: xdr-agent completion bash")
		}
		printBashCompletion()
		return nil
	case "defense-posture":
		flags := flag.NewFlagSet(command, flag.ContinueOnError)
		flags.SetOutput(os.Stdout)
		configPath := flags.String("config", config.DefaultConfigPath, "path to config json")
		if err := flags.Parse(args); err != nil {
			return err
		}

		rawCfg, err := config.LoadRaw(*configPath)
		if err != nil {
			return err
		}
		posturePath := rawCfg.DefensePosturePath
		if posturePath == "" {
			posturePath = config.DefaultDefensePosturePath
		}

		posture, err := controlplane.LoadDefensePosture(posturePath)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				fmt.Fprintln(os.Stdout, "{}")
				return nil
			}
			return err
		}

		output, err := json.MarshalIndent(posture, "", "  ")
		if err != nil {
			return err
		}
		fmt.Fprintln(os.Stdout, string(output))
		return nil
	case "remove":
		return removeInstallation()
	case "run", "enroll":
		// Parse command-line flags
		flags := flag.NewFlagSet(command, flag.ContinueOnError)
		flags.SetOutput(os.Stdout)
		configPath := flags.String("config", config.DefaultConfigPath, "path to config json")

		// Config override flags — when set, these values override the config
		// file and are persisted back so subsequent runs use them.
		controlPlaneURL := flags.String("control-plane-url", "", "override control_plane_url")
		policyIDFlag := flags.String("policy-id", "", "override policy_id")
		tagsFlag := flags.String("tags", "", "override tags (comma-separated)")
		insecureSkipTLS := flags.Bool("insecure-skip-tls-verify", false, "override insecure_skip_tls_verify")

		enrollmentToken := ""
		parseArgs := args
		if command == "enroll" && len(args) > 0 && !strings.HasPrefix(args[0], "-") {
			enrollmentToken = strings.TrimSpace(args[0])
			parseArgs = args[1:]
		}

		if err := flags.Parse(parseArgs); err != nil {
			return err
		}

		if command == "enroll" {
			rest := flags.Args()
			if enrollmentToken == "" {
				if len(rest) != 1 {
					return fmt.Errorf("usage: xdr-agent enroll <enrollment_token> [--config path] [--control-plane-url url] [--policy-id id] [--tags t1,t2]")
				}
				enrollmentToken = strings.TrimSpace(rest[0])
			} else if len(rest) != 0 {
				return fmt.Errorf("usage: xdr-agent enroll <enrollment_token> [--config path] [--control-plane-url url] [--policy-id id] [--tags t1,t2]")
			}
			if enrollmentToken == "" {
				return fmt.Errorf("enrollment_token cannot be empty")
			}
			fmt.Fprintln(os.Stdout, "xdr-agent install path: /usr/bin/xdr-agent")
		}

		// Check if config file exists before starting the agent
		if _, err := os.Stat(*configPath); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				fmt.Fprintf(os.Stdout, "config file not found: %s\n", *configPath)
				return fmt.Errorf("config file not found: %s", *configPath)
			}
			return fmt.Errorf("cannot access config file %s: %w", *configPath, err)
		}

		// Apply CLI overrides to the config file before loading.
		overridesSet := false
		if *controlPlaneURL != "" || *policyIDFlag != "" || *tagsFlag != "" || *insecureSkipTLS {
			cfg, err := config.LoadRaw(*configPath)
			if err != nil {
				return err
			}
			if *controlPlaneURL != "" {
				cfg.ControlPlaneURL = *controlPlaneURL
				overridesSet = true
			}
			if *policyIDFlag != "" {
				cfg.PolicyID = *policyIDFlag
				overridesSet = true
			}
			if *tagsFlag != "" {
				cfg.Tags = splitTags(*tagsFlag)
				overridesSet = true
			}
			if *insecureSkipTLS {
				cfg.InsecureSkipTLSVerify = true
				overridesSet = true
			}
			if overridesSet {
				if err := config.Save(*configPath, cfg); err != nil {
					return fmt.Errorf("save config overrides: %w", err)
				}
				fmt.Fprintln(os.Stdout, "config overrides saved to", *configPath)
			}
		}

		// Use signal.NotifyContext to handle graceful shutdown on SIGTERM and SIGINT
		ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
		defer cancel()

		// Run the service. If "enroll" command is used, it will attempt enrollment once and exit.
		once := command == "enroll"
		if err := service.Run(ctx, *configPath, once, enrollmentToken); err != nil {
			if errors.Is(err, context.Canceled) {
				return nil
			}
			return err
		}

		if command == "enroll" {
			if err := enableAndStartServiceAfterEnroll(); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("unsupported command %q", command)
	}
}

// splitTags splits a comma-separated string into a trimmed slice, discarding empty entries.
func splitTags(s string) []string {
	var tags []string
	for _, t := range strings.Split(s, ",") {
		t = strings.TrimSpace(t)
		if t != "" {
			tags = append(tags, t)
		}
	}
	return tags
}

func enableAndStartServiceAfterEnroll() error {
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stdout, "enrollment successful; run with sudo to auto-enable and start xdr-agent.service")
		return nil
	}

	systemctlPath, err := exec.LookPath("systemctl")
	if err != nil {
		fmt.Fprintln(os.Stdout, "enrollment successful; systemctl not found, skipping service enable/start")
		return nil
	}

	if err := exec.Command(systemctlPath, "daemon-reload").Run(); err != nil {
		return fmt.Errorf("systemctl daemon-reload failed: %w", err)
	}
	if err := exec.Command(systemctlPath, "enable", "xdr-agent.service").Run(); err != nil {
		return fmt.Errorf("systemctl enable xdr-agent.service failed: %w", err)
	}
	if err := exec.Command(systemctlPath, "start", "xdr-agent.service").Run(); err != nil {
		return fmt.Errorf("systemctl start xdr-agent.service failed: %w", err)
	}

	fmt.Fprintln(os.Stdout, "xdr-agent.service enabled and started")
	return nil
}

func removeInstallation() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("remove requires root privileges; run with sudo")
	}

	if systemctlPath, err := exec.LookPath("systemctl"); err == nil {
		_ = exec.Command(systemctlPath, "stop", "xdr-agent.service").Run()
		_ = exec.Command(systemctlPath, "disable", "xdr-agent.service").Run()
		_ = exec.Command(systemctlPath, "daemon-reload").Run()
	}

	paths := []string{
		"/usr/bin/xdr-agent",
		"/etc/xdr-agent",
		"/etc/bash_completion.d/xdr-agent",
		"/usr/lib/systemd/system/xdr-agent.service",
		"/lib/systemd/system/xdr-agent.service",
		"/var/lib/xdr-agent",
	}

	for _, path := range paths {
		if err := os.RemoveAll(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove %s: %w", path, err)
		}
	}

	fmt.Println("xdr-agent removed")
	return nil
}

// printHelp outputs usage information for the xdr-agent CLI.
func printHelp() {
	fmt.Println("xdr-agent: lightweight identity and enrollment agent")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  run        Run the long-lived agent process")
	fmt.Println("  enroll     Perform one enrollment attempt and exit")
	fmt.Println("  defense-posture Show cached local Defense Posture JSON")
	fmt.Println("  completion Output shell completion script")
	fmt.Println("  remove     Remove xdr-agent files and service")
	fmt.Println()
	fmt.Println("Config overrides (for run and enroll):")
	fmt.Println("  --config <path>              Path to config JSON (default: /etc/xdr-agent/config.json)")
	fmt.Println("  --control-plane-url <url>    Override control_plane_url and save to config")
	fmt.Println("  --policy-id <id>             Override policy_id and save to config")
	fmt.Println("  --tags <t1,t2,...>           Override tags (comma-separated) and save to config")
	fmt.Println("  --insecure-skip-tls-verify   Set insecure_skip_tls_verify=true and save to config")
	fmt.Println("  version    Print build version")
	fmt.Println()
	fmt.Printf("Examples:\n")
	fmt.Printf("  xdr-agent run --config %s\n", config.DefaultConfigPath)
	fmt.Printf("  xdr-agent enroll <enrollment_token> --config %s\n", config.DefaultConfigPath)
	fmt.Printf("  xdr-agent defense-posture --config %s\n", config.DefaultConfigPath)
	fmt.Printf("  xdr-agent completion bash\n")
	fmt.Printf("  sudo xdr-agent remove\n")
}

func printBashCompletion() {
	const script = `# bash completion for xdr-agent
_xdr_agent_completion() {
	local cur
	cur="${COMP_WORDS[COMP_CWORD]}"

	if [[ ${COMP_CWORD} -eq 1 ]]; then
		COMPREPLY=( $(compgen -W "run enroll defense-posture remove version completion help" -- "${cur}") )
		return 0
	fi

	case "${COMP_WORDS[1]}" in
		run|enroll|defense-posture)
			COMPREPLY=( $(compgen -W "--config -h --help" -- "${cur}") )
			;;
		completion)
			COMPREPLY=( $(compgen -W "bash" -- "${cur}") )
			;;
		*)
			COMPREPLY=()
			;;
	esac
}

_xdr_agent_sudo_completion() {
	local idx
	for ((idx = 1; idx < COMP_CWORD; idx++)); do
		case "${COMP_WORDS[idx]}" in
			xdr-agent|/usr/bin/xdr-agent)
				local saved_words=("${COMP_WORDS[@]}")
				local saved_cword="${COMP_CWORD}"

				COMP_WORDS=("${COMP_WORDS[@]:idx}")
				COMP_CWORD=$((COMP_CWORD - idx))

				_xdr_agent_completion

				COMP_WORDS=("${saved_words[@]}")
				COMP_CWORD="${saved_cword}"
				return 0
				;;
		esac
	done

	return 1
}

complete -F _xdr_agent_completion xdr-agent
complete -F _xdr_agent_completion /usr/bin/xdr-agent

if declare -F _sudo >/dev/null 2>&1; then
	_xdr_agent_or_sudo_completion() {
		_xdr_agent_sudo_completion || _sudo
	}
	complete -F _xdr_agent_or_sudo_completion sudo
else
	complete -F _xdr_agent_sudo_completion sudo
fi
`

	fmt.Print(script)
}
