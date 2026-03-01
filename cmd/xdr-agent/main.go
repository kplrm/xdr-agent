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
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"xdr-agent/internal/agent"
	"xdr-agent/internal/buildinfo"
	"xdr-agent/internal/config"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "xdr-agent error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// If no command is provided, default to "run".
	if len(os.Args) < 2 {
		return runCommand("run", os.Args[1:])
	}

	// Supported commands: run, enroll, remove, version, help
	switch os.Args[1] {
	case "run", "enroll", "remove", "version":
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
	case "remove":
		return removeInstallation()
	case "enroll":
		return enrollAgentCommand(args)
	case "run":
		return runAgentCommand(args)
	default:
		return fmt.Errorf("unsupported command %q", command)
	}
}

func removeInstallation() error {
	// Check for root privileges before attempting to remove files and disable the service.
	if os.Geteuid() != 0 {
		return fmt.Errorf("remove requires root privileges; run with sudo")
	}

	// Attempt to stop and disable the systemd service if it exists.
	if systemctlPath, err := exec.LookPath("systemctl"); err == nil {
		_ = exec.Command(systemctlPath, "stop", "xdr-agent.service").Run()
		_ = exec.Command(systemctlPath, "disable", "xdr-agent.service").Run()
		_ = exec.Command(systemctlPath, "daemon-reload").Run()
	}

	// Remove known xdr-agent files and directories.
	paths := []string{
		"/usr/bin/xdr-agent",
		"/etc/xdr-agent",
		"/etc/bash_completion.d/xdr-agent",
		"/usr/share/bash-completion/completions/xdr-agent",
		"/usr/lib/systemd/system/xdr-agent.service",
		"/lib/systemd/system/xdr-agent.service",
		"/var/lib/xdr-agent",
	}
	for _, path := range paths {
		if err := os.RemoveAll(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove %s: %w", path, err)
		}
	}

	// Print confirmation message after successful removal.
	fmt.Println("xdr-agent removed")
	return nil
}

func enrollAgentCommand(args []string) error {
	// Parse command-line flags and load default enrollment token path.
	flags := flag.NewFlagSet("enroll", flag.ContinueOnError)
	flags.SetOutput(os.Stdout)
	configPath := flags.String("config", config.DefaultConfigPath, "path to config json")

	// Attempt to parse enrollment token from first argument
	enrollmentToken := ""
	parseArgs := args
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		enrollmentToken = strings.TrimSpace(args[0])
		parseArgs = args[1:]
	}
	if err := flags.Parse(parseArgs); err != nil {
		return err
	}

	// Check if enrollment token was provided via flag or positional argument
	rest := flags.Args()
	if enrollmentToken == "" {
		if len(rest) != 1 {
			return fmt.Errorf("usage: xdr-agent enroll <enrollment_token> [--config path]")
		}
		enrollmentToken = strings.TrimSpace(rest[0])
	} else if len(rest) != 0 {
		return fmt.Errorf("usage: xdr-agent enroll <enrollment_token> [--config path]")
	}
	if enrollmentToken == "" {
		return fmt.Errorf("enrollment_token cannot be empty")
	}

	fmt.Fprintln(os.Stdout, "xdr-agent install path: /usr/bin/xdr-agent")

	if err := validateConfigPath(*configPath); err != nil {
		return err
	}

	// Set up signal handling to allow graceful shutdown on SIGTERM/SIGINT.
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	// Create an agent instance just for enrollment. We won't start the full agent loop here.
	a, err := agent.New(agent.Options{
		ConfigPath:      *configPath,
		EnrollmentToken: enrollmentToken,
	})
	if err != nil {
		return err
	}
	if err := a.Enroll(ctx, false); err != nil {
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	}

	// After successful enrollment, attempt to enable and start the systemd service if running as root.
	if err := enableAndStartServiceAfterEnroll(); err != nil {
		return err
	}

	return nil
}

func runAgentCommand(args []string) error {
	// Parse command-line flags and load default enrollment token path.
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	flags.SetOutput(os.Stdout)
	configPath := flags.String("config", config.DefaultConfigPath, "path to config json")

	// Parse flags and validate config path
	if err := flags.Parse(args); err != nil {
		return err
	}
	if len(flags.Args()) != 0 {
		return fmt.Errorf("usage: xdr-agent run [--config path]")
	}
	if err := validateConfigPath(*configPath); err != nil {
		return err
	}

	// Set up signal handling to allow graceful shutdown on SIGTERM/SIGINT.
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	// Create and run the agent. This will block until the context is canceled.
	a, err := agent.New(agent.Options{ConfigPath: *configPath})
	if err != nil {
		return err
	}
	if err := a.Run(ctx); err != nil {
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	}

	return nil
}

// validateConfigPath checks if the provided config file path exists and is accessible.
func validateConfigPath(configPath string) error {
	if _, err := os.Stat(configPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(os.Stdout, "config file not found: %s\n", configPath)
			return fmt.Errorf("config file not found: %s", configPath)
		}
		return fmt.Errorf("cannot access config file %s: %w", configPath, err)
	}

	return nil
}

func enableAndStartServiceAfterEnroll() error {
	// Validate that it runs with root privileges.
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stdout, "enrollment successful; run with sudo to auto-enable and start xdr-agent.service")
		return nil
	}

	// Check if systemctl is available before attempting to enable/start the service.
	systemctlPath, err := exec.LookPath("systemctl")
	if err != nil {
		fmt.Fprintln(os.Stdout, "enrollment successful; systemctl not found, skipping service enable/start")
		return nil
	}

	// Attempt to enable and start the systemd service.
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

// printHelp outputs usage information for the xdr-agent CLI.
func printHelp() {
	fmt.Println("xdr-agent: lightweight identity and enrollment agent")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  run        Run the long-lived agent process")
	fmt.Println("  enroll     Perform one enrollment attempt and exit")
	fmt.Println("  remove     Remove xdr-agent files and service")
	fmt.Println("  version    Print build version")
	fmt.Println()
	fmt.Printf("Examples:\n")
	fmt.Printf("  xdr-agent run --config %s\n", config.DefaultConfigPath)
	fmt.Printf("  xdr-agent enroll <enrollment_token> --config %s\n", config.DefaultConfigPath)
	fmt.Printf("  sudo xdr-agent remove\n")
}
