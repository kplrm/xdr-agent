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

	"xdr-agent/internal/buildinfo"
	"xdr-agent/internal/config"
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
	case "run", "enroll":
		// Parse command-line flags
		flags := flag.NewFlagSet(command, flag.ContinueOnError)
		flags.SetOutput(os.Stdout)
		configPath := flags.String("config", config.DefaultConfigPath, "path to config json")

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
		}

		// Check if config file exists before starting the agent
		if _, err := os.Stat(*configPath); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				fmt.Fprintf(os.Stdout, "config file not found: %s\n", *configPath)
				return fmt.Errorf("config file not found: %s", *configPath)
			}
			return fmt.Errorf("cannot access config file %s: %w", *configPath, err)
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
		return nil
	default:
		return fmt.Errorf("unsupported command %q", command)
	}
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
	fmt.Println("  remove     Remove xdr-agent files and service")
	fmt.Println("  version    Print build version")
	fmt.Println()
	fmt.Printf("Examples:\n")
	fmt.Printf("  xdr-agent run --config %s\n", config.DefaultConfigPath)
	fmt.Printf("  xdr-agent enroll <enrollment_token> --config %s\n", config.DefaultConfigPath)
	fmt.Printf("  sudo xdr-agent remove\n")
}
