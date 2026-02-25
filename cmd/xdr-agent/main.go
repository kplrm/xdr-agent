package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"xdr-agent/internal/config"
	"xdr-agent/internal/buildinfo"
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
	case "run", "enroll", "version":
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
	case "run", "enroll":
        // Parse command-line flags
		flags := flag.NewFlagSet(command, flag.ContinueOnError)
		flags.SetOutput(os.Stdout)
		configPath := flags.String("config", config.DefaultConfigPath, "path to config json")
		if err := flags.Parse(args); err != nil {
			return err
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
		if err := service.Run(ctx, *configPath, once); err != nil {
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

// printHelp outputs usage information for the xdr-agent CLI.
func printHelp() {
	fmt.Println("xdr-agent: lightweight identity and enrollment agent")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  run        Run the long-lived agent process")
	fmt.Println("  enroll     Perform one enrollment attempt and exit")
	fmt.Println("  version    Print build version")
	fmt.Println()
	fmt.Printf("Examples:\n")
	fmt.Printf("  xdr-agent run --config %s\n", config.DefaultConfigPath)
	fmt.Printf("  xdr-agent enroll --config %s\n", config.DefaultConfigPath)
}
