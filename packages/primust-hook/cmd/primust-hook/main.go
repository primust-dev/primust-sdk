package main

import (
	"fmt"
	"os"

	"github.com/primust-dev/primust-hook/internal/config"
	"github.com/primust-dev/primust-hook/internal/hook"
	"github.com/primust-dev/primust-hook/internal/policy"
	"github.com/primust-dev/primust-hook/internal/transport"
)

var version = "dev"

func main() {
	// primust-hook NEVER blocks. Exit 0 always.
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "primust-hook: panic recovered: %v\n", r)
		}
		os.Exit(0)
	}()

	if len(os.Args) < 2 {
		runCheck()
		return
	}

	switch os.Args[1] {
	case "run":
		runDaemon()
	case "check":
		runCheck()
	case "status":
		runStatus()
	case "version":
		fmt.Fprintf(os.Stdout, "primust-hook %s\n", version)
	default:
		fmt.Fprintf(os.Stderr, "primust-hook: unknown command %q\n", os.Args[1])
		fmt.Fprintf(os.Stderr, "Usage: primust-hook [run|check|status|version]\n")
	}
}

func runCheck() {
	cfg := config.Load()
	pol := policy.LoadPolicy(cfg)
	client := transport.NewClient(cfg)

	interceptor := hook.NewInterceptor(pol, client, cfg)
	interceptor.RunOnce(os.Stdin, os.Stderr)
}

func runDaemon() {
	cfg := config.Load()
	client := transport.NewClient(cfg)

	// Start policy refresh loop
	pol := policy.LoadPolicy(cfg)
	go policy.RefreshLoop(cfg, func(p *policy.Policy) {
		// In daemon mode we would update the running interceptor's policy.
		// For now, just log the refresh.
		_ = p
	})

	fmt.Fprintf(os.Stderr, "primust-hook: daemon started (policy bundle=%s)\n", pol.BundleID)

	interceptor := hook.NewInterceptor(pol, client, cfg)
	interceptor.RunDaemon(os.Stdin, os.Stderr)
}

func runStatus() {
	cfg := config.Load()
	pol := policy.LoadPolicy(cfg)

	fmt.Fprintf(os.Stdout, "primust-hook %s\n", version)
	fmt.Fprintf(os.Stdout, "API URL:    %s\n", cfg.APIURL)
	if cfg.APIKey != "" {
		fmt.Fprintf(os.Stdout, "API Key:    %s...%s\n", cfg.APIKey[:4], cfg.APIKey[len(cfg.APIKey)-4:])
	} else {
		fmt.Fprintf(os.Stdout, "API Key:    (not configured — observability-only mode)\n")
	}
	fmt.Fprintf(os.Stdout, "Policy:     bundle=%s checks=%d\n", pol.BundleID, len(pol.Checks))
	fmt.Fprintf(os.Stdout, "Log:        %s\n", cfg.LogPath)
}
