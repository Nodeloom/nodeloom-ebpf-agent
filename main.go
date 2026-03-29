package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nodeloom/nodeloom-ebpf-agent/internal/agent"
	"github.com/nodeloom/nodeloom-ebpf-agent/internal/config"
)

func main() {
	configPath := flag.String("config", "/etc/nodeloom-ebpf/config.yaml", "Path to config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		// Fall back to environment variables
		cfg = config.FromEnv()
	}

	if cfg.APIKey == "" {
		log.Fatal("NODELOOM_API_KEY is required")
	}
	if cfg.Endpoint == "" {
		cfg.Endpoint = "http://localhost:8080"
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	a, err := agent.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create agent: %v", err)
	}

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("Shutting down...")
		cancel()
	}()

	log.Printf("NodeLoom eBPF Agent starting (endpoint=%s, hostname=%s)", cfg.Endpoint, cfg.Hostname)

	if err := a.Run(ctx); err != nil && ctx.Err() == nil {
		log.Fatalf("Agent error: %v", err)
	}

	// Allow time for final flush
	time.Sleep(2 * time.Second)
	log.Println("NodeLoom eBPF Agent stopped")
}
