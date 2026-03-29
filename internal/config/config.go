package config

import (
	"encoding/json"
	"os"
	"strconv"
	"time"
)

type Config struct {
	// NodeLoom backend connection
	Endpoint string `json:"endpoint"`
	APIKey   string `json:"api_key"`

	// Probe identity
	Hostname    string `json:"hostname"`
	ClusterName string `json:"cluster_name"`

	// Timing
	HeartbeatInterval time.Duration `json:"heartbeat_interval"`
	BatchInterval     time.Duration `json:"batch_interval"`
	BatchSize         int           `json:"batch_size"`

	// LLM endpoints to monitor
	LLMEndpoints []string `json:"llm_endpoints"`

	// Guardrail patterns (PII, prompt injection)
	PIIPatterns             []string `json:"pii_patterns"`
	PromptInjectionPatterns []string `json:"prompt_injection_patterns"`

	// Enforcement
	BlockedEndpoints   []string `json:"blocked_endpoints"`
	RateLimitPerMinute int      `json:"rate_limit_per_minute"`

	// Feature flags
	EnableEnforcement bool `json:"enable_enforcement"`
	EnableGuardrails  bool `json:"enable_guardrails"`
	EnableProcScan    bool `json:"enable_proc_scan"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := &Config{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	applyDefaults(cfg)
	return cfg, nil
}

func FromEnv() *Config {
	cfg := &Config{
		Endpoint:    getEnv("NODELOOM_ENDPOINT", "http://localhost:8080"),
		APIKey:      getEnv("NODELOOM_API_KEY", ""),
		Hostname:    getHostname(),
		ClusterName: getEnv("NODELOOM_CLUSTER_NAME", ""),
		LLMEndpoints: []string{
			"api.openai.com",
			"api.anthropic.com",
			"generativelanguage.googleapis.com",
			"api.cohere.ai",
			"api.mistral.ai",
			"api.together.xyz",
			"api.groq.com",
			"api.fireworks.ai",
			"api.perplexity.ai",
		},
		PIIPatterns: []string{
			`\b\d{3}-\d{2}-\d{4}\b`,
			`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`,
			`\b\d{16}\b`,
			`\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b`,
		},
		PromptInjectionPatterns: []string{
			`(?i)ignore\s+(previous|above|all)\s+(instructions|prompts?)`,
			`(?i)you\s+are\s+now\s+(DAN|jailbroken|unrestricted)`,
			`(?i)system\s*:\s*you\s+are`,
			`(?i)disregard\s+(your|all)\s+(previous|prior)`,
		},
		EnableEnforcement: getEnvBool("NODELOOM_ENABLE_ENFORCEMENT", false),
		EnableGuardrails:  getEnvBool("NODELOOM_ENABLE_GUARDRAILS", true),
		EnableProcScan:    getEnvBool("NODELOOM_ENABLE_PROC_SCAN", true),
	}
	applyDefaults(cfg)
	return cfg
}

func applyDefaults(cfg *Config) {
	if cfg.Hostname == "" {
		cfg.Hostname = getHostname()
	}
	if cfg.HeartbeatInterval == 0 {
		cfg.HeartbeatInterval = 30 * time.Second
	}
	if cfg.BatchInterval == 0 {
		cfg.BatchInterval = 5 * time.Second
	}
	if cfg.BatchSize == 0 {
		cfg.BatchSize = 50
	}
	if cfg.RateLimitPerMinute == 0 {
		cfg.RateLimitPerMinute = 1000
	}
}

func getHostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return h
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvBool(key string, fallback bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return b
}
