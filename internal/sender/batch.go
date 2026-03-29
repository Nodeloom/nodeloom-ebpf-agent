package sender

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/nodeloom/nodeloom-ebpf-agent/internal/config"
	"github.com/nodeloom/nodeloom-ebpf-agent/internal/discovery"
	"github.com/nodeloom/nodeloom-ebpf-agent/internal/telemetry"
)

// BatchSender batches telemetry events and sends them to the NodeLoom backend.
type BatchSender struct {
	client    *http.Client
	endpoint  string
	apiKey    string
	batchSize int
	interval  time.Duration

	queue  []*telemetry.TelemetryEvent
	mu     sync.Mutex
	stopCh chan struct{}
}

func NewBatchSender(endpoint, apiKey string, batchSize int, interval time.Duration) *BatchSender {
	return &BatchSender{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		endpoint:  endpoint,
		apiKey:    apiKey,
		batchSize: batchSize,
		interval:  interval,
		queue:     make([]*telemetry.TelemetryEvent, 0, batchSize),
		stopCh:    make(chan struct{}),
	}
}

// Enqueue adds a telemetry event to the batch queue.
func (bs *BatchSender) Enqueue(event *telemetry.TelemetryEvent) {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	bs.queue = append(bs.queue, event)

	if len(bs.queue) >= bs.batchSize {
		bs.flushLocked()
	}
}

// Start begins the periodic flush loop.
func (bs *BatchSender) Start(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(bs.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-bs.stopCh:
				return
			case <-ticker.C:
				bs.Flush()
			}
		}
	}()
}

// Flush sends all queued events.
func (bs *BatchSender) Flush() {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	bs.flushLocked()
}

func (bs *BatchSender) flushLocked() {
	if len(bs.queue) == 0 {
		return
	}

	events := bs.queue
	bs.queue = make([]*telemetry.TelemetryEvent, 0, bs.batchSize)

	go bs.sendBatch(events)
}

func (bs *BatchSender) sendBatch(events []*telemetry.TelemetryEvent) {
	rawEvents := make([]json.RawMessage, 0, len(events))
	for _, e := range events {
		data, err := json.Marshal(e)
		if err != nil {
			log.Printf("Failed to marshal event: %v", err)
			continue
		}
		rawEvents = append(rawEvents, data)
	}

	batch := telemetry.BatchRequest{
		Events:      rawEvents,
		SDKVersion:  "ebpf-agent/1.0.0",
		SDKLanguage: "go",
	}

	data, err := json.Marshal(batch)
	if err != nil {
		log.Printf("Failed to marshal batch: %v", err)
		return
	}

	url := bs.endpoint + "/api/sdk/v1/telemetry"
	req, err := http.NewRequest("POST", url, bytes.NewReader(data))
	if err != nil {
		log.Printf("Failed to create request: %v", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bs.apiKey)

	resp, err := bs.client.Do(req)
	if err != nil {
		log.Printf("Failed to send batch (%d events): %v", len(events), err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("Batch send failed (status %d): %s", resp.StatusCode, string(body))
		return
	}

	log.Printf("Sent batch of %d telemetry events", len(events))
}

// RegisterProbe registers the probe with the NodeLoom backend.
func (bs *BatchSender) RegisterProbe(ctx context.Context, cfg *config.Config) (string, error) {
	payload := map[string]interface{}{
		"hostname":      cfg.Hostname,
		"clusterName":   cfg.ClusterName,
		"kernelVersion": getKernelVersion(),
		"agentVersion":  "1.0.0",
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal registration: %w", err)
	}

	url := bs.endpoint + "/api/sdk/v1/ebpf/register"
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bs.apiKey)

	resp, err := bs.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("registration failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("registration failed (status %d): %s", resp.StatusCode, string(body))
	}

	var result struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	return result.ID, nil
}

// SendHeartbeat sends a heartbeat to the backend.
func (bs *BatchSender) SendHeartbeat(ctx context.Context, probeID string, processesMonitored int, llmCalls int64, procs []*discovery.DiscoveredProcess) error {
	payload := map[string]interface{}{
		"processesMonitored":  processesMonitored,
		"llmCallsIntercepted": llmCalls,
	}

	if len(procs) > 0 {
		procReports := make([]map[string]interface{}, 0, len(procs))
		for _, p := range procs {
			procReports = append(procReports, map[string]interface{}{
				"processName":    p.ProcessName,
				"executablePath": p.ExecutablePath,
				"commandLine":    p.CommandLine,
				"pid":            p.PID,
				"cgroupPath":     p.CgroupPath,
				"containerId":    p.ContainerID,
				"k8sPodName":     p.K8sPodName,
				"k8sNamespace":   p.K8sNamespace,
				"llmCallCount":   p.LLMCallCount,
			})
		}
		payload["discoveredProcesses"] = procReports
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal heartbeat: %w", err)
	}

	url := fmt.Sprintf("%s/api/sdk/v1/ebpf/probes/%s/heartbeat", bs.endpoint, probeID)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(data))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bs.apiKey)

	resp, err := bs.client.Do(req)
	if err != nil {
		return fmt.Errorf("heartbeat failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("heartbeat failed (status %d): %s", resp.StatusCode, string(body))
	}

	return nil
}

// FetchConfig fetches probe configuration from the backend.
func (bs *BatchSender) FetchConfig(ctx context.Context, probeID string) {
	url := fmt.Sprintf("%s/api/sdk/v1/ebpf/probes/%s/config", bs.endpoint, probeID)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		log.Printf("Failed to create config request: %v", err)
		return
	}

	req.Header.Set("Authorization", "Bearer "+bs.apiKey)

	resp, err := bs.client.Do(req)
	if err != nil {
		log.Printf("Failed to fetch config: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("Fetched probe config: %s", string(body))
	}
}

func getKernelVersion() string {
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return "unknown"
	}
	parts := strings.Split(string(data), " ")
	if len(parts) >= 3 {
		return parts[2]
	}
	return "unknown"
}
