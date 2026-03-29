package interceptor

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// ProcInterceptor is a fallback that monitors /proc for LLM API connections.
// It cannot intercept request/response content, but can detect which processes
// are connecting to LLM endpoints and count connections.
type ProcInterceptor struct {
	llmEndpoints map[string]bool
	eventCh      chan LLMCallEvent
	stopCh       chan struct{}
	stats        struct {
		processes atomic.Int64
		calls     atomic.Int64
	}
	resolvedIPs map[string]string // IP -> hostname
}

func NewProcInterceptor(endpoints []string) *ProcInterceptor {
	endpointMap := make(map[string]bool)
	resolvedIPs := make(map[string]string)
	for _, ep := range endpoints {
		endpointMap[ep] = true
		// Resolve IPs
		ips, err := net.LookupHost(ep)
		if err == nil {
			for _, ip := range ips {
				resolvedIPs[ip] = ep
			}
		}
	}

	return &ProcInterceptor{
		llmEndpoints: endpointMap,
		eventCh:      make(chan LLMCallEvent, 1024),
		stopCh:       make(chan struct{}),
		resolvedIPs:  resolvedIPs,
	}
}

func (p *ProcInterceptor) Start(ctx context.Context) (<-chan LLMCallEvent, error) {
	log.Println("Proc-based interceptor started (monitoring /proc/net/tcp connections)")

	go p.scanLoop(ctx)

	return p.eventCh, nil
}

func (p *ProcInterceptor) Stop() {
	select {
	case p.stopCh <- struct{}{}:
	default:
	}
}

func (p *ProcInterceptor) Stats() InterceptorStats {
	return InterceptorStats{
		ProcessesMonitored:   int(p.stats.processes.Load()),
		LLMCallsIntercepted: p.stats.calls.Load(),
	}
}

func (p *ProcInterceptor) scanLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	defer close(p.eventCh)

	seenConnections := make(map[string]bool) // "pid:remoteIP:remotePort"
	sweepCounter := 0

	for {
		select {
		case <-ctx.Done():
			return
		case <-p.stopCh:
			return
		case <-ticker.C:
			// Periodically clear stale entries to prevent unbounded memory growth
			sweepCounter++
			if sweepCounter >= 360 { // every ~30 minutes at 5s interval
				seenConnections = make(map[string]bool)
				sweepCounter = 0
			}

			connections := p.scanTCPConnections()
			processSet := make(map[int]bool)

			for _, conn := range connections {
				key := fmt.Sprintf("%d:%s:%d", conn.pid, conn.remoteIP, conn.remotePort)
				if seenConnections[key] {
					continue
				}
				seenConnections[key] = true

				processSet[conn.pid] = true
				p.stats.calls.Add(1)

				event := LLMCallEvent{
					ProcessName: conn.processName,
					PID:         conn.pid,
					Executable:  conn.executable,
					Host:        conn.hostname,
					StartTime:   time.Now().UnixNano(),
					EndTime:     time.Now().UnixNano(),
					Provider:    inferProvider(conn.hostname),
				}

				select {
				case p.eventCh <- event:
				default:
				}
			}

			p.stats.processes.Store(int64(len(processSet)))
		}
	}
}

type tcpConnection struct {
	pid         int
	processName string
	executable  string
	remoteIP    string
	remotePort  int
	hostname    string
}

func (p *ProcInterceptor) scanTCPConnections() []tcpConnection {
	var connections []tcpConnection

	procDirs, err := filepath.Glob("/proc/[0-9]*/net/tcp")
	if err != nil {
		return connections
	}

	for _, tcpFile := range procDirs {
		parts := strings.Split(tcpFile, "/")
		if len(parts) < 3 {
			continue
		}
		pid, err := strconv.Atoi(parts[2])
		if err != nil {
			continue
		}

		f, err := os.Open(tcpFile)
		if err != nil {
			continue
		}

		scanner := bufio.NewScanner(f)
		scanner.Scan() // skip header

		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 4 {
				continue
			}

			// Parse remote address (field 2)
			remoteAddr := fields[2]
			remoteIP, remotePort := parseHexAddr(remoteAddr)
			if remotePort != 443 {
				continue
			}

			// Check if this IP belongs to a known LLM endpoint
			if hostname, ok := p.resolvedIPs[remoteIP]; ok {
				procName := readProcName(pid)
				exe := readProcExe(pid)
				connections = append(connections, tcpConnection{
					pid:         pid,
					processName: procName,
					executable:  exe,
					remoteIP:    remoteIP,
					remotePort:  remotePort,
					hostname:    hostname,
				})
			}
		}
		f.Close()
	}

	return connections
}

func parseHexAddr(hexAddr string) (string, int) {
	parts := strings.Split(hexAddr, ":")
	if len(parts) != 2 {
		return "", 0
	}

	hexIP := parts[0]
	hexPort := parts[1]

	port, err := strconv.ParseInt(hexPort, 16, 32)
	if err != nil {
		return "", 0
	}

	if len(hexIP) != 8 {
		return "", 0
	}

	// Convert hex IP (little-endian on x86)
	b0, _ := strconv.ParseUint(hexIP[6:8], 16, 8)
	b1, _ := strconv.ParseUint(hexIP[4:6], 16, 8)
	b2, _ := strconv.ParseUint(hexIP[2:4], 16, 8)
	b3, _ := strconv.ParseUint(hexIP[0:2], 16, 8)

	return fmt.Sprintf("%d.%d.%d.%d", b0, b1, b2, b3), int(port)
}

func readProcName(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(data))
}

func readProcExe(pid int) string {
	exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return ""
	}
	return exe
}

func inferProvider(hostname string) string {
	switch {
	case strings.Contains(hostname, "openai"):
		return "openai"
	case strings.Contains(hostname, "anthropic"):
		return "anthropic"
	case strings.Contains(hostname, "googleapis"):
		return "google"
	case strings.Contains(hostname, "cohere"):
		return "cohere"
	case strings.Contains(hostname, "mistral"):
		return "mistral"
	case strings.Contains(hostname, "together"):
		return "together"
	case strings.Contains(hostname, "groq"):
		return "groq"
	case strings.Contains(hostname, "fireworks"):
		return "fireworks"
	case strings.Contains(hostname, "perplexity"):
		return "perplexity"
	default:
		return "unknown"
	}
}
