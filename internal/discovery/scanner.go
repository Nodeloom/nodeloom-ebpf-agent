package discovery

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// DiscoveredProcess represents a process found making LLM API calls.
type DiscoveredProcess struct {
	ProcessName    string `json:"processName"`
	ExecutablePath string `json:"executablePath,omitempty"`
	CommandLine    string `json:"commandLine,omitempty"`
	PID            int    `json:"pid"`
	CgroupPath     string `json:"cgroupPath,omitempty"`
	ContainerID    string `json:"containerId,omitempty"`
	K8sPodName     string `json:"k8sPodName,omitempty"`
	K8sNamespace   string `json:"k8sNamespace,omitempty"`
	LLMCallCount   int64  `json:"llmCallCount"`
}

// ProcessScanner scans /proc for processes with LLM API connections.
type ProcessScanner struct {
	llmEndpoints map[string]bool
	discovered   map[int]*DiscoveredProcess // pid -> process
	mu           sync.RWMutex
}

func NewProcessScanner(endpoints []string) *ProcessScanner {
	endpointMap := make(map[string]bool)
	for _, ep := range endpoints {
		endpointMap[ep] = true
	}
	return &ProcessScanner{
		llmEndpoints: endpointMap,
		discovered:   make(map[int]*DiscoveredProcess),
	}
}

// Scan performs a full /proc scan looking for processes with:
// 1. TCP connections to known LLM endpoints (port 443)
// 2. Environment variables like OPENAI_API_KEY
// 3. Loaded libraries suggesting AI frameworks
func (ps *ProcessScanner) Scan() []*DiscoveredProcess {
	var results []*DiscoveredProcess

	procDirs, err := filepath.Glob("/proc/[0-9]*")
	if err != nil {
		log.Printf("Failed to scan /proc: %v", err)
		return results
	}

	for _, dir := range procDirs {
		pidStr := filepath.Base(dir)
		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			continue
		}

		if ps.hasLLMIndicators(pid) {
			proc := ps.gatherProcessInfo(pid)
			if proc != nil {
				results = append(results, proc)
				ps.mu.Lock()
				ps.discovered[pid] = proc
				ps.mu.Unlock()
			}
		}
	}

	return results
}

// GetDiscovered returns currently known discovered processes.
func (ps *ProcessScanner) GetDiscovered() []*DiscoveredProcess {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	result := make([]*DiscoveredProcess, 0, len(ps.discovered))
	for _, p := range ps.discovered {
		result = append(result, p)
	}
	return result
}

// RecordCall updates the LLM call count for a process.
func (ps *ProcessScanner) RecordCall(pid int) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if p, ok := ps.discovered[pid]; ok {
		p.LLMCallCount++
	}
}

func (ps *ProcessScanner) hasLLMIndicators(pid int) bool {
	// Check 1: Environment variables
	if ps.hasLLMEnvVars(pid) {
		return true
	}

	// Check 2: Loaded libraries (Python AI frameworks)
	if ps.hasAILibraries(pid) {
		return true
	}

	return false
}

func (ps *ProcessScanner) hasLLMEnvVars(pid int) bool {
	envFile := fmt.Sprintf("/proc/%d/environ", pid)
	data, err := os.ReadFile(envFile)
	if err != nil {
		return false
	}

	envVars := strings.Split(string(data), "\x00")
	llmEnvKeys := []string{
		"OPENAI_API_KEY",
		"ANTHROPIC_API_KEY",
		"GOOGLE_API_KEY",
		"COHERE_API_KEY",
		"MISTRAL_API_KEY",
		"TOGETHER_API_KEY",
		"GROQ_API_KEY",
		"NODELOOM_API_KEY",
	}

	for _, env := range envVars {
		for _, key := range llmEnvKeys {
			if strings.HasPrefix(env, key+"=") {
				return true
			}
		}
	}
	return false
}

func (ps *ProcessScanner) hasAILibraries(pid int) bool {
	mapsFile := fmt.Sprintf("/proc/%d/maps", pid)
	data, err := os.ReadFile(mapsFile)
	if err != nil {
		return false
	}

	content := string(data)
	aiLibs := []string{
		"openai",
		"anthropic",
		"langchain",
		"llama_index",
		"transformers",
		"torch",
		"tensorflow",
	}

	for _, lib := range aiLibs {
		if strings.Contains(content, lib) {
			return true
		}
	}
	return false
}

func (ps *ProcessScanner) gatherProcessInfo(pid int) *DiscoveredProcess {
	proc := &DiscoveredProcess{PID: pid}

	// Process name
	commData, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return nil
	}
	proc.ProcessName = strings.TrimSpace(string(commData))

	// Executable path
	exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err == nil {
		proc.ExecutablePath = exe
	}

	// Command line
	cmdData, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err == nil {
		proc.CommandLine = strings.ReplaceAll(string(cmdData), "\x00", " ")
		proc.CommandLine = strings.TrimSpace(proc.CommandLine)
	}

	// Cgroup (for container detection)
	cgroupData, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err == nil {
		proc.CgroupPath = strings.TrimSpace(string(cgroupData))
		proc.ContainerID = extractContainerID(proc.CgroupPath)
	}

	// K8s metadata from environment or downward API
	proc.K8sPodName = readEnvVar(pid, "HOSTNAME")
	proc.K8sNamespace = readEnvVar(pid, "POD_NAMESPACE")
	if proc.K8sNamespace == "" {
		proc.K8sNamespace = readEnvVar(pid, "KUBERNETES_NAMESPACE")
	}

	return proc
}

func extractContainerID(cgroupPath string) string {
	lines := strings.Split(cgroupPath, "\n")
	for _, line := range lines {
		// Docker: /docker/<container_id>
		if idx := strings.LastIndex(line, "/docker/"); idx >= 0 {
			id := line[idx+8:]
			if len(id) >= 12 {
				return id[:12]
			}
		}
		// K8s: /kubepods/.../cri-containerd-<id>
		if idx := strings.LastIndex(line, "cri-containerd-"); idx >= 0 {
			id := line[idx+15:]
			if dotIdx := strings.Index(id, "."); dotIdx > 0 {
				id = id[:dotIdx]
			}
			if len(id) >= 12 {
				return id[:12]
			}
		}
	}
	return ""
}

func readEnvVar(pid int, key string) string {
	envFile := fmt.Sprintf("/proc/%d/environ", pid)
	data, err := os.ReadFile(envFile)
	if err != nil {
		return ""
	}
	for _, env := range strings.Split(string(data), "\x00") {
		if strings.HasPrefix(env, key+"=") {
			return strings.TrimPrefix(env, key+"=")
		}
	}
	return ""
}
