package interceptor

import "context"

// LLMCallEvent represents an intercepted LLM API call.
type LLMCallEvent struct {
	ProcessName  string
	PID          int
	Executable   string
	CommandLine  string
	CgroupPath   string
	ContainerID  string
	K8sPodName   string
	K8sNamespace string

	// HTTP data
	Method       string
	Host         string
	Path         string
	RequestBody  string
	ResponseBody string
	StatusCode   int

	// Timing
	StartTime    int64 // unix nano
	EndTime      int64 // unix nano
	DurationMs   int64

	// Extracted data (populated by assembler)
	Model            string
	PromptTokens     int
	CompletionTokens int
	TotalTokens      int
	Provider         string

	// Guardrail results
	GuardrailViolations []string
}

// InterceptorStats holds aggregate stats from the interceptor.
type InterceptorStats struct {
	ProcessesMonitored  int
	LLMCallsIntercepted int64
}

// Interceptor is the interface for LLM call interception.
type Interceptor interface {
	Start(ctx context.Context) (<-chan LLMCallEvent, error)
	Stop()
	Stats() InterceptorStats
}
