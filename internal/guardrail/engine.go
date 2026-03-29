package guardrail

import (
	"log"
	"regexp"
	"strings"
)

// Engine performs local guardrail checks on intercepted plaintext.
type Engine struct {
	piiPatterns             []*regexp.Regexp
	promptInjectionPatterns []*regexp.Regexp
}

func NewEngine(piiPatterns, injectionPatterns []string) *Engine {
	e := &Engine{}

	for _, p := range piiPatterns {
		r, err := regexp.Compile(p)
		if err != nil {
			log.Printf("Invalid PII pattern '%s': %v", p, err)
			continue
		}
		e.piiPatterns = append(e.piiPatterns, r)
	}

	for _, p := range injectionPatterns {
		r, err := regexp.Compile(p)
		if err != nil {
			log.Printf("Invalid injection pattern '%s': %v", p, err)
			continue
		}
		e.promptInjectionPatterns = append(e.promptInjectionPatterns, r)
	}

	return e
}

// Check runs all guardrail checks on the given text and returns violations.
func (e *Engine) Check(text string) []string {
	if text == "" {
		return nil
	}

	var violations []string

	// Check PII patterns
	for _, r := range e.piiPatterns {
		if r.MatchString(text) {
			violations = append(violations, "pii_detected:"+r.String())
		}
	}

	// Check prompt injection patterns
	for _, r := range e.promptInjectionPatterns {
		if r.MatchString(text) {
			violations = append(violations, "prompt_injection:"+r.String())
		}
	}

	return violations
}

// CheckPII specifically checks for PII patterns.
func (e *Engine) CheckPII(text string) []string {
	var found []string
	for _, r := range e.piiPatterns {
		matches := r.FindAllString(text, -1)
		for _, m := range matches {
			found = append(found, maskPII(m))
		}
	}
	return found
}

// CheckPromptInjection specifically checks for prompt injection patterns.
func (e *Engine) CheckPromptInjection(text string) bool {
	for _, r := range e.promptInjectionPatterns {
		if r.MatchString(text) {
			return true
		}
	}
	return false
}

func maskPII(s string) string {
	if len(s) <= 4 {
		return strings.Repeat("*", len(s))
	}
	return s[:2] + strings.Repeat("*", len(s)-4) + s[len(s)-2:]
}
