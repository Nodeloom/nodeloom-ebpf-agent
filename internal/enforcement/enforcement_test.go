package enforcement

import (
	"testing"
)

func TestEngine_ShouldBlock(t *testing.T) {
	e := NewEngine([]string{"blocked.api.com"}, 100)

	if !e.ShouldBlock("blocked.api.com") {
		t.Error("should block blocked endpoint")
	}
	if e.ShouldBlock("api.openai.com") {
		t.Error("should not block non-blocked endpoint")
	}
}

func TestEngine_BlockUnblock(t *testing.T) {
	e := NewEngine(nil, 100)

	if e.ShouldBlock("new.api.com") {
		t.Error("should not be blocked initially")
	}

	e.BlockEndpoint("new.api.com")
	if !e.ShouldBlock("new.api.com") {
		t.Error("should be blocked after BlockEndpoint")
	}

	e.UnblockEndpoint("new.api.com")
	if e.ShouldBlock("new.api.com") {
		t.Error("should not be blocked after UnblockEndpoint")
	}
}

func TestEngine_CheckRateLimit(t *testing.T) {
	e := NewEngine(nil, 3) // 3 per minute

	// First 3 should pass
	for i := 0; i < 3; i++ {
		if e.CheckRateLimit(1234) {
			t.Errorf("call %d should not be rate limited", i+1)
		}
	}

	// 4th should be rate limited
	if !e.CheckRateLimit(1234) {
		t.Error("4th call should be rate limited")
	}

	// Different PID should not be affected
	if e.CheckRateLimit(5678) {
		t.Error("different PID should not be rate limited")
	}
}

func TestEngine_Evaluate(t *testing.T) {
	e := NewEngine([]string{"blocked.com"}, 100)

	// Blocked endpoint
	action := e.Evaluate(1, "blocked.com", nil)
	if action.Type != ActionBlock {
		t.Errorf("expected block, got %s", action.Type)
	}

	// Normal
	action = e.Evaluate(1, "api.openai.com", nil)
	if action.Type != ActionAllow {
		t.Errorf("expected allow, got %s", action.Type)
	}

	// Violations
	action = e.Evaluate(1, "api.openai.com", []string{"pii_detected"})
	if action.Type != ActionAlert {
		t.Errorf("expected alert, got %s", action.Type)
	}
}
