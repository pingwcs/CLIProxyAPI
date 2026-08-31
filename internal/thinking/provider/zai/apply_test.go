package zai

import (
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/thinking"
	"github.com/tidwall/gjson"
)

func TestZAIApplier_GLM52_Enabled(t *testing.T) {
	applier := NewApplier()
	modelInfo := &registry.ModelInfo{ID: "glm-5.2"}

	body := []byte(`{"model":"glm-5.2","messages":[{"role":"user","content":"hello"}]}`)
	cfg := thinking.ThinkingConfig{
		Mode:  thinking.ModeLevel,
		Level: thinking.LevelHigh,
	}

	result, err := applier.Apply(body, cfg, modelInfo)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := gjson.GetBytes(result, "thinking.type").String(); got != "enabled" {
		t.Errorf("thinking.type = %q, want 'enabled'", got)
	}
	if got := gjson.GetBytes(result, "reasoning_effort").String(); got != "high" {
		t.Errorf("reasoning_effort = %q, want 'high'", got)
	}
	if gjson.GetBytes(result, "thinking.clear_thinking").Exists() {
		t.Errorf("expected thinking.clear_thinking to be omitted for GLM-5.2")
	}
	if gjson.GetBytes(result, "enable_thinking").Exists() {
		t.Errorf("expected enable_thinking to be omitted for GLM-5.2")
	}
}

func TestZAIApplier_GLM52_Disabled(t *testing.T) {
	applier := NewApplier()
	modelInfo := &registry.ModelInfo{ID: "glm-5.2"}

	body := []byte(`{"model":"glm-5.2","reasoning_effort":"high","messages":[{"role":"user","content":"hello"}]}`)
	cfg := thinking.ThinkingConfig{
		Mode: thinking.ModeNone,
	}

	result, err := applier.Apply(body, cfg, modelInfo)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := gjson.GetBytes(result, "thinking.type").String(); got != "disabled" {
		t.Errorf("thinking.type = %q, want 'disabled'", got)
	}
	if gjson.GetBytes(result, "reasoning_effort").Exists() {
		t.Errorf("expected reasoning_effort to be removed when disabled")
	}
}

func TestZAIApplier_GeneralZai_Enabled(t *testing.T) {
	applier := NewApplier()
	modelInfo := &registry.ModelInfo{ID: "glm-4.7"}

	body := []byte(`{"model":"glm-4.7","messages":[{"role":"user","content":"hello"}]}`)
	cfg := thinking.ThinkingConfig{
		Mode:  thinking.ModeLevel,
		Level: thinking.LevelMedium,
	}

	result, err := applier.Apply(body, cfg, modelInfo)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := gjson.GetBytes(result, "thinking.type").String(); got != "enabled" {
		t.Errorf("thinking.type = %q, want 'enabled'", got)
	}
	if got := gjson.GetBytes(result, "thinking.clear_thinking").Bool(); got != false {
		t.Errorf("thinking.clear_thinking = %v, want false", got)
	}
	if got := gjson.GetBytes(result, "enable_thinking").Bool(); got != true {
		t.Errorf("enable_thinking = %v, want true", got)
	}
	if got := gjson.GetBytes(result, "reasoning_effort").String(); got != "medium" {
		t.Errorf("reasoning_effort = %q, want 'medium'", got)
	}
}

func TestZAIApplier_GeneralZai_Disabled(t *testing.T) {
	applier := NewApplier()
	modelInfo := &registry.ModelInfo{ID: "glm-4.7"}

	body := []byte(`{"model":"glm-4.7","enable_thinking":true,"reasoning_effort":"high","messages":[{"role":"user","content":"hello"}]}`)
	cfg := thinking.ThinkingConfig{
		Mode:   thinking.ModeBudget,
		Budget: 0,
	}

	result, err := applier.Apply(body, cfg, modelInfo)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := gjson.GetBytes(result, "thinking.type").String(); got != "disabled" {
		t.Errorf("thinking.type = %q, want 'disabled'", got)
	}
	if gjson.GetBytes(result, "enable_thinking").Exists() {
		t.Errorf("expected enable_thinking to be removed when disabled")
	}
	if gjson.GetBytes(result, "reasoning_effort").Exists() {
		t.Errorf("expected reasoning_effort to be removed when disabled")
	}
}

func TestZAIApplier_BudgetConversion(t *testing.T) {
	applier := NewApplier()
	modelInfo := &registry.ModelInfo{ID: "glm-4.7"}

	body := []byte(`{"model":"glm-4.7","messages":[{"role":"user","content":"hello"}]}`)
	cfg := thinking.ThinkingConfig{
		Mode:   thinking.ModeBudget,
		Budget: 16384,
	}

	result, err := applier.Apply(body, cfg, modelInfo)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := gjson.GetBytes(result, "thinking.type").String(); got != "enabled" {
		t.Errorf("thinking.type = %q, want 'enabled'", got)
	}
	if got := gjson.GetBytes(result, "reasoning_effort").String(); got != "high" {
		t.Errorf("reasoning_effort = %q, want 'high' (from 16384 budget)", got)
	}
}
