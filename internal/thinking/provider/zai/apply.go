package zai

import (
	"fmt"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/thinking"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// Applier implements thinking.ProviderApplier for Z.AI / AutoClaw models.
//
// ZAI-specific behavior (matching AutoClaw client):
//   - GLM-5.2 (BigModel / official GLM-5.2):
//     Enabled:  thinking.type="enabled" + optional reasoning_effort="<level>"
//     Disabled: thinking.type="disabled"
//   - General ZAI models:
//     Enabled:  thinking.type="enabled" + thinking.clear_thinking=false + enable_thinking=true (+ optional reasoning_effort)
//     Disabled: thinking.type="disabled"
type Applier struct{}

var _ thinking.ProviderApplier = (*Applier)(nil)

// NewApplier creates a new ZAI thinking applier.
func NewApplier() *Applier {
	return &Applier{}
}

func init() {
	thinking.RegisterProvider("zai", NewApplier())
}

// Apply applies thinking configuration to a ZAI request body.
func (a *Applier) Apply(body []byte, config thinking.ThinkingConfig, modelInfo *registry.ModelInfo) ([]byte, error) {
	if len(body) == 0 || !gjson.ValidBytes(body) {
		body = []byte(`{}`)
	}

	modelID := ""
	if modelInfo != nil {
		modelID = modelInfo.ID
	}
	if modelID == "" {
		modelID = gjson.GetBytes(body, "model").String()
	}

	isGlm52 := isBigModelGLM52(modelID)

	if isDisabled(config) {
		return applyDisabledThinking(body, isGlm52)
	}

	effort := resolveEffort(config, modelInfo)
	return applyEnabledThinking(body, effort, isGlm52)
}

func isBigModelGLM52(modelID string) bool {
	m := strings.ToLower(strings.TrimSpace(modelID))
	if idx := strings.LastIndex(m, "/"); idx >= 0 {
		m = m[idx+1:]
	}
	return strings.HasSuffix(m, "glm-5.2") || strings.Contains(m, "glm-5.2")
}

func isDisabled(config thinking.ThinkingConfig) bool {
	if config.Mode == thinking.ModeNone {
		return true
	}
	if config.Mode == thinking.ModeBudget && config.Budget == 0 {
		return true
	}
	lvl := strings.ToLower(strings.TrimSpace(string(config.Level)))
	return lvl == "none" || lvl == "off"
}

func resolveEffort(config thinking.ThinkingConfig, modelInfo *registry.ModelInfo) string {
	switch config.Mode {
	case thinking.ModeLevel:
		return strings.ToLower(strings.TrimSpace(string(config.Level)))
	case thinking.ModeBudget:
		if config.Budget > 0 {
			if lvl, ok := thinking.ConvertBudgetToLevel(config.Budget); ok {
				return lvl
			}
		}
	case thinking.ModeAuto:
		return ""
	}
	return ""
}

func applyDisabledThinking(body []byte, isGlm52 bool) ([]byte, error) {
	result := body
	var err error
	result, err = sjson.DeleteBytes(result, "reasoning_effort")
	if err != nil {
		return body, fmt.Errorf("zai thinking: failed to delete reasoning_effort: %w", err)
	}
	result, err = sjson.DeleteBytes(result, "enable_thinking")
	if err != nil {
		return body, fmt.Errorf("zai thinking: failed to delete enable_thinking: %w", err)
	}
	result, err = sjson.DeleteBytes(result, "chat_template_kwargs.enable_thinking")
	if err != nil {
		return body, fmt.Errorf("zai thinking: failed to delete chat_template_kwargs: %w", err)
	}
	result, err = sjson.SetBytes(result, "thinking.type", "disabled")
	if err != nil {
		return body, fmt.Errorf("zai thinking: failed to set thinking.type: %w", err)
	}
	result, _ = sjson.DeleteBytes(result, "thinking.clear_thinking")
	result, _ = sjson.DeleteBytes(result, "thinking.effort")
	result, _ = sjson.DeleteBytes(result, "thinking.budget_tokens")
	return result, nil
}

func applyEnabledThinking(body []byte, effort string, isGlm52 bool) ([]byte, error) {
	result := body
	var err error

	result, err = sjson.SetBytes(result, "thinking.type", "enabled")
	if err != nil {
		return body, fmt.Errorf("zai thinking: failed to set thinking.type: %w", err)
	}

	if isGlm52 {
		result, _ = sjson.DeleteBytes(result, "thinking.clear_thinking")
		result, _ = sjson.DeleteBytes(result, "enable_thinking")
		if effort != "" && effort != "none" && effort != "off" {
			result, err = sjson.SetBytes(result, "reasoning_effort", effort)
			if err != nil {
				return body, fmt.Errorf("zai thinking: failed to set reasoning_effort: %w", err)
			}
		} else {
			result, _ = sjson.DeleteBytes(result, "reasoning_effort")
		}
	} else {
		result, err = sjson.SetBytes(result, "thinking.clear_thinking", false)
		if err != nil {
			return body, fmt.Errorf("zai thinking: failed to set thinking.clear_thinking: %w", err)
		}
		result, err = sjson.SetBytes(result, "enable_thinking", true)
		if err != nil {
			return body, fmt.Errorf("zai thinking: failed to set enable_thinking: %w", err)
		}
		if effort != "" && effort != "none" && effort != "off" {
			result, err = sjson.SetBytes(result, "reasoning_effort", effort)
			if err != nil {
				return body, fmt.Errorf("zai thinking: failed to set reasoning_effort: %w", err)
			}
		}
	}

	return result, nil
}
