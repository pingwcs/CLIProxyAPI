package executor

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	zaiauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/zai"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	"github.com/tidwall/gjson"
)

func TestNormalizeZAIUpstreamModel(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"zai_auto", "auto"},
		{"zaicoding_glm-5.3", "glm-5.3"},
		{"zai_glm-5.3-flash", "glm-5.3-flash"},
		{"tdpsk_deepseek-v4-pro-202606", "deepseek-v4-pro-202606"},
		{"glm-5.3", "glm-5.3"},
	}

	for _, tt := range tests {
		got := normalizeZAIUpstreamModel(tt.input)
		if got != tt.want {
			t.Errorf("normalizeZAIUpstreamModel(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestApplyZAIHeaders(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "https://example.com", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer legacy-token")

	applyZAIHeaders(req, "test-token", "zai_auto", false)

	if req.Header.Get("Authorization") != "" {
		t.Errorf("expected Authorization header to be absent, got %q", req.Header.Get("Authorization"))
	}
	if got := req.Header.Get("X-Authorization"); got != "Bearer test-token" {
		t.Errorf("X-Authorization = %q, want 'Bearer test-token'", got)
	}
	if got := req.Header.Get("X-Harness-Type"); got != "zcode" {
		t.Errorf("X-Harness-Type = %q, want 'zcode'", got)
	}
	if got := req.Header.Get("X-Request-Model"); got != "zai_auto" {
		t.Errorf("X-Request-Model = %q, want 'zai_auto'", got)
	}
	if got := req.Header.Get("X-Product"); got != "autoclaw" {
		t.Errorf("X-Product = %q, want 'autoclaw'", got)
	}
	if got := req.Header.Get("X-Channel"); got != "zai" {
		t.Errorf("X-Channel = %q, want 'zai'", got)
	}
	if got := req.Header.Get("X-Client-Type"); got != "pc" {
		t.Errorf("X-Client-Type = %q, want 'pc'", got)
	}
	if req.Header.Get("X-Request-Id") == "" {
		t.Errorf("missing X-Request-Id")
	}
	if req.Header.Get("X-Session-Id") == "" {
		t.Errorf("missing X-Session-Id")
	}
	if got := req.Header.Get("X-Session-Key"); got == "" || got != "agent:main:"+req.Header.Get("X-Session-Id") {
		t.Errorf("X-Session-Key = %q, want 'agent:main:%s'", got, req.Header.Get("X-Session-Id"))
	}
	if got := req.Header.Get("Accept"); got != "*/*" {
		t.Errorf("Accept for non-stream = %q, want '*/*'", got)
	}

	streamReq, _ := http.NewRequest(http.MethodPost, "https://example.com", nil)
	applyZAIHeaders(streamReq, "test-token", "zai_auto", true)
	if got := streamReq.Header.Get("Accept"); got != "text/event-stream, */*" {
		t.Errorf("Accept for stream = %q, want 'text/event-stream, */*'", got)
	}

	// Preserves custom X-Session-Key if already set
	customSessionReq, _ := http.NewRequest(http.MethodPost, "https://example.com", nil)
	customSessionReq.Header.Set("X-Session-Key", "agent:custom:session-123")
	applyZAIHeaders(customSessionReq, "test-token", "zai_auto", false)
	if got := customSessionReq.Header.Get("X-Session-Key"); got != "agent:custom:session-123" {
		t.Errorf("X-Session-Key = %q, want 'agent:custom:session-123'", got)
	}
	wantUA := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36"
	if got := req.Header.Get("User-Agent"); got != wantUA {
		t.Errorf("User-Agent = %q, want %q", got, wantUA)
	}

	// Preserves custom User-Agent if already set
	customReq, _ := http.NewRequest(http.MethodPost, "https://example.com", nil)
	customReq.Header.Set("User-Agent", "CustomAgent/1.0")
	applyZAIHeaders(customReq, "test-token", "zai_auto", false)
	if got := customReq.Header.Get("User-Agent"); got != "CustomAgent/1.0" {
		t.Errorf("User-Agent = %q, want 'CustomAgent/1.0'", got)
	}
}

func TestZAICreds_BearerPrefixStripping(t *testing.T) {
	tests := []struct {
		name string
		auth *cliproxyauth.Auth
		want string
	}{
		{
			name: "metadata access_token with Bearer",
			auth: &cliproxyauth.Auth{
				Metadata: map[string]any{
					"access_token": "Bearer eyJhbGciOiJIUzI1NiJ9.metadata",
				},
			},
			want: "eyJhbGciOiJIUzI1NiJ9.metadata",
		},
		{
			name: "attributes access_token with lowercase bearer",
			auth: &cliproxyauth.Auth{
				Attributes: map[string]string{
					"access_token": "bearer   eyJhbGciOiJIUzI1NiJ9.attr_access",
				},
			},
			want: "eyJhbGciOiJIUzI1NiJ9.attr_access",
		},
		{
			name: "attributes api_key with uppercase BEARER",
			auth: &cliproxyauth.Auth{
				Attributes: map[string]string{
					"api_key": "BEARER eyJhbGciOiJIUzI1NiJ9.attr_apikey",
				},
			},
			want: "eyJhbGciOiJIUzI1NiJ9.attr_apikey",
		},
		{
			name: "metadata raw token without Bearer prefix",
			auth: &cliproxyauth.Auth{
				Metadata: map[string]any{
					"access_token": "eyJhbGciOiJIUzI1NiJ9.raw",
				},
			},
			want: "eyJhbGciOiJIUzI1NiJ9.raw",
		},
		{
			name: "nil auth",
			auth: nil,
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := zaiCreds(tt.auth)
			if got != tt.want {
				t.Errorf("zaiCreds() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestZAIExecutor_Execute_SSEAggregation(t *testing.T) {
	var receivedModel string
	var receivedStream bool
	var receivedRequestModel string
	var receivedXAuth string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedRequestModel = r.Header.Get("X-Request-Model")
		receivedXAuth = r.Header.Get("X-Authorization")

		bodyBytes, _ := io.ReadAll(r.Body)
		receivedModel = gjson.GetBytes(bodyBytes, "model").String()
		receivedStream = gjson.GetBytes(bodyBytes, "stream").Bool()

		w.Header().Set("Content-Type", "text/event-stream")
		flusher, ok := w.(http.Flusher)

		chunk1 := `data: {"id":"chatcmpl-1","object":"chat.completion.chunk","created":123456,"model":"auto","choices":[{"index":0,"delta":{"role":"assistant","reasoning_content":"thinking "},"finish_reason":null}]}` + "\n\n"
		chunk2 := `data: {"id":"chatcmpl-1","object":"chat.completion.chunk","created":123456,"model":"auto","choices":[{"index":0,"delta":{"content":"Hello world!","reasoning_content":"process"},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":20,"total_tokens":30}}` + "\n\n"
		chunkDone := "data: [DONE]\n\n"

		_, _ = w.Write([]byte(chunk1))
		if ok {
			flusher.Flush()
		}
		_, _ = w.Write([]byte(chunk2))
		if ok {
			flusher.Flush()
		}
		_, _ = w.Write([]byte(chunkDone))
		if ok {
			flusher.Flush()
		}
	}))
	defer server.Close()

	cfg := &config.Config{}
	exec := NewZAIExecutor(cfg)

	auth := &cliproxyauth.Auth{
		Provider: "zai",
		Metadata: map[string]any{
			"access_token": "secret-jwt",
			"base_url":     server.URL,
		},
	}

	reqPayload := []byte(`{"model":"zai_auto","messages":[{"role":"user","content":"hi"}]}`)
	req := cliproxyexecutor.Request{
		Model:   "zai_auto",
		Payload: reqPayload,
	}
	opts := cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FormatOpenAI,
	}

	ctx := context.WithValue(context.Background(), "cliproxy.roundtripper", server.Client().Transport)
	resp, err := exec.Execute(ctx, auth, req, opts)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if receivedModel != "auto" {
		t.Errorf("upstream received model %q, want 'auto'", receivedModel)
	}
	if !receivedStream {
		t.Errorf("upstream received stream=false, want true")
	}
	if receivedRequestModel != "zai_auto" {
		t.Errorf("upstream received X-Request-Model %q, want 'zai_auto'", receivedRequestModel)
	}
	if receivedXAuth != "Bearer secret-jwt" {
		t.Errorf("upstream received X-Authorization %q, want 'Bearer secret-jwt'", receivedXAuth)
	}

	content := gjson.GetBytes(resp.Payload, "choices.0.message.content").String()
	if content != "Hello world!" {
		t.Errorf("response content = %q, want 'Hello world!'", content)
	}

	reasoning := gjson.GetBytes(resp.Payload, "choices.0.message.reasoning_content").String()
	if reasoning != "thinking process" {
		t.Errorf("response reasoning_content = %q, want 'thinking process'", reasoning)
	}
}

func TestZAIExecutor_HostFailover(t *testing.T) {
	// Start an active secondary server
	secondaryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(`data: {"id":"chatcmpl-2","choices":[{"index":0,"delta":{"content":"success from secondary"},"finish_reason":"stop"}]}` + "\n\ndata: [DONE]\n\n"))
	}))
	defer secondaryServer.Close()

	// Get an unused closed port for dead server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	deadAddr := listener.Addr().String()
	_ = listener.Close()

	// Temporarily override defaultZAIUpstreams
	origUpstreams := defaultZAIUpstreams
	defaultZAIUpstreams = []string{
		"http://" + deadAddr,
		secondaryServer.URL,
	}
	defer func() {
		defaultZAIUpstreams = origUpstreams
	}()

	cfg := &config.Config{}
	exec := NewZAIExecutor(cfg)

	auth := &cliproxyauth.Auth{
		Provider: "zai",
		Metadata: map[string]any{
			"access_token": "token-123",
			"base_url":     "http://" + deadAddr,
		},
	}

	reqPayload := []byte(`{"model":"zai_auto","messages":[{"role":"user","content":"hi"}]}`)
	ctx := context.WithValue(context.Background(), "cliproxy.roundtripper", secondaryServer.Client().Transport)
	resp, err := exec.Execute(ctx, auth, cliproxyexecutor.Request{
		Model:   "zai_auto",
		Payload: reqPayload,
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FormatOpenAI,
	})

	if err != nil {
		t.Fatalf("Execute with failover failed: %v", err)
	}

	content := gjson.GetBytes(resp.Payload, "choices.0.message.content").String()
	if content != "success from secondary" {
		t.Errorf("content = %q, want 'success from secondary'", content)
	}
}

func TestZAIExecutor_Refresh(t *testing.T) {
	refreshServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		nowSec := time.Now().Unix() + 3600
		payload := fmt.Sprintf(`{"user_id":137721,"exp":%d}`, nowSec)
		fakeAccessJWT := "eyJhbGciOiJIUzI1NiJ9." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".dummySig"
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code": 0,
			"msg":  "",
			"data": map[string]any{
				"access_token":  fakeAccessJWT,
				"refresh_token": "rotated-refresh-token-xyz",
				"user_id":       137721,
				"user_name":     "autoclaw_user",
			},
		})
	}))
	defer refreshServer.Close()

	cfg := &config.Config{}
	exec := NewZAIExecutor(cfg)

	auth := &cliproxyauth.Auth{
		Provider: "zai",
		Metadata: map[string]any{
			"refresh_token":  "initial-refresh",
			"token_endpoint": refreshServer.URL + zaiauth.DefaultRefreshPath,
			"device_id":      "dev-999",
		},
	}

	ctx := context.WithValue(context.Background(), "cliproxy.roundtripper", refreshServer.Client().Transport)
	refreshed, err := exec.Refresh(ctx, auth)
	if err != nil {
		t.Fatalf("Refresh failed: %v", err)
	}

	if refreshed == nil || refreshed.Metadata == nil {
		t.Fatal("expected non-nil refreshed auth and metadata")
	}

	if refreshed.Metadata["refresh_token"] != "rotated-refresh-token-xyz" {
		t.Errorf("refresh_token = %v, want rotated-refresh-token-xyz", refreshed.Metadata["refresh_token"])
	}
	if refreshed.Metadata["last_refresh"] == nil || refreshed.Metadata["last_refresh"] == "" {
		t.Errorf("expected last_refresh to be set")
	}
	if refreshed.Metadata["access_expired"] == nil || refreshed.Metadata["access_expired"] == "" {
		t.Errorf("expected access_expired to be set")
	}
}

func TestZAIExecutor_Execute_ToolStream(t *testing.T) {
	var receivedToolStream bool
	var receivedTools gjson.Result

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		receivedToolStream = gjson.GetBytes(bodyBytes, "tool_stream").Bool()
		receivedTools = gjson.GetBytes(bodyBytes, "tools")

		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(`data: {"id":"chatcmpl-tool","choices":[{"index":0,"delta":{"content":"tool response"},"finish_reason":"stop"}]}` + "\n\ndata: [DONE]\n\n"))
	}))
	defer server.Close()

	cfg := &config.Config{}
	exec := NewZAIExecutor(cfg)

	auth := &cliproxyauth.Auth{
		Provider: "zai",
		Metadata: map[string]any{
			"access_token": "token-123",
			"base_url":     server.URL,
		},
	}

	// Case 1: with tools -> tool_stream: true
	reqPayloadWithTools := []byte(`{"model":"zai_auto","messages":[{"role":"user","content":"call tool"}],"tools":[{"type":"function","function":{"name":"test"}}]}`)
	ctx := context.WithValue(context.Background(), "cliproxy.roundtripper", server.Client().Transport)
	_, err := exec.Execute(ctx, auth, cliproxyexecutor.Request{
		Model:   "zai_auto",
		Payload: reqPayloadWithTools,
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FormatOpenAI,
	})
	if err != nil {
		t.Fatalf("Execute with tools failed: %v", err)
	}
	if !receivedToolStream {
		t.Errorf("expected tool_stream=true when tools present")
	}
	if !receivedTools.Exists() || len(receivedTools.Array()) != 1 {
		t.Errorf("expected tools array with 1 item")
	}

	// Case 2: without tools -> tool_stream omitted
	reqPayloadNoTools := []byte(`{"model":"zai_auto","messages":[{"role":"user","content":"no tool"}]}`)
	_, err = exec.Execute(ctx, auth, cliproxyexecutor.Request{
		Model:   "zai_auto",
		Payload: reqPayloadNoTools,
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FormatOpenAI,
	})
	if err != nil {
		t.Fatalf("Execute without tools failed: %v", err)
	}
	if receivedToolStream {
		t.Errorf("expected tool_stream=false when no tools present")
	}
}

func TestZAIExecutor_AggregateSSE_ReasoningVariants(t *testing.T) {
	// Test fallback delta.reasoning
	sseDataReasoning := []byte(
		"data: {\"id\":\"c1\",\"choices\":[{\"index\":0,\"delta\":{\"reasoning\":\"reasoning thought\"},\"finish_reason\":null}]}\n\n" +
			"data: {\"id\":\"c1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"done\"},\"finish_reason\":\"stop\"}]}\n\n" +
			"data: [DONE]\n\n",
	)
	comp, err := aggregateSSEToCompletion(sseDataReasoning)
	if err != nil {
		t.Fatalf("aggregateSSEToCompletion failed: %v", err)
	}
	if got := gjson.GetBytes(comp, "choices.0.message.reasoning_content").String(); got != "reasoning thought" {
		t.Errorf("reasoning_content = %q, want 'reasoning thought'", got)
	}

	// Test fallback delta.reasoning_text
	sseDataReasoningText := []byte(
		"data: {\"id\":\"c2\",\"choices\":[{\"index\":0,\"delta\":{\"reasoning_text\":\"reasoning_text thought\"},\"finish_reason\":null}]}\n\n" +
			"data: {\"id\":\"c2\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"done\"},\"finish_reason\":\"stop\"}]}\n\n" +
			"data: [DONE]\n\n",
	)
	comp2, err := aggregateSSEToCompletion(sseDataReasoningText)
	if err != nil {
		t.Fatalf("aggregateSSEToCompletion failed: %v", err)
	}
	if got := gjson.GetBytes(comp2, "choices.0.message.reasoning_content").String(); got != "reasoning_text thought" {
		t.Errorf("reasoning_content = %q, want 'reasoning_text thought'", got)
	}
}

func TestZAIExecutor_AggregateSSE_UsageNormalization(t *testing.T) {
	sseDataUsage := []byte(
		"data: {\"id\":\"c3\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"done\"},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":100,\"completion_tokens\":20,\"total_tokens\":120,\"prompt_cache_hit_tokens\":35,\"cache_write_tokens\":15}}\n\n" +
			"data: [DONE]\n\n",
	)
	comp, err := aggregateSSEToCompletion(sseDataUsage)
	if err != nil {
		t.Fatalf("aggregateSSEToCompletion failed: %v", err)
	}
	if got := gjson.GetBytes(comp, "usage.prompt_tokens_details.cached_tokens").Int(); got != 35 {
		t.Errorf("usage cached_tokens = %d, want 35", got)
	}
	if got := gjson.GetBytes(comp, "usage.prompt_tokens_details.cache_write_tokens").Int(); got != 15 {
		t.Errorf("usage cache_write_tokens = %d, want 15", got)
	}
}

func TestNormalizeZAIStreamLine(t *testing.T) {
	// 1. Line with delta.reasoning
	line1 := []byte(`data: {"choices":[{"delta":{"reasoning":"thinking delta"}}]}`)
	norm1 := normalizeZAIStreamLine(line1)
	if got := gjson.GetBytes(bytes.TrimPrefix(norm1, []byte("data: ")), "choices.0.delta.reasoning_content").String(); got != "thinking delta" {
		t.Errorf("normalized reasoning_content = %q, want 'thinking delta'", got)
	}

	// 2. Line with delta.reasoning_text
	line2 := []byte(`data: {"choices":[{"delta":{"reasoning_text":"text delta"}}]}`)
	norm2 := normalizeZAIStreamLine(line2)
	if got := gjson.GetBytes(bytes.TrimPrefix(norm2, []byte("data: ")), "choices.0.delta.reasoning_content").String(); got != "text delta" {
		t.Errorf("normalized reasoning_content = %q, want 'text delta'", got)
	}

	// 3. Line with usage prompt_cache_hit_tokens
	line3 := []byte(`data: {"choices":[],"usage":{"prompt_tokens":50,"prompt_cache_hit_tokens":20}}`)
	norm3 := normalizeZAIStreamLine(line3)
	if got := gjson.GetBytes(bytes.TrimPrefix(norm3, []byte("data: ")), "usage.prompt_tokens_details.cached_tokens").Int(); got != 20 {
		t.Errorf("normalized cached_tokens = %d, want 20", got)
	}

	// 4. Non-JSON / [DONE] line unchanged
	doneLine := []byte(`data: [DONE]`)
	if !bytes.Equal(normalizeZAIStreamLine(doneLine), doneLine) {
		t.Errorf("expected [DONE] line to be unchanged")
	}
}
