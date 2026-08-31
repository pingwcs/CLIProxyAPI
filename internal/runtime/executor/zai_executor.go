package executor

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	zaiauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/zai"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/thinking"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

var (
	zaiRoutePrefixPattern = regexp.MustCompile(`^[a-z]+_`)
	defaultZAIUpstreams   = []string{
		zaiauth.DefaultBaseURL,
		"https://autoglm-acceleration-api.zhipuai.cn/autoclaw-proxy/proxy/autoclaw",
		"https://autoglm-api.zhipuai.cn/autoclaw-proxy/proxy/autoclaw",
	}
)

// ZAIExecutor is a stateless executor for AutoClaw (z.ai) using OpenAI-compatible chat completions.
type ZAIExecutor struct {
	ClaudeExecutor
	cfg *config.Config
}

// NewZAIExecutor creates a new ZAI executor.
func NewZAIExecutor(cfg *config.Config) *ZAIExecutor {
	return &ZAIExecutor{
		ClaudeExecutor: ClaudeExecutor{
			cfg:                     cfg,
			requestLogProvider:      "zai",
			upstreamModelNormalizer: normalizeZAIUpstreamModel,
		},
		cfg: cfg,
	}
}

// Identifier returns the executor identifier.
func (e *ZAIExecutor) Identifier() string { return "zai" }

// ZAIAliasExecutor registers the zai executor under the "autoclaw" provider key so auth
// files typed "autoclaw" also work. The executor lookup key is strings.ToLower(auth.Provider)
// (executorKeyFromAuth, sdk/cliproxy/auth/conductor_execution.go:1628).
type ZAIAliasExecutor struct {
	*ZAIExecutor
}

// NewZAIAliasExecutor creates a new ZAIAliasExecutor.
func NewZAIAliasExecutor(cfg *config.Config) *ZAIAliasExecutor {
	return &ZAIAliasExecutor{ZAIExecutor: NewZAIExecutor(cfg)}
}

// Identifier returns the autoclaw alias identifier.
func (e *ZAIAliasExecutor) Identifier() string { return "autoclaw" }

// RequestToFormat reports the upstream request format used after auth selection.
// The AutoClaw upstream is OpenAI-chat-completions only.
func (e *ZAIExecutor) RequestToFormat(_ cliproxyexecutor.Request, _ cliproxyexecutor.Options) sdktranslator.Format {
	return sdktranslator.FormatOpenAI
}

// PrepareRequest injects ZAI credentials and headers into the outgoing HTTP request.
func (e *ZAIExecutor) PrepareRequest(req *http.Request, auth *cliproxyauth.Auth) error {
	if req == nil {
		return nil
	}
	token := zaiCreds(auth)
	routeModel := ""
	if auth != nil && auth.Attributes != nil {
		routeModel = auth.Attributes["model"]
	}
	applyZAIHeaders(req, token, routeModel, false)
	var attrs map[string]string
	if auth != nil {
		attrs = auth.Attributes
	}
	util.ApplyCustomHeadersFromAttrs(req, attrs)
	return nil
}

// HttpRequest injects ZAI credentials into the request and executes it.
func (e *ZAIExecutor) HttpRequest(ctx context.Context, auth *cliproxyauth.Auth, req *http.Request) (*http.Response, error) {
	if req == nil {
		return nil, fmt.Errorf("zai executor: request is nil")
	}
	if ctx == nil {
		ctx = req.Context()
	}
	httpReq := req.WithContext(ctx)
	if err := e.PrepareRequest(httpReq, auth); err != nil {
		return nil, err
	}
	httpClient := helps.NewZAIHTTPClient(ctx, e.cfg, auth, 0)
	return httpClient.Do(httpReq)
}

// Execute performs a non-streaming chat completion request to AutoClaw (z.ai).
func (e *ZAIExecutor) Execute(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (resp cliproxyexecutor.Response, err error) {
	from := opts.SourceFormat
	to := sdktranslator.FromString("openai")
	responseFormat := cliproxyexecutor.ResponseFormatOrSource(opts)

	baseModel := thinking.ParseSuffix(req.Model).ModelName
	routeModel := baseModel
	token := zaiCreds(auth)

	reporter := helps.NewExecutorUsageReporter(ctx, e, baseModel, auth)
	defer reporter.TrackFailure(ctx, &err)

	originalPayloadSource := req.Payload
	if len(opts.OriginalRequest) > 0 {
		originalPayloadSource = opts.OriginalRequest
	}
	originalPayload := bytes.Clone(originalPayloadSource)
	originalTranslated := helps.TranslateRequestWithCodexMultiAgentV2(ctx, opts.Headers, e.cfg, from, to, baseModel, originalPayload, false)
	body := helps.TranslateRequestWithCodexMultiAgentV2(ctx, opts.Headers, e.cfg, from, to, baseModel, bytes.Clone(req.Payload), false)

	upstreamModel := normalizeZAIUpstreamModel(baseModel)
	body, err = sjson.SetBytes(body, "model", upstreamModel)
	if err != nil {
		return resp, fmt.Errorf("zai executor: failed to set model in payload: %w", err)
	}

	// Upstream AutoClaw proxy is streaming-only; force stream: true
	body, err = sjson.SetBytes(body, "stream", true)
	if err != nil {
		return resp, fmt.Errorf("zai executor: failed to set stream in payload: %w", err)
	}

	if tools := gjson.GetBytes(body, "tools"); tools.Exists() && tools.IsArray() && len(tools.Array()) > 0 {
		body, err = sjson.SetBytes(body, "tool_stream", true)
		if err != nil {
			return resp, fmt.Errorf("zai executor: failed to set tool_stream in payload: %w", err)
		}
	}

	body, err = helps.ApplyThinkingWithSourcePayload(body, req.Payload, originalPayloadSource, req.Model, from.String(), "zai", e.Identifier())
	if err != nil {
		return resp, err
	}

	requestedModel := helps.PayloadRequestedModel(opts, req.Model)
	requestPath := helps.PayloadRequestPath(opts)
	body = helps.ApplyPayloadConfigWithRequest(e.cfg, baseModel, to.String(), from.String(), "", body, originalTranslated, requestedModel, requestPath, opts.Headers)
	reporter.SetTranslatedReasoningEffort(body, e.Identifier())

	var httpResp *http.Response
	var lastErr error
	upstreams := getZAIUpstreamURLs(auth)
	for _, upstreamBase := range upstreams {
		upstreamURL := strings.TrimRight(upstreamBase, "/") + "/chat/completions"
		httpReq, errReq := http.NewRequestWithContext(ctx, http.MethodPost, upstreamURL, bytes.NewReader(body))
		if errReq != nil {
			return resp, fmt.Errorf("zai executor: failed to create HTTP request: %w", errReq)
		}
		applyZAIHeaders(httpReq, token, routeModel, false)
		var attrs map[string]string
		if auth != nil {
			attrs = auth.Attributes
		}
		util.ApplyCustomHeadersFromAttrs(httpReq, attrs)

		var authID, authLabel, authType, authValue string
		if auth != nil {
			authID = auth.ID
			authLabel = auth.Label
			authType, authValue = auth.AccountInfo()
		}
		helps.RecordAPIRequest(ctx, e.cfg, helps.UpstreamRequestLog{
			URL:       upstreamURL,
			Method:    http.MethodPost,
			Headers:   httpReq.Header.Clone(),
			Body:      body,
			Provider:  e.Identifier(),
			AuthID:    authID,
			AuthLabel: authLabel,
			AuthType:  authType,
			AuthValue: authValue,
		})

		httpClient := helps.NewZAIHTTPClient(ctx, e.cfg, auth, 0)
		httpClient = reporter.TrackHTTPClient(httpClient)

		respCandidate, errDo := httpClient.Do(httpReq)
		if errDo != nil {
			if ctx.Err() != nil {
				helps.RecordAPIResponseError(ctx, e.cfg, errDo)
				return resp, errDo
			}
			lastErr = errDo
			log.Warnf("zai executor: upstream %s failed: %v, trying next upstream", upstreamBase, errDo)
			continue
		}
		httpResp = respCandidate
		break
	}

	if httpResp == nil {
		if lastErr == nil {
			lastErr = fmt.Errorf("zai executor: all upstreams unreachable")
		}
		helps.RecordAPIResponseError(ctx, e.cfg, lastErr)
		return resp, lastErr
	}

	defer func() {
		if errClose := httpResp.Body.Close(); errClose != nil {
			log.Errorf("zai executor: close response body error: %v", errClose)
		}
	}()

	helps.RecordAPIResponseMetadata(ctx, e.cfg, httpResp.StatusCode, httpResp.Header.Clone())
	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		b, _ := io.ReadAll(httpResp.Body)
		helps.AppendAPIResponseChunk(ctx, e.cfg, b)
		helps.LogWithRequestID(ctx).Debugf("request error, error status: %d, error message: %s", httpResp.StatusCode, helps.SummarizeErrorBody(httpResp.Header.Get("Content-Type"), b))
		err = statusErr{code: httpResp.StatusCode, msg: string(b)}
		return resp, err
	}

	data, err := io.ReadAll(httpResp.Body)
	if err != nil {
		helps.RecordAPIResponseError(ctx, e.cfg, err)
		return resp, err
	}
	helps.AppendAPIResponseChunk(ctx, e.cfg, data)

	aggregated, errAgg := aggregateSSEToCompletion(data)
	if errAgg != nil {
		helps.RecordAPIResponseError(ctx, e.cfg, errAgg)
		return resp, fmt.Errorf("zai executor: failed to aggregate SSE stream: %w", errAgg)
	}

	reporter.Publish(ctx, helps.ParseOpenAIUsage(aggregated))
	var param any
	out := sdktranslator.TranslateNonStream(ctx, to, responseFormat, req.Model, opts.OriginalRequest, body, aggregated, &param)
	if responseFormat == sdktranslator.FormatOpenAIResponse {
		out = helps.EnsureResponsesUsageDetails(out)
	}
	resp = cliproxyexecutor.Response{Payload: out, Headers: httpResp.Header.Clone()}
	e.maybeRefreshZaiCredits(ctx, auth)
	return resp, nil
}

// ExecuteStream performs a streaming chat completion request to AutoClaw (z.ai).
func (e *ZAIExecutor) ExecuteStream(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (_ *cliproxyexecutor.StreamResult, err error) {
	from := opts.SourceFormat
	to := sdktranslator.FromString("openai")
	responseFormat := cliproxyexecutor.ResponseFormatOrSource(opts)

	baseModel := thinking.ParseSuffix(req.Model).ModelName
	routeModel := baseModel
	token := zaiCreds(auth)

	reporter := helps.NewExecutorUsageReporter(ctx, e, baseModel, auth)
	defer reporter.TrackFailure(ctx, &err)

	originalPayloadSource := req.Payload
	if len(opts.OriginalRequest) > 0 {
		originalPayloadSource = opts.OriginalRequest
	}
	originalPayload := bytes.Clone(originalPayloadSource)
	originalTranslated := helps.TranslateRequestWithCodexMultiAgentV2(ctx, opts.Headers, e.cfg, from, to, baseModel, originalPayload, true)
	body := helps.TranslateRequestWithCodexMultiAgentV2(ctx, opts.Headers, e.cfg, from, to, baseModel, bytes.Clone(req.Payload), true)

	upstreamModel := normalizeZAIUpstreamModel(baseModel)
	body, err = sjson.SetBytes(body, "model", upstreamModel)
	if err != nil {
		return nil, fmt.Errorf("zai executor: failed to set model in payload: %w", err)
	}

	body, err = sjson.SetBytes(body, "stream", true)
	if err != nil {
		return nil, fmt.Errorf("zai executor: failed to set stream in payload: %w", err)
	}

	body, err = helps.ApplyThinkingWithSourcePayload(body, req.Payload, originalPayloadSource, req.Model, from.String(), "zai", e.Identifier())
	if err != nil {
		return nil, err
	}

	body, err = sjson.SetBytes(body, "stream_options.include_usage", true)
	if err != nil {
		return nil, fmt.Errorf("zai executor: failed to set stream_options in payload: %w", err)
	}

	if tools := gjson.GetBytes(body, "tools"); tools.Exists() && tools.IsArray() && len(tools.Array()) > 0 {
		body, err = sjson.SetBytes(body, "tool_stream", true)
		if err != nil {
			return nil, fmt.Errorf("zai executor: failed to set tool_stream in payload: %w", err)
		}
	}

	requestedModel := helps.PayloadRequestedModel(opts, req.Model)
	requestPath := helps.PayloadRequestPath(opts)
	body = helps.ApplyPayloadConfigWithRequest(e.cfg, baseModel, to.String(), from.String(), "", body, originalTranslated, requestedModel, requestPath, opts.Headers)
	reporter.SetTranslatedReasoningEffort(body, e.Identifier())

	var httpResp *http.Response
	var lastErr error
	upstreams := getZAIUpstreamURLs(auth)
	for _, upstreamBase := range upstreams {
		upstreamURL := strings.TrimRight(upstreamBase, "/") + "/chat/completions"
		httpReq, errReq := http.NewRequestWithContext(ctx, http.MethodPost, upstreamURL, bytes.NewReader(body))
		if errReq != nil {
			return nil, fmt.Errorf("zai executor: failed to create HTTP request: %w", errReq)
		}
		applyZAIHeaders(httpReq, token, routeModel, true)
		var attrs map[string]string
		if auth != nil {
			attrs = auth.Attributes
		}
		util.ApplyCustomHeadersFromAttrs(httpReq, attrs)

		var authID, authLabel, authType, authValue string
		if auth != nil {
			authID = auth.ID
			authLabel = auth.Label
			authType, authValue = auth.AccountInfo()
		}
		helps.RecordAPIRequest(ctx, e.cfg, helps.UpstreamRequestLog{
			URL:       upstreamURL,
			Method:    http.MethodPost,
			Headers:   httpReq.Header.Clone(),
			Body:      body,
			Provider:  e.Identifier(),
			AuthID:    authID,
			AuthLabel: authLabel,
			AuthType:  authType,
			AuthValue: authValue,
		})

		httpClient := helps.NewZAIHTTPClient(ctx, e.cfg, auth, 0)
		httpClient = reporter.TrackHTTPClient(httpClient)

		respCandidate, errDo := httpClient.Do(httpReq)
		if errDo != nil {
			if ctx.Err() != nil {
				helps.RecordAPIResponseError(ctx, e.cfg, errDo)
				return nil, errDo
			}
			lastErr = errDo
			log.Warnf("zai executor: upstream %s failed: %v, trying next upstream", upstreamBase, errDo)
			continue
		}
		httpResp = respCandidate
		break
	}

	if httpResp == nil {
		if lastErr == nil {
			lastErr = fmt.Errorf("zai executor: all upstreams unreachable")
		}
		helps.RecordAPIResponseError(ctx, e.cfg, lastErr)
		return nil, lastErr
	}

	helps.RecordAPIResponseMetadata(ctx, e.cfg, httpResp.StatusCode, httpResp.Header.Clone())
	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		b, _ := io.ReadAll(httpResp.Body)
		helps.AppendAPIResponseChunk(ctx, e.cfg, b)
		helps.LogWithRequestID(ctx).Debugf("request error, error status: %d, error message: %s", httpResp.StatusCode, helps.SummarizeErrorBody(httpResp.Header.Get("Content-Type"), b))
		if errClose := httpResp.Body.Close(); errClose != nil {
			log.Errorf("zai executor: close response body error: %v", errClose)
		}
		err = statusErr{code: httpResp.StatusCode, msg: string(b)}
		return nil, err
	}

	out := make(chan cliproxyexecutor.StreamChunk)
	go func() {
		defer close(out)
		defer func() {
			if errClose := httpResp.Body.Close(); errClose != nil {
				log.Errorf("zai executor: close response body error: %v", errClose)
			}
		}()
		scanner := bufio.NewScanner(httpResp.Body)
		scanner.Buffer(nil, 1_048_576) // 1MB
		claudeInputTokens := helps.NewClaudeInputTokenState(from, to, responseFormat, originalPayload)
		var param any
		var streamUsage helps.StreamUsageBuffer
		defer streamUsage.Publish(ctx, reporter)
		for scanner.Scan() {
			line := scanner.Bytes()
			helps.AppendAPIResponseChunk(ctx, e.cfg, line)
			normalizedLine := normalizeZAIStreamLine(line)
			streamUsage.ObserveOpenAIStream(normalizedLine)
			chunks := helps.TranslateStreamWithClaudeInputTokens(ctx, to, responseFormat, req.Model, opts.OriginalRequest, body, bytes.Clone(normalizedLine), &param, claudeInputTokens)
			for i := range chunks {
				select {
				case out <- cliproxyexecutor.StreamChunk{Payload: chunks[i]}:
				case <-ctx.Done():
					return
				}
			}
		}
		doneChunks := helps.TranslateStreamWithClaudeInputTokens(ctx, to, responseFormat, req.Model, opts.OriginalRequest, body, []byte("[DONE]"), &param, claudeInputTokens)
		for i := range doneChunks {
			select {
			case out <- cliproxyexecutor.StreamChunk{Payload: doneChunks[i]}:
			case <-ctx.Done():
				return
			}
		}
		if errScan := scanner.Err(); errScan != nil {
			helps.RecordAPIResponseError(ctx, e.cfg, errScan)
			reporter.PublishFailure(ctx, errScan)
			select {
			case out <- cliproxyexecutor.StreamChunk{Err: errScan}:
			case <-ctx.Done():
			}
		}
	}()

	e.maybeRefreshZaiCredits(ctx, auth)
	return &cliproxyexecutor.StreamResult{
		Headers: httpResp.Header.Clone(),
		Chunks:  out,
	}, nil
}

// Refresh updates access tokens using the z.ai userapi refresh endpoint.
func (e *ZAIExecutor) Refresh(ctx context.Context, auth *cliproxyauth.Auth) (*cliproxyauth.Auth, error) {
	log.Debugf("zai executor: refresh called")
	if refreshed, handled, err := helps.RefreshAuthViaHome(ctx, e.cfg, auth); handled {
		return refreshed, err
	}
	if auth == nil {
		return nil, fmt.Errorf("zai executor: auth is nil")
	}

	var refreshToken string
	if auth.Metadata != nil {
		if v, ok := auth.Metadata["refresh_token"].(string); ok && strings.TrimSpace(v) != "" {
			refreshToken = strings.TrimSpace(v)
		}
	}
	if refreshToken == "" {
		return auth, nil
	}

	tokenEndpoint := zaiTokenEndpoint(auth)
	deviceID := zaiDeviceID(auth)
	httpClient := helps.NewZAIHTTPClient(ctx, e.cfg, auth, 0)
	refreshedData, err := zaiauth.RefreshAccess(ctx, httpClient, tokenEndpoint, deviceID, refreshToken, auth.ProxyURL)
	if err != nil {
		return nil, err
	}

	if auth.Metadata == nil {
		auth.Metadata = make(map[string]any)
	}
	auth.Metadata["access_token"] = refreshedData.AccessToken
	if refreshedData.RefreshToken != "" {
		auth.Metadata["refresh_token"] = refreshedData.RefreshToken
	}
	if expMs := zaiauth.JWTExpMs(refreshedData.AccessToken); expMs > 0 {
		expired := time.UnixMilli(expMs).UTC().Format(time.RFC3339)
		// "expired" is the metadata key CPA core reads for refresh scheduling;
		// "access_expired" keeps round-trip compatibility with my_zai export files.
		auth.Metadata["expired"] = expired
		auth.Metadata["access_expired"] = expired
	}
	auth.Metadata["last_refresh"] = time.Now().UTC().Format(time.RFC3339)
	return auth, nil
}

// CountTokens counts tokens locally for the OpenAI-compatible chat request.
func (e *ZAIExecutor) CountTokens(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	baseModel := thinking.ParseSuffix(req.Model).ModelName
	from := opts.SourceFormat
	responseFormat := cliproxyexecutor.ResponseFormatOrSource(opts)
	to := sdktranslator.FromString("openai")
	isCompat := helps.APIKeyModelIsCompat(req)
	translated := helps.TranslateRequestWithAPIKeyModelCompatibility(ctx, opts.Headers, e.cfg, from, to, baseModel, req.Payload, false, isCompat)

	translated, err := helps.ApplyRequestThinking(translated, req, opts, from.String(), to.String(), e.Identifier())
	if err != nil {
		return cliproxyexecutor.Response{}, err
	}

	enc, err := helps.TokenizerForModel(baseModel)
	if err != nil {
		return cliproxyexecutor.Response{}, fmt.Errorf("zai executor: tokenizer init failed: %w", err)
	}

	count, err := helps.CountOpenAIChatTokens(enc, translated)
	if err != nil {
		return cliproxyexecutor.Response{}, fmt.Errorf("zai executor: token counting failed: %w", err)
	}

	usageJSON := helps.BuildOpenAIUsageJSON(count)
	translatedUsage := sdktranslator.TranslateTokenCount(ctx, to, responseFormat, count, usageJSON)
	return cliproxyexecutor.Response{Payload: translatedUsage}, nil
}

func zaiCreds(a *cliproxyauth.Auth) string {
	if a == nil {
		return ""
	}
	if a.Metadata != nil {
		if v, ok := a.Metadata["access_token"].(string); ok && strings.TrimSpace(v) != "" {
			return zaiauth.StripBearerScheme(v)
		}
	}
	if a.Attributes != nil {
		if v := strings.TrimSpace(a.Attributes["access_token"]); v != "" {
			return zaiauth.StripBearerScheme(v)
		}
		if v := strings.TrimSpace(a.Attributes["api_key"]); v != "" {
			return zaiauth.StripBearerScheme(v)
		}
	}
	return ""
}

func zaiDeviceID(a *cliproxyauth.Auth) string {
	if a == nil {
		return ""
	}
	if a.Metadata != nil {
		if v, ok := a.Metadata["device_id"].(string); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	if a.Attributes != nil {
		if v := strings.TrimSpace(a.Attributes["device_id"]); v != "" {
			return v
		}
	}
	return ""
}

func zaiBaseURL(a *cliproxyauth.Auth) string {
	if a == nil {
		return zaiauth.DefaultBaseURL
	}
	if a.Metadata != nil {
		if v, ok := a.Metadata["base_url"].(string); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	if a.Attributes != nil {
		if v := strings.TrimSpace(a.Attributes["base_url"]); v != "" {
			return v
		}
	}
	return zaiauth.DefaultBaseURL
}

func zaiTokenEndpoint(a *cliproxyauth.Auth) string {
	if a == nil {
		return ""
	}
	if a.Metadata != nil {
		if v, ok := a.Metadata["token_endpoint"].(string); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	if a.Attributes != nil {
		if v := strings.TrimSpace(a.Attributes["token_endpoint"]); v != "" {
			return v
		}
	}
	return ""
}

func normalizeZAIUpstreamModel(model string) string {
	model = strings.TrimSpace(model)
	return zaiRoutePrefixPattern.ReplaceAllString(model, "")
}

func applyZAIHeaders(r *http.Request, token, routeModel string, stream bool) {
	r.Header.Del("Authorization")
	r.Header.Set("Content-Type", "application/json")
	if stream {
		r.Header.Set("Accept", "text/event-stream, */*")
	} else {
		r.Header.Set("Accept", "*/*")
	}
	if r.Header.Get("User-Agent") == "" {
		r.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36")
	}
	if token != "" {
		r.Header.Set("X-Authorization", "Bearer "+token)
	}
	r.Header.Set("X-Request-Id", uuid.New().String())
	if routeModel != "" {
		r.Header.Set("X-Request-Model", routeModel)
	}
	r.Header.Set("X-Client-Type", "pc")
	r.Header.Set("X-Product", "autoclaw")
	r.Header.Set("X-Harness-Type", "zcode")
	r.Header.Set("X-Tm", "win")
	r.Header.Set("X-Version", zaiauth.XVersion)
	r.Header.Set("X-Lang", zaiauth.XLang)
	r.Header.Set("x_trace_id", "autoclaw-desktop")
	r.Header.Set("X-Channel", "zai")
	sessionID := r.Header.Get("X-Session-Id")
	if sessionID == "" {
		sessionID = uuid.New().String()
		r.Header.Set("X-Session-Id", sessionID)
	}
	agentID := r.Header.Get("X-Agent-Id")
	if agentID == "" {
		agentID = "main"
		r.Header.Set("X-Agent-Id", agentID)
	}
	if r.Header.Get("X-Session-Key") == "" {
		r.Header.Set("X-Session-Key", fmt.Sprintf("agent:%s:%s", agentID, sessionID))
	}
}

func getZAIUpstreamURLs(auth *cliproxyauth.Auth) []string {
	primary := zaiBaseURL(auth)
	if primary == "" {
		primary = defaultZAIUpstreams[0]
	}
	urls := []string{primary}
	for _, u := range defaultZAIUpstreams {
		if !strings.EqualFold(strings.TrimRight(u, "/"), strings.TrimRight(primary, "/")) {
			urls = append(urls, u)
		}
	}
	return urls
}

type aggregatedChoiceMsg struct {
	Role             string `json:"role"`
	Content          string `json:"content"`
	ReasoningContent string `json:"reasoning_content,omitempty"`
}

type aggregatedChoice struct {
	Index        int                 `json:"index"`
	Message      aggregatedChoiceMsg `json:"message"`
	FinishReason string              `json:"finish_reason"`
}

type aggregatedChatCompletion struct {
	ID      string             `json:"id"`
	Object  string             `json:"object"`
	Created int64              `json:"created"`
	Model   string             `json:"model"`
	Choices []aggregatedChoice `json:"choices"`
	Usage   json.RawMessage    `json:"usage,omitempty"`
}

func aggregateSSEToCompletion(data []byte) ([]byte, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(nil, 10*1024*1024)

	var id string
	var created int64
	var model string
	var content strings.Builder
	var reasoning strings.Builder
	finishReason := "stop"
	var usageRaw json.RawMessage

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		dataStr := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if dataStr == "" || dataStr == "[DONE]" {
			continue
		}
		if !gjson.Valid(dataStr) {
			continue
		}
		parsed := gjson.Parse(dataStr)
		if chunkID := parsed.Get("id").String(); chunkID != "" {
			id = chunkID
		}
		if chunkCreated := parsed.Get("created").Int(); chunkCreated > 0 {
			created = chunkCreated
		}
		if chunkModel := parsed.Get("model").String(); chunkModel != "" {
			model = chunkModel
		}
		if u := parsed.Get("usage"); u.Exists() {
			usageRaw = normalizeZAIUsageJSON([]byte(u.Raw))
		}
		firstChoice := parsed.Get("choices.0")
		if firstChoice.Exists() {
			delta := firstChoice.Get("delta")
			if delta.Exists() {
				if c := delta.Get("content"); c.Exists() && c.Type == gjson.String {
					content.WriteString(c.String())
				}
				if rc := delta.Get("reasoning_content"); rc.Exists() && rc.Type == gjson.String {
					reasoning.WriteString(rc.String())
				} else if r := delta.Get("reasoning"); r.Exists() && r.Type == gjson.String {
					reasoning.WriteString(r.String())
				} else if rt := delta.Get("reasoning_text"); rt.Exists() && rt.Type == gjson.String {
					reasoning.WriteString(rt.String())
				}
			}
			if fr := firstChoice.Get("finish_reason"); fr.Exists() && fr.Type == gjson.String && fr.String() != "" {
				finishReason = fr.String()
			}
		}
	}

	if id == "" {
		id = "zai-" + uuid.New().String()
	}
	if created == 0 {
		created = time.Now().Unix()
	}
	if model == "" {
		model = "unknown"
	}

	comp := aggregatedChatCompletion{
		ID:      id,
		Object:  "chat.completion",
		Created: created,
		Model:   model,
		Choices: []aggregatedChoice{
			{
				Index: 0,
				Message: aggregatedChoiceMsg{
					Role:             "assistant",
					Content:          content.String(),
					ReasoningContent: reasoning.String(),
				},
				FinishReason: finishReason,
			},
		},
		Usage: usageRaw,
	}

	return json.Marshal(comp)
}

func normalizeZAIUsageJSON(raw []byte) []byte {
	if len(raw) == 0 || !gjson.ValidBytes(raw) {
		return raw
	}
	parsed := gjson.ParseBytes(raw)
	result := raw
	if hit := parsed.Get("prompt_cache_hit_tokens"); hit.Exists() && !parsed.Get("prompt_tokens_details.cached_tokens").Exists() {
		result, _ = sjson.SetBytes(result, "prompt_tokens_details.cached_tokens", hit.Int())
	}
	if write := parsed.Get("cache_write_tokens"); write.Exists() && !parsed.Get("prompt_tokens_details.cache_write_tokens").Exists() {
		result, _ = sjson.SetBytes(result, "prompt_tokens_details.cache_write_tokens", write.Int())
	}
	return result
}

func normalizeZAIStreamLine(line []byte) []byte {
	trimmed := bytes.TrimSpace(line)
	if !bytes.HasPrefix(trimmed, []byte("data:")) {
		return line
	}
	dataPayload := bytes.TrimSpace(bytes.TrimPrefix(trimmed, []byte("data:")))
	if len(dataPayload) == 0 || bytes.Equal(dataPayload, []byte("[DONE]")) || !gjson.ValidBytes(dataPayload) {
		return line
	}

	parsed := gjson.ParseBytes(dataPayload)
	modified := false
	result := dataPayload

	delta := parsed.Get("choices.0.delta")
	if delta.Exists() && !delta.Get("reasoning_content").Exists() {
		if r := delta.Get("reasoning"); r.Exists() && r.Type == gjson.String {
			result, _ = sjson.SetBytes(result, "choices.0.delta.reasoning_content", r.String())
			modified = true
		} else if rt := delta.Get("reasoning_text"); rt.Exists() && rt.Type == gjson.String {
			result, _ = sjson.SetBytes(result, "choices.0.delta.reasoning_content", rt.String())
			modified = true
		}
	}

	if u := parsed.Get("usage"); u.Exists() {
		normalizedUsage := normalizeZAIUsageJSON([]byte(u.Raw))
		if !bytes.Equal(normalizedUsage, []byte(u.Raw)) {
			result, _ = sjson.SetRawBytes(result, "usage", normalizedUsage)
			modified = true
		}
	}

	if modified {
		return append([]byte("data: "), result...)
	}
	return line
}
