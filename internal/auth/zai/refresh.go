// Package zai provides authentication and token refresh functionality for AutoClaw (z.ai).
package zai

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	AppID               = "100003"
	AppKey              = "38d2391985e2369a5fb8227d8e6cd5e5"
	SourceID            = "autoclaw"
	XVersion            = "1.17.8"
	XLang               = "en"
	DefaultUserAPIHost  = "https://autoglm-api.autoglm.ai"
	DefaultRefreshPath  = "/userapi/v1/refresh"
	FallbackRefreshPath = "/userapi/v1/agent-refresh" // used when code==400002
	DefaultBaseURL      = "https://autoglm-api.autoglm.ai/autoclaw-proxy/proxy/autoclaw"
)

var (
	jwtPattern          = regexp.MustCompile(`^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`)
	bearerSchemePattern = regexp.MustCompile(`(?i)^bearer\s+`)
)

// StripBearerScheme removes an optional leading "Bearer " (case-insensitive) scheme prefix from a token value.
func StripBearerScheme(token string) string {
	return strings.TrimSpace(bearerSchemePattern.ReplaceAllString(strings.TrimSpace(token), ""))
}

// RefreshData holds the refreshed credentials returned by z.ai userapi.
type RefreshData struct {
	AccessToken  string
	RefreshToken string // rotates on every refresh
	UserID       int64
	UserName     string
}

type refreshRequestPayload struct {
	SourceID     string `json:"source_id"`
	DeviceID     string `json:"device_id"`
	RefreshToken string `json:"refresh_token"`
}

type refreshResponsePayload struct {
	Code int64                `json:"code"`
	Msg  string               `json:"msg"`
	Data *refreshResponseData `json:"data"`
}

type refreshResponseData struct {
	AccessToken  string      `json:"access_token"`
	RefreshToken string      `json:"refresh_token"`
	UserID       json.Number `json:"user_id"`
	UserName     string      `json:"user_name"`
}

// RefreshAccess calls the refresh endpoint. If the server returns code 400002
// (signature check failure), it retries once against agent-refresh.
// tokenEndpoint may be "" to use defaultUserAPIHost+defaultRefreshPath.
// proxyURL is optional http(s) proxy (may be "").
func RefreshAccess(ctx context.Context, client *http.Client, tokenEndpoint, deviceID, refreshToken, proxyURL string) (*RefreshData, error) {
	refreshToken = StripBearerScheme(refreshToken)
	if strings.TrimSpace(refreshToken) == "" {
		return nil, fmt.Errorf("zai refresh: refresh_token is empty")
	}

	primaryURL := strings.TrimSpace(tokenEndpoint)
	if primaryURL == "" {
		primaryURL = DefaultUserAPIHost + DefaultRefreshPath
	}

	httpClient := client
	if httpClient == nil {
		httpClient = &http.Client{}
		if strings.TrimSpace(proxyURL) != "" {
			if parsedProxy, err := url.Parse(proxyURL); err == nil {
				httpClient.Transport = &http.Transport{
					Proxy: http.ProxyURL(parsedProxy),
				}
			}
		}
	}

	data, code, msg, err := doRefreshRequest(ctx, httpClient, primaryURL, deviceID, refreshToken)
	if err == nil {
		return data, nil
	}

	// Retry once on signature check failure code 400002
	if code == 400002 {
		fallbackURL := deriveFallbackEndpoint(primaryURL)
		fallbackData, _, fallbackMsg, fallbackErr := doRefreshRequest(ctx, httpClient, fallbackURL, deviceID, refreshToken)
		if fallbackErr == nil {
			return fallbackData, nil
		}
		return nil, fmt.Errorf("zai refresh: fallback failed: %w (msg: %s, original error: %v, original msg: %s)", fallbackErr, fallbackMsg, err, msg)
	}

	return nil, err
}

func deriveFallbackEndpoint(primaryURL string) string {
	if strings.Contains(primaryURL, DefaultRefreshPath) {
		return strings.Replace(primaryURL, DefaultRefreshPath, FallbackRefreshPath, 1)
	}
	if parsed, err := url.Parse(primaryURL); err == nil && parsed.Host != "" {
		parsed.Path = FallbackRefreshPath
		parsed.RawQuery = ""
		return parsed.String()
	}
	return DefaultUserAPIHost + FallbackRefreshPath
}

func doRefreshRequest(ctx context.Context, client *http.Client, targetURL, deviceID, refreshToken string) (*RefreshData, int64, string, error) {
	reqBody := refreshRequestPayload{
		SourceID:     SourceID,
		DeviceID:     deviceID,
		RefreshToken: refreshToken,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, 0, "", fmt.Errorf("zai refresh: failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, 0, "", fmt.Errorf("zai refresh: failed to create request: %w", err)
	}

	ts := strconv.FormatInt(time.Now().Unix(), 10)
	sign := AuthSign(AppID, ts, AppKey)
	traceID := newRandomUUID()

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "*")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("User-Agent", "node")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("X-Version", XVersion)
	req.Header.Set("X-Tm", "win")
	req.Header.Set("X-Product", "autoclaw")
	req.Header.Set("X-Channel", "zai")
	req.Header.Set("X-Lang", XLang)
	req.Header.Set("X-Trace-Id", traceID)
	req.Header.Set("X-Auth-Appid", AppID)
	req.Header.Set("X-Auth-TimeStamp", ts)
	req.Header.Set("X-Auth-Sign", sign)

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, "", fmt.Errorf("zai refresh: HTTP request failed: %w", err)
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			log.Errorf("zai refresh: close response body error: %v", errClose)
		}
	}()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, "", fmt.Errorf("zai refresh: failed to read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, 0, "", fmt.Errorf("zai refresh: unexpected status code %d: %s", resp.StatusCode, string(respBody))
	}

	var resPayload refreshResponsePayload
	if err := json.Unmarshal(respBody, &resPayload); err != nil {
		return nil, 0, "", fmt.Errorf("zai refresh: failed to decode response JSON: %w (body: %s)", err, string(respBody))
	}

	if resPayload.Code != 0 || resPayload.Data == nil || strings.TrimSpace(resPayload.Data.AccessToken) == "" {
		return nil, resPayload.Code, resPayload.Msg, fmt.Errorf("zai refresh failed: code=%d msg=%s", resPayload.Code, resPayload.Msg)
	}

	var userID int64
	if resPayload.Data.UserID != "" {
		userID, _ = resPayload.Data.UserID.Int64()
	}

	return &RefreshData{
		AccessToken:  StripBearerScheme(resPayload.Data.AccessToken),
		RefreshToken: StripBearerScheme(resPayload.Data.RefreshToken),
		UserID:       userID,
		UserName:     resPayload.Data.UserName,
	}, resPayload.Code, resPayload.Msg, nil
}

// AuthSign calculates the MD5 signature for z.ai userapi: md5(appid + "&" + timestamp + "&" + appkey).
func AuthSign(appID, ts, appKey string) string {
	raw := fmt.Sprintf("%s&%s&%s", appID, ts, appKey)
	hash := md5.Sum([]byte(raw))
	return hex.EncodeToString(hash[:])
}

// IsJWT reports whether s looks like a three-segment JWT token.
func IsJWT(s string) bool {
	return jwtPattern.MatchString(strings.TrimSpace(s))
}

// JWTExpMs parses the expiration timestamp (in milliseconds) from a JWT's base64url payload.
// Returns 0 if parsing fails or exp is not present.
func JWTExpMs(token string) int64 {
	token = strings.TrimSpace(token)
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return 0
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// Fallback to std url encoding
		payloadBytes, err = base64.URLEncoding.DecodeString(parts[1])
		if err != nil {
			return 0
		}
	}

	var claims struct {
		Exp json.Number `json:"exp"`
	}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return 0
	}

	if claims.Exp == "" {
		return 0
	}

	expFloat, err := claims.Exp.Float64()
	if err != nil || expFloat <= 0 {
		return 0
	}

	return int64(expFloat * 1000)
}

func newRandomUUID() string {
	var buf [16]byte
	_, _ = rand.Read(buf[:])
	buf[6] = (buf[6] & 0x0f) | 0x40 // Version 4
	buf[8] = (buf[8] & 0x3f) | 0x80 // Variant RFC 4122
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		buf[0:4],
		buf[4:6],
		buf[6:8],
		buf[8:10],
		buf[10:16],
	)
}
