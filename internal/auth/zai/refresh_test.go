package zai

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRefreshAccess_Success(t *testing.T) {
	expectedDeviceID := "test-device-123"
	expectedRefreshToken := "initial-refresh-token"
	mockNewAccess := "new-access-jwt-token"
	mockNewRefresh := "rotated-refresh-token"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("unexpected Content-Type: %s", r.Header.Get("Content-Type"))
		}
		if r.Header.Get("X-Auth-Appid") != AppID {
			t.Errorf("unexpected X-Auth-Appid: %s", r.Header.Get("X-Auth-Appid"))
		}
		if r.Header.Get("X-Auth-Sign") == "" {
			t.Errorf("missing X-Auth-Sign header")
		}
		if r.Header.Get("X-Trace-Id") == "" {
			t.Errorf("missing X-Trace-Id header")
		}

		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed to read body: %v", err)
		}
		var payload map[string]string
		if err := json.Unmarshal(bodyBytes, &payload); err != nil {
			t.Fatalf("failed to parse json body: %v", err)
		}

		if payload["source_id"] != SourceID {
			t.Errorf("expected source_id=%s, got %s", SourceID, payload["source_id"])
		}
		if payload["device_id"] != expectedDeviceID {
			t.Errorf("expected device_id=%s, got %s", expectedDeviceID, payload["device_id"])
		}
		if payload["refresh_token"] != expectedRefreshToken {
			t.Errorf("expected refresh_token=%s, got %s", expectedRefreshToken, payload["refresh_token"])
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code": 0,
			"msg":  "",
			"data": map[string]any{
				"access_token":  mockNewAccess,
				"refresh_token": mockNewRefresh,
				"user_id":       137721,
				"user_name":     "test_user",
			},
		})
	}))
	defer ts.Close()

	ctx := context.Background()
	refreshed, err := RefreshAccess(ctx, ts.Client(), ts.URL+"/userapi/v1/refresh", expectedDeviceID, expectedRefreshToken, "")
	if err != nil {
		t.Fatalf("RefreshAccess failed: %v", err)
	}

	if refreshed.AccessToken != mockNewAccess {
		t.Errorf("expected AccessToken %q, got %q", mockNewAccess, refreshed.AccessToken)
	}
	if refreshed.RefreshToken != mockNewRefresh {
		t.Errorf("expected RefreshToken %q, got %q", mockNewRefresh, refreshed.RefreshToken)
	}
	if refreshed.UserID != 137721 {
		t.Errorf("expected UserID 137721, got %d", refreshed.UserID)
	}
	if refreshed.UserName != "test_user" {
		t.Errorf("expected UserName 'test_user', got %q", refreshed.UserName)
	}
}

func TestRefreshAccess_FallbackOn400002(t *testing.T) {
	primaryHits := 0
	fallbackHits := 0

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "agent-refresh") {
			fallbackHits++
			_ = json.NewEncoder(w).Encode(map[string]any{
				"code": 0,
				"msg":  "ok",
				"data": map[string]any{
					"access_token":  "fallback-access-token",
					"refresh_token": "fallback-refresh-token",
					"user_id":       42,
					"user_name":     "fallback_user",
				},
			})
			return
		}

		primaryHits++
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code": 400002,
			"msg":  "signature check error",
			"data": nil,
		})
	}))
	defer ts.Close()

	ctx := context.Background()
	refreshed, err := RefreshAccess(ctx, ts.Client(), ts.URL+DefaultRefreshPath, "dev-1", "ref-1", "")
	if err != nil {
		t.Fatalf("expected fallback success, got err: %v", err)
	}

	if primaryHits != 1 {
		t.Errorf("expected 1 primary hit, got %d", primaryHits)
	}
	if fallbackHits != 1 {
		t.Errorf("expected 1 fallback hit, got %d", fallbackHits)
	}
	if refreshed.AccessToken != "fallback-access-token" {
		t.Errorf("unexpected access token: %s", refreshed.AccessToken)
	}
}

func TestRefreshAccess_Error(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code": 500001,
			"msg":  "invalid refresh token",
			"data": nil,
		})
	}))
	defer ts.Close()

	ctx := context.Background()
	_, err := RefreshAccess(ctx, ts.Client(), ts.URL, "dev-1", "ref-invalid", "")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "code=500001") {
		t.Errorf("expected error to contain code=500001, got: %v", err)
	}
}

func TestJWTExpMs(t *testing.T) {
	nowSec := time.Now().Unix() + 3600
	payloadJSON := fmt.Sprintf(`{"user_id":123,"exp":%d}`, nowSec)
	payloadB64 := base64.RawURLEncoding.EncodeToString([]byte(payloadJSON))
	token := fmt.Sprintf("eyJhbGciOiJIUzI1NiJ9.%s.dummySignature", payloadB64)

	expMs := JWTExpMs(token)
	expectedMs := nowSec * 1000
	if expMs != expectedMs {
		t.Errorf("expected expMs %d, got %d", expectedMs, expMs)
	}

	// Invalid tokens
	if JWTExpMs("invalid") != 0 {
		t.Errorf("expected 0 for invalid token")
	}
	if JWTExpMs("a.b.c") != 0 {
		t.Errorf("expected 0 for malformed json token")
	}
}

func TestIsJWT(t *testing.T) {
	valid := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgN_pGM"
	if !IsJWT(valid) {
		t.Errorf("expected true for %s", valid)
	}

	invalid := "not-a-jwt"
	if IsJWT(invalid) {
		t.Errorf("expected false for %s", invalid)
	}
}
