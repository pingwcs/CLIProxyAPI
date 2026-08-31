package executor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func TestZAIExecutor_UpdateZaiCreditsBalance(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/agent-assetmgr/api/v2/wallets" {
			http.NotFound(w, r)
			return
		}
		if r.URL.Query().Get("biz_app_id") != "autoclaw" {
			t.Errorf("expected biz_app_id=autoclaw, got %s", r.URL.Query().Get("biz_app_id"))
		}
		if r.Header.Get("Authorization") != "Bearer test-jwt-token" {
			t.Errorf("expected Authorization Bearer test-jwt-token, got %s", r.Header.Get("Authorization"))
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code": 0,
			"msg":  "SUCCESS",
			"data": map[string]any{
				"total_balance": 250.0,
				"wallets": []map[string]any{
					{
						"public_wallet_type": "subscription",
						"display_name":       "Subscription Plan",
						"balance":            200.0,
						"balance_view":       "200.00",
						"display":            true,
						"priority":           1,
					},
					{
						"public_wallet_type": "fuel_pack",
						"display_name":       "Fuel Pack",
						"balance":            50.0,
						"balance_view":       "50.00",
						"display":            false,
						"priority":           2,
					},
				},
			},
		})
	}))
	defer ts.Close()

	auth := &cliproxyauth.Auth{
		ID:       "zai-exec-test-1",
		Provider: "zai",
		Metadata: map[string]any{
			"access_token":   "test-jwt-token",
			"token_endpoint": ts.URL + "/userapi/v1/refresh",
		},
	}

	exec := NewZAIExecutor(&config.Config{})
	ctx := context.WithValue(context.Background(), "cliproxy.roundtripper", ts.Client().Transport)

	exec.updateZaiCreditsBalance(ctx, auth, "")

	hint, ok := cliproxyauth.GetZaiCreditsHint(auth.ID)
	if !ok {
		t.Fatalf("expected hint to be found")
	}
	if !hint.Known || hint.TotalBalance != 250.0 {
		t.Fatalf("hint = %+v, want TotalBalance=250.0 Known=true", hint)
	}
	if len(hint.Wallets) != 2 {
		t.Fatalf("expected 2 wallets, got %d", len(hint.Wallets))
	}
	if hint.Wallets[0].Type != "subscription" || hint.Wallets[0].BalanceView != "200.00" || !hint.Wallets[0].Display {
		t.Errorf("wallet 0 mismatch: %+v", hint.Wallets[0])
	}
	if hint.Wallets[1].Type != "fuel_pack" || hint.Wallets[1].BalanceView != "50.00" || hint.Wallets[1].Display {
		t.Errorf("wallet 1 mismatch: %+v", hint.Wallets[1])
	}
}

func TestZAIExecutor_MaybeRefreshZaiCredits_RateLimit(t *testing.T) {
	hits := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code": 0,
			"msg":  "SUCCESS",
			"data": map[string]any{
				"total_balance": 100.0,
				"wallets":       []map[string]any{},
			},
		})
	}))
	defer ts.Close()

	auth := &cliproxyauth.Auth{
		ID:       "zai-exec-test-ratelimit",
		Provider: "zai",
		Metadata: map[string]any{
			"access_token":   "test-token",
			"token_endpoint": ts.URL,
		},
	}

	exec := NewZAIExecutor(&config.Config{})
	ctx := context.WithValue(context.Background(), "cliproxy.roundtripper", ts.Client().Transport)

	// First call triggers async refresh
	exec.maybeRefreshZaiCredits(ctx, auth)

	// Second call immediately should be suppressed by rate limit
	exec.maybeRefreshZaiCredits(ctx, auth)

	// Allow goroutine to complete
	time.Sleep(100 * time.Millisecond)

	if hits != 1 {
		t.Fatalf("expected exactly 1 server hit, got %d", hits)
	}

	hint, ok := cliproxyauth.GetZaiCreditsHint(auth.ID)
	if !ok || !hint.Known {
		t.Fatalf("expected hint to be stored, got %+v (ok=%v)", hint, ok)
	}
}

func TestZAIExecutor_MaybeRefreshZaiCredits_EmptyToken(t *testing.T) {
	auth := &cliproxyauth.Auth{
		ID:       "zai-exec-test-empty",
		Provider: "zai",
		Metadata: map[string]any{},
	}

	exec := NewZAIExecutor(&config.Config{})
	exec.maybeRefreshZaiCredits(context.Background(), auth)

	if cliproxyauth.HasKnownZaiCreditsHint(auth.ID) {
		t.Fatalf("expected no hint for empty token")
	}
}
