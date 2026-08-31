package zai

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthSign_Deterministic(t *testing.T) {
	ts := "1725100000"
	expectedRaw := fmt.Sprintf("%s&%s&%s", AppID, ts, AppKey)
	h := md5.Sum([]byte(expectedRaw))
	expectedSign := hex.EncodeToString(h[:])

	sign := AuthSign(AppID, ts, AppKey)
	if sign != expectedSign {
		t.Fatalf("AuthSign = %q, want %q", sign, expectedSign)
	}
}

func TestWalletHostFromTokenEndpoint(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		want     string
	}{
		{
			name:     "empty endpoint",
			endpoint: "",
			want:     DefaultWalletHost,
		},
		{
			name:     "whitespace only",
			endpoint: "   ",
			want:     DefaultWalletHost,
		},
		{
			name:     "standard https url",
			endpoint: "https://autoglm-api.autoglm.ai/userapi/v1/refresh",
			want:     "https://autoglm-api.autoglm.ai",
		},
		{
			name:     "custom port host",
			endpoint: "https://custom.api.org:8443/refresh/path",
			want:     "https://custom.api.org:8443",
		},
		{
			name:     "invalid url",
			endpoint: "::not-a-valid-url::",
			want:     DefaultWalletHost,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WalletHostFromTokenEndpoint(tt.endpoint)
			if got != tt.want {
				t.Errorf("WalletHostFromTokenEndpoint(%q) = %q, want %q", tt.endpoint, got, tt.want)
			}
		})
	}
}

func TestFetchWalletBalance_Success(t *testing.T) {
	mockToken := "mock-jwt-token"
	rawTokenWithBearer := "Bearer " + mockToken

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if r.URL.Path != WalletPath {
			t.Errorf("expected path %s, got %s", WalletPath, r.URL.Path)
		}
		if r.URL.Query().Get("biz_app_id") != "autoclaw" {
			t.Errorf("expected query param biz_app_id=autoclaw, got %q", r.URL.Query().Get("biz_app_id"))
		}
		if r.Header.Get("Authorization") != "Bearer "+mockToken {
			t.Errorf("expected Authorization Bearer %s, got %s", mockToken, r.Header.Get("Authorization"))
		}
		if r.Header.Get("X-Auth-Appid") != AppID {
			t.Errorf("unexpected X-Auth-Appid: %s", r.Header.Get("X-Auth-Appid"))
		}
		reqTs := r.Header.Get("X-Auth-TimeStamp")
		if reqTs == "" {
			t.Errorf("missing X-Auth-TimeStamp")
		}
		expectedSign := AuthSign(AppID, reqTs, AppKey)
		if r.Header.Get("X-Auth-Sign") != expectedSign {
			t.Errorf("X-Auth-Sign = %q, want %q", r.Header.Get("X-Auth-Sign"), expectedSign)
		}
		if r.Header.Get("X-Version") != XVersion {
			t.Errorf("unexpected X-Version: %s", r.Header.Get("X-Version"))
		}
		if r.Header.Get("X-Tm") != "win" {
			t.Errorf("unexpected X-Tm: %s", r.Header.Get("X-Tm"))
		}
		if r.Header.Get("X-Product") != "autoclaw" {
			t.Errorf("unexpected X-Product: %s", r.Header.Get("X-Product"))
		}
		if r.Header.Get("X-Channel") != "zai" {
			t.Errorf("unexpected X-Channel: %s", r.Header.Get("X-Channel"))
		}
		if r.Header.Get("X-Lang") != XLang {
			t.Errorf("unexpected X-Lang: %s", r.Header.Get("X-Lang"))
		}
		if r.Header.Get("X-Trace-Id") == "" {
			t.Errorf("missing X-Trace-Id")
		}
		if r.Header.Get("Accept") != "*/*" {
			t.Errorf("unexpected Accept header: %s", r.Header.Get("Accept"))
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code": 0,
			"msg":  "SUCCESS",
			"data": map[string]any{
				"total_balance": 150.5,
				"wallets": []map[string]any{
					{
						"public_wallet_type": "subscription",
						"display_name":       "Subscription Plan",
						"balance":            100.0,
						"balance_view":       "100.00",
						"display":            true,
						"priority":           1,
					},
					{
						"public_wallet_type": "reward",
						"display_name":       "Reward Bonus",
						"balance":            50.5,
						"balance_view":       "50.50",
						"display":            true,
						"priority":           2,
					},
				},
			},
		})
	}))
	defer ts.Close()

	ctx := context.Background()
	balance, err := FetchWalletBalance(ctx, ts.Client(), ts.URL, rawTokenWithBearer)
	if err != nil {
		t.Fatalf("FetchWalletBalance failed: %v", err)
	}

	if balance.TotalBalance != 150.5 {
		t.Errorf("expected TotalBalance 150.5, got %v", balance.TotalBalance)
	}
	if len(balance.Wallets) != 2 {
		t.Fatalf("expected 2 wallets, got %d", len(balance.Wallets))
	}
	if balance.Wallets[0].Type != "subscription" || balance.Wallets[0].Balance != 100.0 || balance.Wallets[0].BalanceView != "100.00" || !balance.Wallets[0].Display || balance.Wallets[0].Priority != 1 {
		t.Errorf("unexpected wallet 0: %+v", balance.Wallets[0])
	}
	if balance.Wallets[1].Type != "reward" || balance.Wallets[1].Balance != 50.5 || balance.Wallets[1].BalanceView != "50.50" || !balance.Wallets[1].Display || balance.Wallets[1].Priority != 2 {
		t.Errorf("unexpected wallet 1: %+v", balance.Wallets[1])
	}
}

func TestFetchWalletBalance_NonZeroCode(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code": 401001,
			"msg":  "token expired",
			"data": nil,
		})
	}))
	defer ts.Close()

	ctx := context.Background()
	_, err := FetchWalletBalance(ctx, ts.Client(), ts.URL, "sample-token")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if got := err.Error(); got != "zai wallet failed: code=401001 msg=token expired" {
		t.Errorf("unexpected error message: %s", got)
	}
}

func TestFetchWalletBalance_Non2xxStatus(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
	}))
	defer ts.Close()

	ctx := context.Background()
	_, err := FetchWalletBalance(ctx, ts.Client(), ts.URL, "sample-token")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestFetchWalletBalance_EmptyToken(t *testing.T) {
	ctx := context.Background()
	_, err := FetchWalletBalance(ctx, nil, "", "")
	if err == nil {
		t.Fatal("expected error for empty token, got nil")
	}
}
