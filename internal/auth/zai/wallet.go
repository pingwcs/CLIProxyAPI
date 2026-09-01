package zai

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/httpwire"
	log "github.com/sirupsen/logrus"
)

const (
	DefaultWalletHost = "https://autoglm-api.autoglm.ai"
	WalletPath        = "/agent-assetmgr/api/v2/wallets"
)

// ZaiWalletEntry holds the details of an individual wallet.
type ZaiWalletEntry struct {
	Type        string  `json:"public_wallet_type"`
	DisplayName string  `json:"display_name"`
	Balance     float64 `json:"balance"`
	BalanceView string  `json:"balance_view"`
	Display     bool    `json:"display"`
	Priority    int     `json:"priority"`
}

// ZaiWalletBalance holds the aggregated balance and per-wallet breakdown.
type ZaiWalletBalance struct {
	TotalBalance float64          `json:"total_balance"`
	Wallets      []ZaiWalletEntry `json:"wallets"`
}

type walletResponsePayload struct {
	Code int64             `json:"code"`
	Msg  string            `json:"msg"`
	Data *ZaiWalletBalance `json:"data"`
}

// WalletHostFromTokenEndpoint extracts the scheme and host origin from a token endpoint URL,
// falling back to DefaultWalletHost if parsing fails or input is empty.
func WalletHostFromTokenEndpoint(tokenEndpoint string) string {
	trimmed := strings.TrimSpace(tokenEndpoint)
	if trimmed == "" {
		return DefaultWalletHost
	}
	parsed, err := url.Parse(trimmed)
	if err == nil && parsed.Scheme != "" && parsed.Host != "" {
		return parsed.Scheme + "://" + parsed.Host
	}
	return DefaultWalletHost
}

// FetchWalletBalance queries the z.ai wallet endpoint to fetch current credits/balance information.
func FetchWalletBalance(ctx context.Context, httpClient *http.Client, host, accessToken string) (*ZaiWalletBalance, error) {
	token := StripBearerScheme(accessToken)
	if strings.TrimSpace(token) == "" {
		return nil, fmt.Errorf("zai wallet: access_token is empty")
	}

	host = strings.TrimSpace(host)
	if host == "" {
		host = DefaultWalletHost
	}

	targetURL := strings.TrimRight(host, "/") + WalletPath + "?biz_app_id=autoclaw"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("zai wallet: failed to create request: %w", err)
	}

	ts := strconv.FormatInt(time.Now().Unix(), 10)
	sign := AuthSign(AppID, ts, AppKey)
	traceID := newRandomUUID()

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "*")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("User-Agent", "node")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("X-Auth-Appid", AppID)
	req.Header.Set("X-Auth-TimeStamp", ts)
	req.Header.Set("X-Auth-Sign", sign)
	req.Header.Set("X-Version", XVersion)
	req.Header.Set("X-Tm", "win")
	req.Header.Set("X-Product", "autoclaw")
	req.Header.Set("X-Channel", "zai")
	req.Header.Set("X-Lang", XLang)
	req.Header.Set("X-Trace-Id", traceID)

	client := httpClient
	if client == nil {
		client = &http.Client{}
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("zai wallet: HTTP request failed: %w", err)
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			log.Errorf("zai wallet: close response body error: %v", errClose)
		}
	}()

	httpwire.DecompressResponseBody(resp)

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("zai wallet: failed to read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("zai wallet: unexpected status code %d: %s", resp.StatusCode, string(respBody))
	}

	var resPayload walletResponsePayload
	if err := json.Unmarshal(respBody, &resPayload); err != nil {
		return nil, fmt.Errorf("zai wallet: failed to decode response JSON: %w (body: %s)", err, string(respBody))
	}

	if resPayload.Code != 0 {
		return nil, fmt.Errorf("zai wallet failed: code=%d msg=%s", resPayload.Code, resPayload.Msg)
	}

	if resPayload.Data == nil {
		return &ZaiWalletBalance{}, nil
	}

	return resPayload.Data, nil
}
