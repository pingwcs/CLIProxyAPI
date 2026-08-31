package executor

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	zaiauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/zai"
	homekv "github.com/router-for-me/CLIProxyAPI/v7/internal/home"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

const (
	zaiCreditsHintRefreshInterval = 10 * time.Minute
	zaiCreditsHintRefreshTimeout  = 5 * time.Second
)

var (
	zaiCreditsHintRefreshByID sync.Map // auth.ID → *zaiCreditsHintRefreshState
)

type zaiCreditsHintRefreshState struct {
	mu          sync.Mutex
	lastAttempt time.Time
}

type zaiKVClient interface {
	KVSetNX(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error)
}

var currentZaiKVClient = func() (zaiKVClient, bool, error) {
	return homekv.CurrentKVClient()
}

func zaiCreditsRefreshLockKey(authID string) string {
	return "cpa:zai:credits-refresh-lock:" + strings.TrimSpace(authID)
}

func (e *ZAIExecutor) maybeRefreshZaiCredits(ctx context.Context, auth *cliproxyauth.Auth) {
	if e == nil || auth == nil {
		return
	}
	if ctx != nil && ctx.Err() != nil {
		return
	}
	authID := strings.TrimSpace(auth.ID)
	if authID == "" {
		return
	}
	token := zaiCreds(auth)
	if strings.TrimSpace(token) == "" {
		return
	}

	if client, homeMode, errClient := currentZaiKVClient(); homeMode {
		if errClient != nil {
			log.Errorf("zai executor: home kv best-effort refresh lock failed prefix=cpa:zai:*: %v", errClient)
			return
		}
		written, errSetNX := client.KVSetNX(context.Background(), zaiCreditsRefreshLockKey(authID), []byte("1"), zaiCreditsHintRefreshInterval)
		if errSetNX != nil {
			log.Errorf("zai executor: home kv best-effort refresh lock failed prefix=cpa:zai:*: %v", errSetNX)
			return
		}
		if !written {
			return
		}
		refreshCtx := context.Background()
		if ctx != nil {
			if rt, ok := ctx.Value("cliproxy.roundtripper").(http.RoundTripper); ok && rt != nil {
				refreshCtx = context.WithValue(refreshCtx, "cliproxy.roundtripper", rt)
			}
		}
		refreshCtx, cancel := context.WithTimeout(refreshCtx, zaiCreditsHintRefreshTimeout)
		authCopy := auth.Clone()
		go func(auth *cliproxyauth.Auth, token string) {
			defer cancel()
			e.updateZaiCreditsBalance(refreshCtx, auth, token)
		}(authCopy, token)
		return
	}

	state := &zaiCreditsHintRefreshState{}
	if existing, loaded := zaiCreditsHintRefreshByID.LoadOrStore(authID, state); loaded {
		if cast, ok := existing.(*zaiCreditsHintRefreshState); ok && cast != nil {
			state = cast
		} else {
			zaiCreditsHintRefreshByID.Delete(authID)
			zaiCreditsHintRefreshByID.Store(authID, state)
		}
	}

	now := time.Now()
	if !state.mu.TryLock() {
		return
	}
	if !state.lastAttempt.IsZero() && now.Sub(state.lastAttempt) < zaiCreditsHintRefreshInterval {
		state.mu.Unlock()
		return
	}
	state.lastAttempt = now

	refreshCtx := context.Background()
	if ctx != nil {
		if rt, ok := ctx.Value("cliproxy.roundtripper").(http.RoundTripper); ok && rt != nil {
			refreshCtx = context.WithValue(refreshCtx, "cliproxy.roundtripper", rt)
		}
	}
	refreshCtx, cancel := context.WithTimeout(refreshCtx, zaiCreditsHintRefreshTimeout)
	authCopy := auth.Clone()

	go func(state *zaiCreditsHintRefreshState, auth *cliproxyauth.Auth, token string) {
		defer cancel()
		defer state.mu.Unlock()
		e.updateZaiCreditsBalance(refreshCtx, auth, token)
	}(state, authCopy, token)
}

func (e *ZAIExecutor) updateZaiCreditsBalance(ctx context.Context, auth *cliproxyauth.Auth, token string) {
	if auth == nil || strings.TrimSpace(auth.ID) == "" {
		return
	}
	token = strings.TrimSpace(token)
	if token == "" {
		token = zaiCreds(auth)
	}
	if token == "" {
		return
	}

	host := zaiauth.WalletHostFromTokenEndpoint(zaiTokenEndpoint(auth))
	httpClient := helps.NewZAIHTTPClient(ctx, e.cfg, auth, 0)
	balance, err := zaiauth.FetchWalletBalance(ctx, httpClient, host, token)
	if err != nil {
		log.Debugf("zai executor: refresh credits failed for %s: %v", auth.ID, err)
		return
	}
	if balance == nil {
		return
	}

	wallets := make([]cliproxyauth.ZaiWalletEntrySnapshot, 0, len(balance.Wallets))
	for _, w := range balance.Wallets {
		wallets = append(wallets, cliproxyauth.ZaiWalletEntrySnapshot{
			Type:        w.Type,
			BalanceView: w.BalanceView,
			Display:     w.Display,
		})
	}

	cliproxyauth.SetZaiCreditsHint(strings.TrimSpace(auth.ID), cliproxyauth.ZaiCreditsHint{
		Known:        true,
		TotalBalance: balance.TotalBalance,
		Wallets:      wallets,
		UpdatedAt:    time.Now(),
	})
}
