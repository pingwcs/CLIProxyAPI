package auth

import (
	"context"
	"strings"
	"sync"
	"time"

	homekv "github.com/router-for-me/CLIProxyAPI/v7/internal/home"
)

// ZaiWalletEntrySnapshot holds a snapshot of a single wallet entry in the credits hint.
type ZaiWalletEntrySnapshot struct {
	Type        string `json:"type"`
	BalanceView string `json:"balance_view"`
	Display     bool   `json:"display"`
}

// ZaiCreditsHint stores the latest known credits/wallet state for a zai auth.
type ZaiCreditsHint struct {
	Known        bool                     `json:"known"`
	TotalBalance float64                  `json:"total_balance"`
	Wallets      []ZaiWalletEntrySnapshot `json:"wallets"`
	UpdatedAt    time.Time                `json:"updated_at"`
}

var zaiCreditsHintByAuth sync.Map

// SetZaiCreditsHint updates the latest known credits state for an auth.
func SetZaiCreditsHint(authID string, hint ZaiCreditsHint) {
	authID = strings.TrimSpace(authID)
	if authID == "" {
		return
	}
	if hint.UpdatedAt.IsZero() {
		hint.UpdatedAt = time.Now()
	}
	if _, homeMode, _ := homekv.CurrentKVClient(); homeMode {
		homekv.KVSetJSONBestEffort(context.Background(), zaiCreditsHintKey(authID), hint, 30*time.Minute)
		return
	}
	zaiCreditsHintByAuth.Store(authID, hint)
}

// GetZaiCreditsHint returns the latest known credits state for an auth.
func GetZaiCreditsHint(authID string) (ZaiCreditsHint, bool) {
	hint, ok, err := GetZaiCreditsHintRequired(context.Background(), authID)
	if err == nil {
		return hint, ok
	}
	return ZaiCreditsHint{}, false
}

// GetZaiCreditsHintRequired returns the latest known credits state with error propagation in home mode.
func GetZaiCreditsHintRequired(ctx context.Context, authID string) (ZaiCreditsHint, bool, error) {
	authID = strings.TrimSpace(authID)
	if authID == "" {
		return ZaiCreditsHint{}, false, nil
	}
	var homeHint ZaiCreditsHint
	homeMode, found, errGet := homekv.KVGetJSONRequired(ctx, zaiCreditsHintKey(authID), &homeHint)
	if homeMode {
		return homeHint, found, errGet
	}
	value, ok := zaiCreditsHintByAuth.Load(authID)
	if !ok {
		return ZaiCreditsHint{}, false, nil
	}
	hint, ok := value.(ZaiCreditsHint)
	if !ok {
		zaiCreditsHintByAuth.Delete(authID)
		return ZaiCreditsHint{}, false, nil
	}
	return hint, true, nil
}

// HasKnownZaiCreditsHint reports whether credits state has been discovered for an auth.
func HasKnownZaiCreditsHint(authID string) bool {
	hint, ok := GetZaiCreditsHint(authID)
	return ok && hint.Known
}

func zaiCreditsHintKey(authID string) string {
	return "cpa:zai:credits-hint:" + strings.TrimSpace(authID)
}
