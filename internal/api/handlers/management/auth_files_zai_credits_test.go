package management

import (
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func TestBuildAuthFileEntry_ZaiCreditsKnown(t *testing.T) {
	h := &Handler{}
	auth := &coreauth.Auth{
		ID:       "zai-test-mgmt-known",
		Provider: "zai",
		Attributes: map[string]string{
			"path": "/tmp/dummy-zai.json",
		},
	}

	updatedAt := time.Unix(1725100000, 0).UTC()
	coreauth.SetZaiCreditsHint(auth.ID, coreauth.ZaiCreditsHint{
		Known:        true,
		TotalBalance: 180.5,
		Wallets: []coreauth.ZaiWalletEntrySnapshot{
			{
				Type:        "subscription",
				BalanceView: "100.00",
				Display:     true,
			},
			{
				Type:        "reward",
				BalanceView: "80.50",
				Display:     true,
			},
		},
		UpdatedAt: updatedAt,
	})

	entry := h.buildAuthFileEntry(auth)
	if entry == nil {
		t.Fatalf("expected non-nil entry")
	}

	creditsRaw, ok := entry["credits"]
	if !ok {
		t.Fatalf("expected entry to have 'credits' key")
	}

	credits, ok := creditsRaw.(gin.H)
	if !ok {
		t.Fatalf("expected credits to be gin.H, got %T", creditsRaw)
	}

	if gotKnown, ok := credits["known"].(bool); !ok || !gotKnown {
		t.Errorf("credits.known = %v, want true", credits["known"])
	}
	if gotTotal, ok := credits["total_balance"].(float64); !ok || gotTotal != 180.5 {
		t.Errorf("credits.total_balance = %v, want 180.5", credits["total_balance"])
	}
	if gotWallets, ok := credits["wallets"].([]coreauth.ZaiWalletEntrySnapshot); !ok || len(gotWallets) != 2 {
		t.Errorf("credits.wallets = %#v, want slice of 2 elements", credits["wallets"])
	}
	if gotUpdated, ok := credits["updated_at"].(time.Time); !ok || !gotUpdated.Equal(updatedAt) {
		t.Errorf("credits.updated_at = %v, want %v", credits["updated_at"], updatedAt)
	}
}

func TestBuildAuthFileEntry_ZaiCreditsUnknown(t *testing.T) {
	h := &Handler{}
	auth := &coreauth.Auth{
		ID:       "zai-test-mgmt-unknown",
		Provider: "zai",
		Attributes: map[string]string{
			"path": "/tmp/dummy-zai.json",
		},
	}

	entry := h.buildAuthFileEntry(auth)
	if entry == nil {
		t.Fatalf("expected non-nil entry")
	}

	creditsRaw, ok := entry["credits"]
	if !ok {
		t.Fatalf("expected entry to have 'credits' key")
	}

	credits, ok := creditsRaw.(gin.H)
	if !ok {
		t.Fatalf("expected credits to be gin.H, got %T", creditsRaw)
	}

	if gotKnown, ok := credits["known"].(bool); !ok || gotKnown {
		t.Errorf("credits.known = %v, want false", credits["known"])
	}
	if _, ok := credits["total_balance"]; ok {
		t.Errorf("credits should not have total_balance when unknown")
	}
}

func TestBuildAuthFileEntry_NonZaiProviderOmitsCredits(t *testing.T) {
	h := &Handler{}
	auth := &coreauth.Auth{
		ID:       "codex-test-mgmt",
		Provider: "codex",
		Attributes: map[string]string{
			"path": "/tmp/dummy-codex.json",
		},
	}

	entry := h.buildAuthFileEntry(auth)
	if entry == nil {
		t.Fatalf("expected non-nil entry")
	}

	if _, ok := entry["credits"]; ok {
		t.Fatalf("non-zai provider should not have credits key in entry")
	}
}
