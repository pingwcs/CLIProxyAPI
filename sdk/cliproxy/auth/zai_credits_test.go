package auth

import (
	"context"
	"testing"
	"time"
)

func TestZaiCreditsHint_InMemory(t *testing.T) {
	authID := "zai-test-auth-1"

	// Initial check should be not found
	if HasKnownZaiCreditsHint(authID) {
		t.Fatalf("expected HasKnownZaiCreditsHint to be false initially")
	}
	if _, ok := GetZaiCreditsHint(authID); ok {
		t.Fatalf("expected GetZaiCreditsHint to return ok=false initially")
	}

	hint := ZaiCreditsHint{
		Known:        true,
		TotalBalance: 123.45,
		Wallets: []ZaiWalletEntrySnapshot{
			{
				Type:        "subscription",
				BalanceView: "100.00",
				Display:     true,
			},
			{
				Type:        "reward",
				BalanceView: "23.45",
				Display:     true,
			},
		},
		UpdatedAt: time.Now(),
	}

	SetZaiCreditsHint(authID, hint)

	if !HasKnownZaiCreditsHint(authID) {
		t.Fatalf("expected HasKnownZaiCreditsHint to be true after set")
	}

	got, ok := GetZaiCreditsHint(authID)
	if !ok {
		t.Fatalf("expected GetZaiCreditsHint to return ok=true")
	}
	if !got.Known || got.TotalBalance != 123.45 {
		t.Errorf("got TotalBalance=%v Known=%v, want 123.45 and true", got.TotalBalance, got.Known)
	}
	if len(got.Wallets) != 2 {
		t.Fatalf("got %d wallets, want 2", len(got.Wallets))
	}
	if got.Wallets[0].Type != "subscription" || got.Wallets[0].BalanceView != "100.00" || !got.Wallets[0].Display {
		t.Errorf("unexpected wallet 0: %+v", got.Wallets[0])
	}
	if got.Wallets[1].Type != "reward" || got.Wallets[1].BalanceView != "23.45" || !got.Wallets[1].Display {
		t.Errorf("unexpected wallet 1: %+v", got.Wallets[1])
	}
}

func TestZaiCreditsHint_EmptyAuthID(t *testing.T) {
	SetZaiCreditsHint("", ZaiCreditsHint{Known: true, TotalBalance: 10})
	if HasKnownZaiCreditsHint("") {
		t.Fatalf("expected HasKnownZaiCreditsHint to be false for empty authID")
	}
	if _, ok := GetZaiCreditsHint(""); ok {
		t.Fatalf("expected GetZaiCreditsHint to return ok=false for empty authID")
	}
	if _, ok, err := GetZaiCreditsHintRequired(context.Background(), ""); err != nil || ok {
		t.Fatalf("expected GetZaiCreditsHintRequired to return ok=false err=nil for empty authID")
	}
}

func TestZaiCreditsHint_AutoTimestamp(t *testing.T) {
	authID := "zai-test-auth-ts"
	SetZaiCreditsHint(authID, ZaiCreditsHint{Known: true, TotalBalance: 50})

	got, ok := GetZaiCreditsHint(authID)
	if !ok {
		t.Fatalf("expected GetZaiCreditsHint to return ok=true")
	}
	if got.UpdatedAt.IsZero() {
		t.Fatalf("expected UpdatedAt to be automatically populated")
	}
}
