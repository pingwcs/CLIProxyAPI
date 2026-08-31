package auth

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

type testTokenStorage struct {
	meta map[string]any
}

func (s *testTokenStorage) SetMetadata(meta map[string]any) { s.meta = meta }

func (s *testTokenStorage) SaveTokenToFile(authFilePath string) error {
	raw, err := json.Marshal(s.meta)
	if err != nil {
		return err
	}
	return os.WriteFile(authFilePath, raw, 0o600)
}

func TestFileTokenStore_Save_DisabledPersistsFlagForTokenStorage(t *testing.T) {
	ctx := context.Background()
	baseDir := t.TempDir()
	path := filepath.Join(baseDir, "disabled.json")

	if err := os.WriteFile(path, []byte(`{"type":"test","disabled":true}`), 0o600); err != nil {
		t.Fatalf("seed auth file: %v", err)
	}

	store := NewFileTokenStore()
	store.SetBaseDir(baseDir)
	storage := &testTokenStorage{}

	auth := &cliproxyauth.Auth{
		ID:       "disabled.json",
		Provider: "test",
		FileName: "disabled.json",
		Disabled: true,
		Storage:  storage,
		Metadata: map[string]any{"type": "test"},
	}

	if _, err := store.Save(ctx, auth); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read auth file: %v", err)
	}
	var meta map[string]any
	if err := json.Unmarshal(raw, &meta); err != nil {
		t.Fatalf("unmarshal auth file: %v", err)
	}
	if disabled, _ := meta["disabled"].(bool); !disabled {
		t.Fatalf("disabled=%v, want true (raw=%s)", meta["disabled"], string(raw))
	}
}

func TestFileTokenStore_PersistAndReload_PreservesDisabledState(t *testing.T) {
	ctx := context.Background()
	baseDir := t.TempDir()
	path := filepath.Join(baseDir, "zai_auth.json")

	if err := os.WriteFile(path, []byte(`{"type":"zai","token":"abc"}`), 0o600); err != nil {
		t.Fatalf("seed auth file: %v", err)
	}

	store := NewFileTokenStore()
	store.SetBaseDir(baseDir)

	auth := &cliproxyauth.Auth{
		ID:       "zai_auth.json",
		Provider: "zai",
		FileName: "zai_auth.json",
		Status:   cliproxyauth.StatusDisabled,
		Disabled: true,
		Metadata: map[string]any{
			"type":     "zai",
			"token":    "abc",
			"disabled": true,
		},
		Attributes: map[string]string{
			cliproxyauth.AttributePath:   path,
			cliproxyauth.AttributeSource: path,
		},
	}

	if _, errSave := store.Save(ctx, auth); errSave != nil {
		t.Fatalf("Save() error: %v", errSave)
	}

	// Read auth files back from disk
	auths, errRead := store.readAuthFiles(path, baseDir)
	if errRead != nil {
		t.Fatalf("readAuthFiles() error: %v", errRead)
	}
	if len(auths) != 1 {
		t.Fatalf("expected 1 auth, got %d", len(auths))
	}
	reloaded := auths[0]
	if !reloaded.Disabled {
		t.Fatalf("expected reloaded auth to have Disabled=true, got false")
	}
	if reloaded.Status != cliproxyauth.StatusDisabled {
		t.Fatalf("expected reloaded auth to have Status=StatusDisabled, got %s", reloaded.Status)
	}
}
