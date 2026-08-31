package management

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	sdkAuth "github.com/router-for-me/CLIProxyAPI/v7/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

func TestPatchAuthFileStatus_DisableZaiAuth(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")

	authDir := t.TempDir()
	fileName := "zai_account.json"
	filePath := filepath.Join(authDir, fileName)
	initialContent := []byte(`{"type":"zai","token":"test-token"}`)
	if errWrite := os.WriteFile(filePath, initialContent, 0o600); errWrite != nil {
		t.Fatalf("failed to write auth file: %v", errWrite)
	}

	filestore := sdkAuth.NewFileTokenStore()
	filestore.SetBaseDir(authDir)
	selector := &coreauth.RoundRobinSelector{}
	manager := coreauth.NewManager(filestore, selector, nil)

	authRecord := &coreauth.Auth{
		ID:       fileName,
		FileName: fileName,
		Provider: "zai",
		Status:   coreauth.StatusActive,
		Disabled: false,
		Metadata: map[string]any{
			"type":  "zai",
			"token": "test-token",
		},
		Attributes: map[string]string{
			coreauth.AttributePath:          filePath,
			coreauth.AttributeSource:        filePath,
			coreauth.AttributeSourceBackend: coreauth.AuthSourceFile,
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if _, errReg := manager.Register(t.Context(), authRecord); errReg != nil {
		t.Fatalf("register auth: %v", errReg)
	}

	// Register model in GlobalModelRegistry for this client
	reg := registry.GetGlobalRegistry()
	reg.RegisterClient(authRecord.ID, "zai", []*registry.ModelInfo{{
		ID:   "zai_auto",
		Type: "zai",
	}})

	// Verify before patch: model is in registry and selector can pick it
	modelsBefore := reg.GetModelsForClient(authRecord.ID)
	if len(modelsBefore) == 0 {
		t.Fatalf("expected models registered for %s", authRecord.ID)
	}
	pickedBefore, errPickBefore := selector.Pick(t.Context(), "zai", "zai_auto", cliproxyexecutor.Options{}, []*coreauth.Auth{authRecord})
	if errPickBefore != nil || pickedBefore == nil || pickedBefore.ID != authRecord.ID {
		t.Fatalf("expected auth to be picked before disable: %v", errPickBefore)
	}

	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir}, manager)

	// Test disabling the auth via UI payload: {"name":"zai_account.json","disabled":true}
	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	req := httptest.NewRequest(http.MethodPatch, "/v0/management/auth-files/status", strings.NewReader(`{"name":"zai_account.json","disabled":true}`))
	req.Header.Set("Content-Type", "application/json")
	ctx.Request = req

	h.PatchAuthFileStatus(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	// 1. In-memory manager assertions
	currentAuth, ok := manager.GetByID(authRecord.ID)
	if !ok || currentAuth == nil {
		t.Fatalf("expected auth %s to exist in manager", authRecord.ID)
	}
	if !currentAuth.Disabled {
		t.Fatalf("expected auth.Disabled == true, got false")
	}
	if currentAuth.Status != coreauth.StatusDisabled {
		t.Fatalf("expected auth.Status == StatusDisabled, got %s", currentAuth.Status)
	}
	if disabledMeta, _ := currentAuth.Metadata["disabled"].(bool); !disabledMeta {
		t.Fatalf("expected auth.Metadata[disabled] == true, got %v", currentAuth.Metadata["disabled"])
	}

	// 2. On-disk persistence assertion
	diskData, errReadDisk := os.ReadFile(filePath)
	if errReadDisk != nil {
		t.Fatalf("failed to read persisted auth file: %v", errReadDisk)
	}
	var diskMeta map[string]any
	if errUnmarshal := json.Unmarshal(diskData, &diskMeta); errUnmarshal != nil {
		t.Fatalf("failed to parse persisted auth JSON: %v", errUnmarshal)
	}
	if disabledDisk, _ := diskMeta["disabled"].(bool); !disabledDisk {
		t.Fatalf("expected persisted disk JSON disabled == true, got %v (data: %s)", diskMeta["disabled"], string(diskData))
	}

	// 3. GlobalModelRegistry assertion: client must be unregistered
	modelsAfter := reg.GetModelsForClient(authRecord.ID)
	if len(modelsAfter) != 0 {
		t.Fatalf("expected client %s to be unregistered from GlobalModelRegistry, but got models: %+v", authRecord.ID, modelsAfter)
	}

	// 4. Selector assertion: disabled auth must be excluded from Pick
	_, errPickAfter := selector.Pick(t.Context(), "zai", "zai_auto", cliproxyexecutor.Options{}, []*coreauth.Auth{currentAuth})
	if errPickAfter == nil {
		t.Fatalf("expected selector.Pick to fail for disabled auth, but succeeded")
	}
}

func TestPatchAuthFileStatus_CaseInsensitiveLookup(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")

	authDir := t.TempDir()
	fileName := "ZAI_Account.json"
	filePath := filepath.Join(authDir, fileName)
	if errWrite := os.WriteFile(filePath, []byte(`{"type":"zai"}`), 0o600); errWrite != nil {
		t.Fatalf("failed to write auth file: %v", errWrite)
	}

	filestore := sdkAuth.NewFileTokenStore()
	filestore.SetBaseDir(authDir)
	manager := coreauth.NewManager(filestore, &coreauth.RoundRobinSelector{}, nil)

	authRecord := &coreauth.Auth{
		ID:       "zai_account.json", // lowercased ID as synthesized on Windows
		FileName: "ZAI_Account.json",
		Provider: "zai",
		Status:   coreauth.StatusActive,
		Disabled: false,
		Metadata: map[string]any{
			"type": "zai",
		},
		Attributes: map[string]string{
			coreauth.AttributePath: filePath,
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if _, errReg := manager.Register(t.Context(), authRecord); errReg != nil {
		t.Fatalf("register auth: %v", errReg)
	}

	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir}, manager)

	// Send request with uppercase name
	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	req := httptest.NewRequest(http.MethodPatch, "/v0/management/auth-files/status", strings.NewReader(`{"name":"ZAI_ACCOUNT.JSON","disabled":true}`))
	req.Header.Set("Content-Type", "application/json")
	ctx.Request = req

	h.PatchAuthFileStatus(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	currentAuth, ok := manager.GetByID(authRecord.ID)
	if !ok || !currentAuth.Disabled {
		t.Fatalf("expected auth to be disabled after case-insensitive lookup, got %+v", currentAuth)
	}
}

func TestPatchAuthFileStatus_PayloadVariants(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")

	authDir := t.TempDir()
	filestore := sdkAuth.NewFileTokenStore()
	filestore.SetBaseDir(authDir)
	manager := coreauth.NewManager(filestore, &coreauth.RoundRobinSelector{}, nil)

	authRecord := &coreauth.Auth{
		ID:        "test-auth.json",
		FileName:  "test-auth.json",
		Provider:  "zai",
		Status:    coreauth.StatusActive,
		Disabled:  false,
		Metadata:  map[string]any{"type": "zai"},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if _, errReg := manager.Register(t.Context(), authRecord); errReg != nil {
		t.Fatalf("register auth: %v", errReg)
	}

	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir}, manager)

	// Variant 1: "enabled": false -> disabled = true
	rec1 := httptest.NewRecorder()
	ctx1, _ := gin.CreateTestContext(rec1)
	req1 := httptest.NewRequest(http.MethodPatch, "/v0/management/auth-files/status", strings.NewReader(`{"name":"test-auth.json","enabled":false}`))
	req1.Header.Set("Content-Type", "application/json")
	ctx1.Request = req1
	h.PatchAuthFileStatus(ctx1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("variant 1 status = %d, want %d body=%s", rec1.Code, http.StatusOK, rec1.Body.String())
	}
	if a, _ := manager.GetByID(authRecord.ID); !a.Disabled {
		t.Fatalf("expected auth disabled via enabled:false")
	}

	// Variant 2: "status": "active" -> disabled = false
	rec2 := httptest.NewRecorder()
	ctx2, _ := gin.CreateTestContext(rec2)
	req2 := httptest.NewRequest(http.MethodPatch, "/v0/management/auth-files/status", strings.NewReader(`{"name":"test-auth.json","status":"active"}`))
	req2.Header.Set("Content-Type", "application/json")
	ctx2.Request = req2
	h.PatchAuthFileStatus(ctx2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("variant 2 status = %d, want %d body=%s", rec2.Code, http.StatusOK, rec2.Body.String())
	}
	if a, _ := manager.GetByID(authRecord.ID); a.Disabled {
		t.Fatalf("expected auth enabled via status:active")
	}

	// Variant 3: "status": "disabled" -> disabled = true
	rec3 := httptest.NewRecorder()
	ctx3, _ := gin.CreateTestContext(rec3)
	req3 := httptest.NewRequest(http.MethodPatch, "/v0/management/auth-files/status", strings.NewReader(`{"name":"test-auth.json","status":"disabled"}`))
	req3.Header.Set("Content-Type", "application/json")
	ctx3.Request = req3
	h.PatchAuthFileStatus(ctx3)
	if rec3.Code != http.StatusOK {
		t.Fatalf("variant 3 status = %d, want %d body=%s", rec3.Code, http.StatusOK, rec3.Body.String())
	}
	if a, _ := manager.GetByID(authRecord.ID); !a.Disabled {
		t.Fatalf("expected auth disabled via status:disabled")
	}
}

func TestPatchAuthFileStatus_SynthesizerEmptyFileNameMatch(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")

	authDir := t.TempDir()
	filePath := filepath.Join(authDir, "custom-zai.json")
	if errWrite := os.WriteFile(filePath, []byte(`{"type":"zai"}`), 0o600); errWrite != nil {
		t.Fatalf("failed to write auth file: %v", errWrite)
	}

	filestore := sdkAuth.NewFileTokenStore()
	filestore.SetBaseDir(authDir)
	manager := coreauth.NewManager(filestore, &coreauth.RoundRobinSelector{}, nil)

	// Auth with empty FileName (as previously produced by synthesizer/file.go)
	authRecord := &coreauth.Auth{
		ID:       "custom-zai.json",
		FileName: "", // empty
		Provider: "zai",
		Status:   coreauth.StatusActive,
		Disabled: false,
		Metadata: map[string]any{"type": "zai"},
		Attributes: map[string]string{
			coreauth.AttributePath: filePath,
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if _, errReg := manager.Register(t.Context(), authRecord); errReg != nil {
		t.Fatalf("register auth: %v", errReg)
	}

	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir}, manager)

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	req := httptest.NewRequest(http.MethodPatch, "/v0/management/auth-files/status", strings.NewReader(`{"name":"custom-zai.json","disabled":true}`))
	req.Header.Set("Content-Type", "application/json")
	ctx.Request = req

	h.PatchAuthFileStatus(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	currentAuth, ok := manager.GetByID(authRecord.ID)
	if !ok || !currentAuth.Disabled {
		t.Fatalf("expected auth to be disabled, got %+v", currentAuth)
	}
}

func TestPatchAuthFileStatus_CallsPostAuthPersistHook(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")

	authDir := t.TempDir()
	filePath := filepath.Join(authDir, "hook-zai.json")
	if errWrite := os.WriteFile(filePath, []byte(`{"type":"zai"}`), 0o600); errWrite != nil {
		t.Fatalf("failed to write auth file: %v", errWrite)
	}

	filestore := sdkAuth.NewFileTokenStore()
	filestore.SetBaseDir(authDir)
	manager := coreauth.NewManager(filestore, &coreauth.RoundRobinSelector{}, nil)

	authRecord := &coreauth.Auth{
		ID:       "hook-zai.json",
		FileName: "hook-zai.json",
		Provider: "zai",
		Status:   coreauth.StatusActive,
		Disabled: false,
		Metadata: map[string]any{"type": "zai"},
		Attributes: map[string]string{
			coreauth.AttributePath: filePath,
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if _, errReg := manager.Register(t.Context(), authRecord); errReg != nil {
		t.Fatalf("register auth: %v", errReg)
	}

	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir}, manager)

	hookCalled := false
	var hookedAuth *coreauth.Auth
	h.SetPostAuthPersistHook(func(ctx context.Context, auth *coreauth.Auth) error {
		hookCalled = true
		hookedAuth = auth
		return nil
	})

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	req := httptest.NewRequest(http.MethodPatch, "/v0/management/auth-files/status", strings.NewReader(`{"name":"hook-zai.json","disabled":true}`))
	req.Header.Set("Content-Type", "application/json")
	ctx.Request = req

	h.PatchAuthFileStatus(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if !hookCalled {
		t.Fatalf("expected PostAuthPersistHook to be called on status patch")
	}
	if hookedAuth == nil || !hookedAuth.Disabled {
		t.Fatalf("expected hookedAuth to have Disabled=true, got %+v", hookedAuth)
	}
}
