package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// zaiRefreshLead is the duration before token expiry when refresh should occur.
var zaiRefreshLead = 60 * time.Minute

// ZAIAuthenticator implements the Authenticator interface for AutoClaw (z.ai).
type ZAIAuthenticator struct{}

// NewZAIAuthenticator constructs a new ZAI authenticator.
func NewZAIAuthenticator() Authenticator {
	return &ZAIAuthenticator{}
}

// Provider returns the provider key for zai.
func (ZAIAuthenticator) Provider() string {
	return "zai"
}

// RefreshLead returns the duration before token expiry when refresh should occur.
func (ZAIAuthenticator) RefreshLead() *time.Duration {
	return &zaiRefreshLead
}

// Login returns an error explaining that interactive login is unsupported for zai.
func (ZAIAuthenticator) Login(ctx context.Context, cfg *config.Config, opts *LoginOptions) (*coreauth.Auth, error) {
	return nil, fmt.Errorf("zai: interactive login not supported; import auth files exported by the my_zai bridge (node server.mjs --export-cpa) into the auths directory")
}
