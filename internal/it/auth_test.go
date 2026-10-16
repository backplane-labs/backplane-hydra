package it_test

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/backplane-labs/backplane-hydra/internal/overlay"
	"github.com/backplane-labs/backplane-hydra/pkg/auth"
)

// TestAccessTokens: a JWT access token verifies locally against Hydra's
// keys, the ID token beside it does not pass for one, introspection asks
// Hydra every time: after a revocation it refuses at once while the JWT
// lives out its TTL (the model's promise).
func TestAccessTokens(t *testing.T) {
	t.Parallel()

	e := startWith(t, func(s *overlay.Settings) { s.Tokens.AccessToken = "jwt" }, nil)

	c := e.newClient(t, true)
	q := newBrowser(t, e.callback).authorize(t, c, e.callback)
	tokens := exchange(t, c, q.Get("code"), e.callback)

	access, idToken := fmt.Sprint(tokens["access_token"]), fmt.Sprint(tokens["id_token"])
	if strings.Count(access, ".") != 2 {
		t.Fatalf("access token is not a JWT: %q", access)
	}

	ctx := t.Context()

	jwts, err := auth.NewTokens(auth.TokensOptions{Issuer: publicURL + "/"})
	if err != nil {
		t.Fatal(err)
	}

	got, err := jwts.Verify(ctx, access)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	t.Logf("claims: %v", got.Claims)

	if got.Subject != subject || got.ClientID != c.ClientID || !got.HasScopes("openid", "email") || got.IsClient() {
		t.Fatalf("jwt auth: %+v", got)
	}

	if _, err := jwts.Verify(ctx, idToken); !errors.Is(err, auth.ErrInvalid) {
		t.Fatalf("an ID token passed for an access token: %v", err)
	}

	introspection, err := auth.NewIntrospection(adminURL, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	in, err := introspection.Verify(ctx, access, "email")
	if err != nil || in.Subject != subject || in.ClientID != c.ClientID {
		t.Fatalf("introspection: %+v %v", in, err)
	}

	if _, err := introspection.Verify(ctx, fmt.Sprint(tokens["refresh_token"])); !errors.Is(err, auth.ErrInvalid) {
		t.Fatalf("a refresh token passed: %v", err)
	}

	revokeToken(t, c.ClientID, c.ClientSecret, access)

	if _, err := introspection.Verify(ctx, access); !errors.Is(err, auth.ErrInactive) {
		t.Fatalf("introspection after revoke: %v", err)
	}

	if _, err := jwts.Verify(ctx, access); err != nil {
		t.Fatalf("the JWT within its TTL: %v", err)
	}
}

// TestOpaqueTokens: with opaque access tokens the authenticator asks Hydra.
func TestOpaqueTokens(t *testing.T) {
	t.Parallel()

	e := start(t, nil)

	c := e.newClient(t, true)
	q := newBrowser(t, e.callback).authorize(t, c, e.callback)
	tokens := exchange(t, c, q.Get("code"), e.callback)

	introspection, _ := auth.NewIntrospection(adminURL, nil, nil)
	a := auth.Authenticator{Introspection: introspection}

	got, err := a.Authenticate(t.Context(), http.Header{"Authorization": {"Bearer " + fmt.Sprint(tokens["access_token"])}})
	if err != nil || got.Subject != subject || got.Source != auth.FromIntrospection {
		t.Fatalf("auth: %+v %v", got, err)
	}
}

// revokeToken revokes a token through Hydra's public revocation endpoint.
func revokeToken(t *testing.T, clientID, secret, token string) {
	t.Helper()

	form := url.Values{"token": {token}, "client_id": {clientID}, "client_secret": {secret}}

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, publicURL+"/oauth2/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("revoke: %s", res.Status)
	}
}
