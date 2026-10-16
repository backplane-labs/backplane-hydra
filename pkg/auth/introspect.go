package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Introspection asks Hydra's admin API about a token on every call: no
// cache, so a revoked token fails the next call on every replica.
type Introspection struct {
	endpoint string
	client   *http.Client
	headers  map[string]string
}

// NewIntrospection asks Hydra's admin API at adminURL (as this service
// reaches it); headers go with every request (a proxy's authorization);
// client nil: a client with a 10s timeout.
func NewIntrospection(adminURL string, headers map[string]string, client *http.Client) (Introspection, error) {
	if adminURL == "" {
		return Introspection{}, fmt.Errorf("%w: Hydra's admin URL is required", ErrOptions)
	}

	if client == nil {
		client = &http.Client{Timeout: defaultTimeout}
	}

	return Introspection{
		endpoint: strings.TrimRight(adminURL, "/") + "/admin/oauth2/introspect", client: client, headers: headers,
	}, nil
}

// introspection is Hydra's answer.
type introspection struct {
	Active    bool           `json:"active"`
	Subject   string         `json:"sub"`
	ClientID  string         `json:"client_id"`
	Scope     string         `json:"scope"`
	Audience  []string       `json:"aud"`
	ExpiresAt int64          `json:"exp"`
	IssuedAt  int64          `json:"iat"`
	TokenUse  string         `json:"token_use"`
	Extra     map[string]any `json:"ext"`
}

// maxAnswer bounds Hydra's answer.
const maxAnswer = 1 << 20

// Verify asks Hydra whether token is an active access token and returns
// what it grants; scopes, when given, must all be granted (Hydra checks).
func (i Introspection) Verify(ctx context.Context, token string, scopes ...string) (Auth, error) {
	if token == "" {
		return Auth{}, ErrNoCredential
	}

	form := url.Values{"token": {token}}
	if len(scopes) > 0 {
		form.Set("scope", strings.Join(scopes, " "))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, i.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return Auth{}, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	for k, v := range i.headers {
		req.Header.Set(k, v)
	}

	res, err := i.client.Do(req)
	if err != nil {
		return Auth{}, fmt.Errorf("%w: introspect: %w", ErrUnavailable, err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(io.LimitReader(res.Body, maxAnswer))
	if err != nil {
		return Auth{}, fmt.Errorf("%w: introspect: %w", ErrUnavailable, err)
	}

	if res.StatusCode != http.StatusOK {
		return Auth{}, fmt.Errorf("%w: introspect answered %s: %.200s", ErrUnavailable, res.Status, body)
	}

	var in introspection
	if err := json.Unmarshal(body, &in); err != nil {
		return Auth{}, fmt.Errorf("%w: introspect: %w", ErrUnavailable, err)
	}

	if !in.Active {
		return Auth{}, ErrInactive
	}

	// A refresh token is active too, but it authenticates nothing.
	if in.TokenUse != "" && in.TokenUse != "access_token" {
		return Auth{}, fmt.Errorf("%w: a %s, not an access token", ErrInvalid, in.TokenUse)
	}

	return Auth{
		Subject: in.Subject, ClientID: in.ClientID, Scopes: strings.Fields(in.Scope), Audience: in.Audience,
		ExpiresAt: unix(in.ExpiresAt), IssuedAt: unix(in.IssuedAt), Extra: in.Extra, Source: FromIntrospection,
	}, nil
}

func unix(s int64) time.Time {
	if s == 0 {
		return time.Time{}
	}

	return time.Unix(s, 0)
}
