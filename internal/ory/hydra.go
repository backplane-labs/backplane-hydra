package ory

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// Client of OAuth 2.0 as Hydra stores it; Hydra owns the JSON, the fields
// here are what backplane-hydra reads.
type OAuth2Client struct {
	ClientID                string          `json:"client_id,omitempty"`
	ClientName              string          `json:"client_name,omitempty"`
	ClientSecret            string          `json:"client_secret,omitempty"              schemapb:"secret=true"`
	ClientSecretExpiresAt   int64           `json:"client_secret_expires_at,omitempty"`
	GrantTypes              []string        `json:"grant_types,omitempty"`
	ResponseTypes           []string        `json:"response_types,omitempty"`
	RedirectURIs            []string        `json:"redirect_uris,omitempty"`
	PostLogoutRedirectURIs  []string        `json:"post_logout_redirect_uris,omitempty"`
	Scope                   string          `json:"scope,omitempty"`
	Audience                []string        `json:"audience,omitempty"`
	TokenEndpointAuthMethod string          `json:"token_endpoint_auth_method,omitempty"`
	AccessTokenStrategy     string          `json:"access_token_strategy,omitempty"`
	SkipConsent             bool            `json:"skip_consent,omitempty"`
	SkipLogoutConsent       *bool           `json:"skip_logout_consent,omitempty"`
	SubjectType             string          `json:"subject_type,omitempty"`
	Owner                   string          `json:"owner,omitempty"`
	Contacts                []string        `json:"contacts,omitempty"`
	ClientURI               string          `json:"client_uri,omitempty"`
	LogoURI                 string          `json:"logo_uri,omitempty"`
	PolicyURI               string          `json:"policy_uri,omitempty"`
	TOSURI                  string          `json:"tos_uri,omitempty"`
	AllowedCORSOrigins      []string        `json:"allowed_cors_origins,omitempty"`
	JWKSURI                 string          `json:"jwks_uri,omitempty"`
	JWKS                    json.RawMessage `json:"jwks,omitempty"`
	FrontchannelLogoutURI   string          `json:"frontchannel_logout_uri,omitempty"`
	BackchannelLogoutURI    string          `json:"backchannel_logout_uri,omitempty"`
	Metadata                json.RawMessage `json:"metadata,omitempty"`
	CreatedAt               *time.Time      `json:"created_at,omitempty"`
	UpdatedAt               *time.Time      `json:"updated_at,omitempty"`
}

// ClientFilter narrows ListClients.
type ClientFilter struct {
	Name      string
	Owner     string
	PageSize  int
	PageToken string
}

// ListClients pages through the clients.
func (c Client) ListClients(ctx context.Context, f ClientFilter) (Page[OAuth2Client], error) {
	q := url.Values{}
	if f.Name != "" {
		q.Set("client_name", f.Name)
	}

	if f.Owner != "" {
		q.Set("owner", f.Owner)
	}

	paging(q, f.PageSize, f.PageToken)

	var out []OAuth2Client

	h, err := c.do(ctx, request{method: http.MethodGet, base: c.admin, path: "/admin/clients", query: q}, &out)

	return Page[OAuth2Client]{Items: out, Next: nextToken(h)}, err
}

// GetClient reads one client.
func (c Client) GetClient(ctx context.Context, id string) (OAuth2Client, error) {
	var out OAuth2Client

	_, err := c.do(
		ctx,
		request{method: http.MethodGet, base: c.admin, path: "/admin/clients/" + url.PathEscape(id)},
		&out,
	)

	return out, err
}

// CreateClient creates one from Hydra's client JSON; the answer carries
// the generated secret (the only time Hydra shows it).
func (c Client) CreateClient(ctx context.Context, body json.RawMessage) (OAuth2Client, error) {
	var out OAuth2Client

	_, err := c.do(ctx, request{method: http.MethodPost, base: c.admin, path: "/admin/clients", body: body}, &out)

	return out, err
}

// SetClient replaces one with Hydra's client JSON.
func (c Client) SetClient(ctx context.Context, id string, body json.RawMessage) (OAuth2Client, error) {
	var out OAuth2Client

	_, err := c.do(ctx, request{
		method: http.MethodPut, base: c.admin, path: "/admin/clients/" + url.PathEscape(id), body: body,
	}, &out)

	return out, err
}

// PatchClient applies a JSON Patch to one.
func (c Client) PatchClient(ctx context.Context, id string, patch json.RawMessage) (OAuth2Client, error) {
	var out OAuth2Client

	_, err := c.do(ctx, request{
		method: http.MethodPatch, base: c.admin, path: "/admin/clients/" + url.PathEscape(id), body: patch,
	}, &out)

	return out, err
}

// DeleteClient deletes one.
func (c Client) DeleteClient(ctx context.Context, id string) error {
	_, err := c.do(
		ctx,
		request{method: http.MethodDelete, base: c.admin, path: "/admin/clients/" + url.PathEscape(id)},
		nil,
	)

	return err
}

// ConsentRequest is a pending consent.
type ConsentRequest struct {
	Challenge                    string          `json:"challenge"`
	Subject                      string          `json:"subject"`
	Client                       OAuth2Client    `json:"client"`
	RequestedScope               []string        `json:"requested_scope"`
	RequestedAccessTokenAudience []string        `json:"requested_access_token_audience"`
	Skip                         bool            `json:"skip"`
	ACR                          string          `json:"acr,omitempty"`
	AMR                          []string        `json:"amr,omitempty"`
	Context                      json.RawMessage `json:"context,omitempty"`
	OIDCContext                  json.RawMessage `json:"oidc_context,omitempty"`
	LoginSessionID               string          `json:"login_session_id,omitempty"`
	RequestURL                   string          `json:"request_url,omitempty"`
}

// ConsentSession are the claims a consent puts into tokens.
type ConsentSession struct {
	AccessToken json.RawMessage `json:"access_token,omitempty"`
	IDToken     json.RawMessage `json:"id_token,omitempty"`
}

// AcceptConsent is Hydra's acceptOAuth2ConsentRequest.
type AcceptConsent struct {
	GrantScope    []string       `json:"grant_scope"`
	GrantAudience []string       `json:"grant_access_token_audience,omitempty"`
	Remember      bool           `json:"remember,omitempty"`
	RememberFor   int64          `json:"remember_for,omitempty"`
	Session       ConsentSession `json:"session"`
}

// Reject is Hydra's rejectOAuth2Request.
type Reject struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorHint        string `json:"error_hint,omitempty"`
	StatusCode       int    `json:"status_code,omitempty"`
}

type redirect struct {
	RedirectTo string `json:"redirect_to"`
}

func (c Client) challenge(ctx context.Context, method, kind, action, challenge string, body, out any) error {
	path := "/admin/oauth2/auth/requests/" + kind
	if action != "" {
		path += "/" + action
	}

	_, err := c.do(ctx, request{
		method: method, base: c.admin, path: path, query: url.Values{kind + "_challenge": {challenge}}, body: body,
	}, out)

	return err
}

// GetConsentRequest reads a pending consent.
func (c Client) GetConsentRequest(ctx context.Context, challenge string) (ConsentRequest, error) {
	var out ConsentRequest

	err := c.challenge(ctx, http.MethodGet, "consent", "", challenge, nil, &out)

	return out, err
}

// AcceptConsentRequest accepts it: the redirect that resumes the flow.
func (c Client) AcceptConsentRequest(ctx context.Context, challenge string, a AcceptConsent) (string, error) {
	var out redirect

	err := c.challenge(ctx, http.MethodPut, "consent", "accept", challenge, a, &out)

	return out.RedirectTo, err
}

// RejectConsentRequest rejects it: the redirect that ends the flow.
func (c Client) RejectConsentRequest(ctx context.Context, challenge string, r Reject) (string, error) {
	var out redirect

	err := c.challenge(ctx, http.MethodPut, "consent", "reject", challenge, r, &out)

	return out.RedirectTo, err
}

// LoginRequest is a pending login.
type LoginRequest struct {
	Challenge      string          `json:"challenge"`
	Subject        string          `json:"subject,omitempty"`
	Skip           bool            `json:"skip"`
	Client         OAuth2Client    `json:"client"`
	RequestedScope []string        `json:"requested_scope,omitempty"`
	OIDCContext    json.RawMessage `json:"oidc_context,omitempty"`
	SessionID      string          `json:"session_id,omitempty"`
	RequestURL     string          `json:"request_url,omitempty"`
}

// AcceptLogin is Hydra's acceptOAuth2LoginRequest.
type AcceptLogin struct {
	Subject     string          `json:"subject"`
	Remember    bool            `json:"remember,omitempty"`
	RememberFor int64           `json:"remember_for,omitempty"`
	ACR         string          `json:"acr,omitempty"`
	AMR         []string        `json:"amr,omitempty"`
	Context     json.RawMessage `json:"context,omitempty"`
}

// GetLoginRequest reads a pending login.
func (c Client) GetLoginRequest(ctx context.Context, challenge string) (LoginRequest, error) {
	var out LoginRequest

	err := c.challenge(ctx, http.MethodGet, "login", "", challenge, nil, &out)

	return out, err
}

// AcceptLoginRequest accepts it.
func (c Client) AcceptLoginRequest(ctx context.Context, challenge string, a AcceptLogin) (string, error) {
	var out redirect

	err := c.challenge(ctx, http.MethodPut, "login", "accept", challenge, a, &out)

	return out.RedirectTo, err
}

// RejectLoginRequest rejects it.
func (c Client) RejectLoginRequest(ctx context.Context, challenge string, r Reject) (string, error) {
	var out redirect

	err := c.challenge(ctx, http.MethodPut, "login", "reject", challenge, r, &out)

	return out.RedirectTo, err
}

// LogoutRequest is a pending logout.
type LogoutRequest struct {
	Challenge   string        `json:"challenge"`
	Subject     string        `json:"subject"`
	SID         string        `json:"sid,omitempty"`
	RPInitiated bool          `json:"rp_initiated"`
	Client      *OAuth2Client `json:"client,omitempty"`
	RequestURL  string        `json:"request_url,omitempty"`
}

// GetLogoutRequest reads a pending logout.
func (c Client) GetLogoutRequest(ctx context.Context, challenge string) (LogoutRequest, error) {
	var out LogoutRequest

	err := c.challenge(ctx, http.MethodGet, "logout", "", challenge, nil, &out)

	return out, err
}

// AcceptLogoutRequest accepts it.
func (c Client) AcceptLogoutRequest(ctx context.Context, challenge string) (string, error) {
	var out redirect

	err := c.challenge(ctx, http.MethodPut, "logout", "accept", challenge, nil, &out)

	return out.RedirectTo, err
}

// ConsentGrant is a remembered consent of a subject.
type ConsentGrant struct {
	ConsentRequest ConsentRequest `json:"consent_request"`
	GrantScope     []string       `json:"grant_scope"`
	GrantAudience  []string       `json:"grant_access_token_audience,omitempty"`
	Remember       bool           `json:"remember"`
	RememberFor    int64          `json:"remember_for"`
	HandledAt      *time.Time     `json:"handled_at,omitempty"`
	Session        ConsentSession `json:"session"`
}

// ListConsentSessions lists a subject's remembered consents.
func (c Client) ListConsentSessions(ctx context.Context, subject, pageToken string) (Page[ConsentGrant], error) {
	q := url.Values{"subject": {subject}}
	paging(q, 0, pageToken)

	var out []ConsentGrant

	h, err := c.do(
		ctx,
		request{method: http.MethodGet, base: c.admin, path: "/admin/oauth2/auth/sessions/consent", query: q},
		&out,
	)

	return Page[ConsentGrant]{Items: out, Next: nextToken(h)}, err
}

// RevokeConsentSessions revokes a subject's consents: of one client, or
// all; tokens issued under them stop working.
func (c Client) RevokeConsentSessions(ctx context.Context, subject, clientID string) error {
	q := url.Values{"subject": {subject}}
	if clientID != "" {
		q.Set("client", clientID)
	} else {
		q.Set("all", "true")
	}

	_, err := c.do(
		ctx,
		request{method: http.MethodDelete, base: c.admin, path: "/admin/oauth2/auth/sessions/consent", query: q},
		nil,
	)

	return err
}

// RevokeLoginSessions ends a subject's (or one session id's) login
// sessions: the next authorization asks to log in again.
func (c Client) RevokeLoginSessions(ctx context.Context, subject, sid string) error {
	q := url.Values{}
	if subject != "" {
		q.Set("subject", subject)
	}

	if sid != "" {
		q.Set("sid", sid)
	}

	_, err := c.do(
		ctx,
		request{method: http.MethodDelete, base: c.admin, path: "/admin/oauth2/auth/sessions/login", query: q},
		nil,
	)

	return err
}

// Introspection is a token's state.
type Introspection struct {
	Active    bool            `json:"active"`
	Subject   string          `json:"sub,omitempty"`
	ClientID  string          `json:"client_id,omitempty"`
	Scope     string          `json:"scope,omitempty"`
	Audience  []string        `json:"aud,omitempty"`
	ExpiresAt int64           `json:"exp,omitempty"`
	IssuedAt  int64           `json:"iat,omitempty"`
	Issuer    string          `json:"iss,omitempty"`
	TokenType string          `json:"token_type,omitempty"`
	TokenUse  string          `json:"token_use,omitempty"`
	Ext       json.RawMessage `json:"ext,omitempty"`
}

// Introspect reports a token's state (RFC 7662 on the admin API).
func (c Client) Introspect(ctx context.Context, token, scope string) (Introspection, error) {
	form := url.Values{"token": {token}}
	if scope != "" {
		form.Set("scope", scope)
	}

	var out Introspection

	_, err := c.doForm(ctx, "/admin/oauth2/introspect", form, &out)

	return out, err
}

// DeleteTokens deletes every token issued to a client.
func (c Client) DeleteTokens(ctx context.Context, clientID string) error {
	_, err := c.do(ctx, request{
		method: http.MethodDelete, base: c.admin, path: "/admin/oauth2/tokens", query: url.Values{"client_id": {clientID}},
	}, nil)

	return err
}

// JWK is a JSON Web Key; private parts are never kept by this package.
type JWK struct {
	KID string   `json:"kid"`
	Alg string   `json:"alg"`
	Use string   `json:"use"`
	Kty string   `json:"kty"`
	Crv string   `json:"crv,omitempty"`
	X5C []string `json:"x5c,omitempty"`
}

// GetKeySet reads a key set's public keys.
func (c Client) GetKeySet(ctx context.Context, set string) ([]JWK, error) {
	var out struct {
		Keys []JWK `json:"keys"`
	}

	_, err := c.do(
		ctx,
		request{method: http.MethodGet, base: c.admin, path: "/admin/keys/" + url.PathEscape(set)},
		&out,
	)

	return out.Keys, err
}

// CreateKey adds a generated key to a set (a rotation: the newest key
// signs, the older ones still verify).
func (c Client) CreateKey(ctx context.Context, set, alg, use, kid string) ([]JWK, error) {
	var out struct {
		Keys []JWK `json:"keys"`
	}

	_, err := c.do(ctx, request{
		method: http.MethodPost, base: c.admin, path: "/admin/keys/" + url.PathEscape(set),
		body: map[string]string{"alg": alg, "use": use, "kid": kid},
	}, &out)

	return out.Keys, err
}

// DeleteKey removes one key from a set.
func (c Client) DeleteKey(ctx context.Context, set, kid string) error {
	_, err := c.do(ctx, request{
		method: http.MethodDelete, base: c.admin, path: "/admin/keys/" + url.PathEscape(set) + "/" + url.PathEscape(kid),
	}, nil)

	return err
}

// TrustedIssuer may sign JWT bearer grants.
type TrustedIssuer struct {
	ID              string     `json:"id"`
	Issuer          string     `json:"issuer"`
	Subject         string     `json:"subject,omitempty"`
	AllowAnySubject bool       `json:"allow_any_subject,omitempty"`
	Scope           []string   `json:"scope"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
	CreatedAt       *time.Time `json:"created_at,omitempty"`
	PublicKey       struct {
		KID string `json:"kid"`
		Set string `json:"set"`
	} `json:"public_key"`
}

// ListTrustedIssuers lists them.
func (c Client) ListTrustedIssuers(ctx context.Context) ([]TrustedIssuer, error) {
	var out []TrustedIssuer

	_, err := c.do(ctx, request{
		method: http.MethodGet, base: c.admin, path: "/admin/trust/grants/jwt-bearer/issuers",
		query: url.Values{"page_size": {strconv.Itoa(maxPage)}},
	}, &out)

	return out, err
}

// TrustIssuer trusts one: body is Hydra's trustOAuth2JwtGrantIssuer.
func (c Client) TrustIssuer(ctx context.Context, body json.RawMessage) (TrustedIssuer, error) {
	var out TrustedIssuer

	_, err := c.do(
		ctx,
		request{method: http.MethodPost, base: c.admin, path: "/admin/trust/grants/jwt-bearer/issuers", body: body},
		&out,
	)

	return out, err
}

// DeleteTrustedIssuer stops trusting one.
func (c Client) DeleteTrustedIssuer(ctx context.Context, id string) error {
	_, err := c.do(ctx, request{
		method: http.MethodDelete, base: c.admin, path: "/admin/trust/grants/jwt-bearer/issuers/" + url.PathEscape(id),
	}, nil)

	return err
}

// Discovery reads the issuer's OpenID configuration (public API).
func (c Client) Discovery(ctx context.Context) (map[string]any, error) {
	var out map[string]any

	_, err := c.do(
		ctx,
		request{method: http.MethodGet, base: c.public, path: "/.well-known/openid-configuration"},
		&out,
	)

	return out, err
}

// maxPage bounds a single-page listing.
const maxPage = 500
