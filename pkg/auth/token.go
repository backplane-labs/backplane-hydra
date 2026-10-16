package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// Tokens verifies JWT access tokens locally against Hydra's public keys.
// One Tokens serves every goroutine; it holds the keys' cache.
type Tokens struct {
	keys     *keys
	issuer   string
	audience string
	leeway   time.Duration
	now      func() time.Time
}

// TokensOptions configure NewTokens.
type TokensOptions struct {
	// Issuer is Hydra's issuer (urls.self.issuer) tokens must carry as iss.
	// Required.
	Issuer string
	// KeysURL is Hydra's public keys; empty: <Issuer>/.well-known/jwks.json.
	KeysURL string
	// Audience is a value tokens' aud must hold. Empty: not checked — then
	// a token Hydra issued for another API of the installation is accepted
	// too (its signature and issuer still are checked); set it when one
	// Hydra serves several APIs and have clients request the audience.
	Audience string
	// Leeway is the clock skew tolerated on exp, nbf and iat. Default 30s.
	Leeway time.Duration
	// HTTPClient fetches the keys. Default: a client with a 10s timeout.
	HTTPClient *http.Client
	// KeysMaxAge is how old the keys may get before a background refetch.
	// Default 10m. A token with an unknown kid fetches at once anyway.
	KeysMaxAge time.Duration
	// KeysMinRefresh is the least time between two fetches. Default 30s.
	KeysMinRefresh time.Duration
	// Now is the clock (tests). Default time.Now.
	Now func() time.Time
}

// algorithms a token may be signed with: asymmetric only.
//
//nolint:gochecknoglobals // constant list
var algorithms = []jose.SignatureAlgorithm{
	jose.ES256, jose.ES384, jose.ES512, jose.EdDSA, jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512,
}

// Defaults.
const (
	defaultLeeway     = 30 * time.Second
	defaultMaxAge     = 10 * time.Minute
	defaultMinRefresh = 30 * time.Second
	defaultTimeout    = 10 * time.Second
)

// ErrOptions: an option is missing or wrong.
var ErrOptions = errors.New("auth: options")

// NewTokens creates the verifier; it fetches nothing until the first token.
func NewTokens(o TokensOptions) (*Tokens, error) {
	if o.Issuer == "" {
		return nil, fmt.Errorf("%w: Issuer is required", ErrOptions)
	}

	if o.KeysURL == "" {
		o.KeysURL = strings.TrimRight(o.Issuer, "/") + "/.well-known/jwks.json"
	}

	if o.Leeway <= 0 {
		o.Leeway = defaultLeeway
	}

	if o.KeysMaxAge <= 0 {
		o.KeysMaxAge = defaultMaxAge
	}

	if o.KeysMinRefresh <= 0 {
		o.KeysMinRefresh = defaultMinRefresh
	}

	if o.HTTPClient == nil {
		o.HTTPClient = &http.Client{Timeout: defaultTimeout}
	}

	if o.Now == nil {
		o.Now = time.Now
	}

	return &Tokens{
		keys:   newKeys(o.KeysURL, o.HTTPClient, o.KeysMaxAge, o.KeysMinRefresh, o.Now),
		issuer: o.Issuer, audience: o.Audience, leeway: o.Leeway, now: o.Now,
	}, nil
}

// claims are a Hydra access token's claims the package reads.
type claims struct {
	jwt.Claims

	ClientID string         `json:"client_id"`
	Scopes   []string       `json:"scp"`
	Extra    map[string]any `json:"ext"`
}

// idTokenClaims are claims Hydra puts into ID tokens and never into access
// tokens; a consent may add claims to an ID token but not take these away.
//
//nolint:gochecknoglobals // constant list
var idTokenClaims = []string{"auth_time", "at_hash", "nonce", "c_hash"}

// accessToken refuses claims that are not an access token's.
func accessToken(c claims, all map[string]any) error {
	if c.ClientID == "" || c.Expiry == nil || all["scp"] == nil {
		return fmt.Errorf("%w: not an access token (client_id, scp and exp are required)", ErrInvalid)
	}

	for _, claim := range idTokenClaims {
		if _, ok := all[claim]; ok {
			return fmt.Errorf("%w: an ID token (it carries %s), not an access token", ErrInvalid, claim)
		}
	}

	return nil
}

// Verify checks token's signature and claims and returns what it grants.
// An ID token, signed with Hydra's keys too, is refused: an access token
// carries client_id and scp, an ID token auth_time (and at_hash, nonce),
// which no consent can remove.
func (t *Tokens) Verify(ctx context.Context, token string) (Auth, error) {
	parsed, err := jwt.ParseSigned(token, algorithms)
	if err != nil {
		return Auth{}, fmt.Errorf("%w: %w", ErrInvalid, err)
	}

	if len(parsed.Headers) != 1 || parsed.Headers[0].KeyID == "" {
		return Auth{}, fmt.Errorf("%w: one signature with a kid", ErrInvalid)
	}

	header := parsed.Headers[0]

	key, err := t.keys.key(ctx, header.KeyID)
	if err != nil {
		return Auth{}, err
	}

	if key.Algorithm != "" && key.Algorithm != header.Algorithm {
		return Auth{}, fmt.Errorf("%w: signed %s with a key for %s", ErrInvalid, header.Algorithm, key.Algorithm)
	}

	var (
		c   claims
		all map[string]any
	)

	if err := parsed.Claims(key.Key, &c, &all); err != nil {
		return Auth{}, fmt.Errorf("%w: %w", ErrInvalid, err)
	}

	expected := jwt.Expected{Issuer: t.issuer, Time: t.now()}
	if t.audience != "" {
		expected.AnyAudience = jwt.Audience{t.audience}
	}

	if err := c.ValidateWithLeeway(expected, t.leeway); err != nil {
		if errors.Is(err, jwt.ErrExpired) || errors.Is(err, jwt.ErrNotValidYet) {
			return Auth{}, fmt.Errorf("%w: %w", ErrExpired, err)
		}

		return Auth{}, fmt.Errorf("%w: %w", ErrInvalid, err)
	}

	if err := accessToken(c, all); err != nil {
		return Auth{}, err
	}

	a := Auth{
		Subject: c.Subject, ClientID: c.ClientID, Scopes: c.Scopes, Audience: c.Audience,
		ExpiresAt: c.Expiry.Time(), TokenID: c.ID, Extra: c.Extra, Claims: all, Source: FromJWT,
	}
	if c.IssuedAt != nil {
		a.IssuedAt = c.IssuedAt.Time()
	}

	return a, nil
}
