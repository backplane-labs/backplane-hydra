// Package overlay renders the Hydra configuration file backplane-hydra
// owns: the settings an operator edits in the console, the consent and
// logout endpoints it serves, and the token hook while it is bound. Hydra
// loads it after the deployment's base file (`hydra serve all -c base.yml
// -c overlay.yml`) and reloads it when it changes.
package overlay

import (
	"time"

	"github.com/backplane-labs/backplane/pkg/backplane/config"
)

// Settings are the Hydra settings the overlay owns. Durations and flags
// are always written (their defaults are Hydra's); an empty string or
// list is left to the base file.
type Settings struct {
	// Issuer is the public issuer URL of tokens.
	Issuer string `json:"issuer,omitempty" schemapb:"description=Public URL tokens name as their issuer"`
	// LoginURL is the login UI (Kratos's login page when Kratos is the
	// login provider).
	LoginURL        string `json:"login_url,omitempty"        schemapb:"description=The login UI Hydra sends users to"`
	RegistrationURL string `json:"registration_url,omitempty"`
	ErrorURL        string `json:"error_url,omitempty"`
	// PostLogoutRedirect is where a logout without a client's URI lands.
	PostLogoutRedirect string `json:"post_logout_redirect,omitempty"`

	TTL     TTL     `json:"ttl,omitempty"`
	Tokens  Tokens  `json:"tokens,omitempty"`
	PKCE    PKCE    `json:"pkce,omitempty"`
	Claims  Claims  `json:"claims,omitempty"`
	Consent Consent `json:"consent,omitempty"`
	OIDC    OIDC    `json:"oidc,omitempty"`
	Refresh Refresh `json:"refresh,omitempty"`

	// Overrides is raw Hydra YAML merged last, for what Settings does not
	// model; it may not set a key Settings or the callbacks set.
	Overrides string `json:"overrides,omitempty" schemapb:"description=Raw Hydra YAML for keys these settings do not model"`
}

// TTL of Hydra's artifacts.
type TTL struct {
	AccessToken           time.Duration `json:"access_token,omitempty"           schemapb:"default=1h"`
	RefreshToken          time.Duration `json:"refresh_token,omitempty"          schemapb:"default=720h"`
	IDToken               time.Duration `json:"id_token,omitempty"               schemapb:"default=1h"`
	AuthCode              time.Duration `json:"auth_code,omitempty"              schemapb:"default=10m"`
	LoginConsentRequest   time.Duration `json:"login_consent_request,omitempty"  schemapb:"default=30m"`
	AuthenticationSession time.Duration `json:"authentication_session,omitempty" schemapb:"default=720h"`
}

// Tokens are the token strategies.
type Tokens struct {
	// AccessToken is opaque or jwt.
	AccessToken string `json:"access_token,omitempty" schemapb:"default={\"stringValue\":\"opaque\"}" validate:"oneof=opaque jwt"`
	// Scope is how requested scopes match the allowed ones.
	Scope string `json:"scope,omitempty" schemapb:"default={\"stringValue\":\"wildcard\"}" validate:"oneof=wildcard exact"`
}

// PKCE enforcement.
type PKCE struct {
	Enforced                 bool `json:"enforced,omitempty"                    schemapb:"default=false"`
	EnforcedForPublicClients bool `json:"enforced_for_public_clients,omitempty" schemapb:"default=true"`
}

// Claims of tokens.
type Claims struct {
	// MirrorTopLevel copies top-level access token claims under ext.
	MirrorTopLevel bool `json:"mirror_top_level,omitempty" schemapb:"default=true"`
	// AllowedTopLevel are the access token claims allowed at the top level.
	AllowedTopLevel []string `json:"allowed_top_level,omitempty"`
	// ClientCredentialsDefaultScope grants a client credentials request
	// every allowed scope when it asks for none.
	ClientCredentialsDefaultScope bool `json:"client_credentials_default_scope,omitempty" schemapb:"default=false"`
	ExposeInternalErrors          bool `json:"expose_internal_errors,omitempty"           schemapb:"default=false"`
}

// Consent served by backplane-hydra when the hook hydra.Consent is unbound.
type Consent struct {
	// UIURL takes consent that is not skipped; empty: such requests are
	// rejected with consent_required.
	UIURL string `json:"ui_url,omitempty" schemapb:"description=A consent UI for non-trusted clients (empty: refuse them)"`
	// RememberFor is how long an automatic consent is remembered; zero:
	// for ever.
	RememberFor time.Duration `json:"remember_for,omitempty" schemapb:"default=0s"`
}

// OIDC options.
type OIDC struct {
	DynamicClientRegistration bool          `json:"dynamic_client_registration,omitempty" schemapb:"default=false"`
	SubjectTypes              []string      `json:"subject_types,omitempty"               schemapb:"description=public, pairwise"`
	PairwiseSalt              config.Secret `json:"pairwise_salt,omitempty"`
}

// Refresh token rotation.
type Refresh struct {
	RotationGracePeriod time.Duration `json:"rotation_grace_period,omitempty"      schemapb:"default=0s"`
	RotationGraceReuse  int64         `json:"rotation_grace_reuse_count,omitempty" schemapb:"default=0"`
}
