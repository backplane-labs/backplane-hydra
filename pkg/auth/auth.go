// Package auth tells a service who made a request from an OAuth2 access
// token Ory Hydra issued. Two ways, one result (Auth):
//
//   - JWT access tokens (strategies.access_token: jwt): verified locally
//     against Hydra's public keys, without a call. A revoked token stays
//     valid until it expires (ttl.access_token): the model's promise.
//   - Introspection: any access token, opaque or JWT, asked of Hydra's
//     admin API on every call. Nothing is cached: a revoked token fails the
//     next call, at the price of a call to the admin API.
//
// Neither caches tokens, so every replica of a service answers alike. The
// only cache is of the public keys, fetched on first use, on an unknown kid
// and in the background when old.
package auth

import (
	"errors"
	"slices"
	"time"
)

// Errors. Every error of the package wraps one of them.
var (
	// ErrNoCredential: the request carries no bearer token.
	ErrNoCredential = errors.New("auth: no credential")
	// ErrInvalid: the token is malformed, badly signed, not an access token
	// or its claims fail.
	ErrInvalid = errors.New("auth: invalid token")
	// ErrExpired: the token's exp has passed (or its nbf has not come).
	ErrExpired = errors.New("auth: token expired")
	// ErrUnknownKey: the token is signed with a key Hydra does not publish.
	ErrUnknownKey = errors.New("auth: token signed with an unknown key")
	// ErrInactive: Hydra says the token is not active (revoked, expired or
	// never issued).
	ErrInactive = errors.New("auth: token not active")
	// ErrUnavailable: Hydra or its keys could not be reached.
	ErrUnavailable = errors.New("auth: unavailable")
)

// Source of an Auth.
const (
	// FromJWT: verified locally from a JWT access token.
	FromJWT = "jwt"
	// FromIntrospection: Hydra answered for the token.
	FromIntrospection = "introspection"
)

// Auth is who a token speaks for and what it may do.
type Auth struct {
	// Subject is the user the token was issued for, or the client itself
	// for client credentials.
	Subject string
	// ClientID is the OAuth2 client the token was issued to.
	ClientID string
	// Scopes granted to the token.
	Scopes []string
	// Audience the token is meant for.
	Audience []string
	// ExpiresAt and IssuedAt of the token.
	ExpiresAt time.Time
	IssuedAt  time.Time
	// TokenID is the token's jti (JWT) — empty from introspection.
	TokenID string
	// Extra are the claims the consent or the token hook added (Hydra's
	// "ext"); with mirrored top-level claims they are in Claims too.
	Extra map[string]any
	// Claims are all of a JWT's claims (FromJWT).
	Claims map[string]any
	// Source is FromJWT or FromIntrospection.
	Source string
}

// IsZero reports whether a is the zero Auth (nobody).
func (a Auth) IsZero() bool { return a.ClientID == "" && a.Subject == "" }

// HasScope reports whether the token was granted scope.
func (a Auth) HasScope(scope string) bool { return slices.Contains(a.Scopes, scope) }

// HasScopes reports whether the token was granted every one of scopes.
func (a Auth) HasScopes(scopes ...string) bool {
	for _, s := range scopes {
		if !a.HasScope(s) {
			return false
		}
	}

	return true
}

// IsClient reports whether the token speaks for its client alone (client
// credentials), not a user.
func (a Auth) IsClient() bool { return a.Subject == "" || a.Subject == a.ClientID }

// Intended reports whether audience is among the token's.
func (a Auth) Intended(audience string) bool { return slices.Contains(a.Audience, audience) }
