package overlay

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Hooks backplane-hydra declares.
const (
	ConsentHook     = "Consent"
	TokenClaimsHook = "TokenClaims"
)

// Wiring is how Hydra and browsers reach backplane-hydra and what is bound.
type Wiring struct {
	// PublicURL is backplane-hydra's public API as browsers reach it: the
	// consent and logout endpoints.
	PublicURL string
	// CallbacksURL is the callbacks listener as Hydra reaches it.
	CallbacksURL string
	// Key authenticates Hydra's calls (header KeyHeader).
	Key string
	// Bound reports whether a hook (short name) is bound.
	Bound func(hook string) bool
}

// KeyHeader carries Wiring.Key on the token hook.
const KeyHeader = "X-Backplane-Hydra-Key"

// Errors of Render.
var (
	ErrOverrides = errors.New("overrides")
	ErrConflict  = errors.New("is set by the settings or backplane-hydra; change it there")
)

// Render is the overlay document for s and w.
func Render(s Settings, w Wiring) (map[string]any, error) {
	r := renderer{doc: map[string]any{}}

	public := strings.TrimRight(w.PublicURL, "/")
	r.set("urls.consent", public+"/consent")
	r.set("urls.logout", public+"/logout")
	r.setStr("urls.self.issuer", s.Issuer)
	r.setStr("urls.login", s.LoginURL)
	r.setStr("urls.registration", s.RegistrationURL)
	r.setStr("urls.error", s.ErrorURL)
	r.setStr("urls.post_logout_redirect", s.PostLogoutRedirect)

	r.set("ttl.access_token", s.TTL.AccessToken.String())
	r.set("ttl.refresh_token", s.TTL.RefreshToken.String())
	r.set("ttl.id_token", s.TTL.IDToken.String())
	r.set("ttl.auth_code", s.TTL.AuthCode.String())
	r.set("ttl.login_consent_request", s.TTL.LoginConsentRequest.String())
	r.set("ttl.authentication_session", s.TTL.AuthenticationSession.String())

	r.set("strategies.access_token", s.Tokens.AccessToken)
	r.set("strategies.scope", s.Tokens.Scope)

	r.set("oauth2.pkce.enforced", s.PKCE.Enforced)
	r.set("oauth2.pkce.enforced_for_public_clients", s.PKCE.EnforcedForPublicClients)
	r.set("oauth2.mirror_top_level_claims", s.Claims.MirrorTopLevel)
	r.set("oauth2.client_credentials.default_grant_allowed_scope", s.Claims.ClientCredentialsDefaultScope)
	r.set("oauth2.expose_internal_errors", s.Claims.ExposeInternalErrors)

	if len(s.Claims.AllowedTopLevel) > 0 {
		r.set("oauth2.allowed_top_level_claims", s.Claims.AllowedTopLevel)
	}

	r.set("oauth2.grant.refresh_token.rotation_grace_period", s.Refresh.RotationGracePeriod.String())
	r.set("oauth2.grant.refresh_token.rotation_grace_reuse_count", s.Refresh.RotationGraceReuse)

	r.set("oidc.dynamic_client_registration.enabled", s.OIDC.DynamicClientRegistration)

	if len(s.OIDC.SubjectTypes) > 0 {
		r.set("oidc.subject_identifiers.supported_types", s.OIDC.SubjectTypes)
	}

	if salt := s.OIDC.PairwiseSalt.Reveal(); salt != "" {
		r.set("oidc.subject_identifiers.pairwise.salt", salt)
	}

	if w.Bound != nil && w.Bound(TokenClaimsHook) {
		r.set("oauth2.token_hook", map[string]any{
			"url": strings.TrimRight(w.CallbacksURL, "/") + "/token-hook",
			"auth": map[string]any{"type": "api_key", "config": map[string]any{
				"in": "header", "name": KeyHeader, "value": w.Key,
			}},
		})
	}

	if err := r.overrides(s.Overrides); err != nil {
		return nil, err
	}

	return r.doc, nil
}

type renderer struct{ doc map[string]any }

func (r renderer) set(path string, v any) { setPath(r.doc, strings.Split(path, "."), v) }

func (r renderer) setStr(path, v string) {
	if v != "" {
		r.set(path, v)
	}
}

func setPath(m map[string]any, keys []string, v any) {
	for _, k := range keys[:len(keys)-1] {
		next, ok := m[k].(map[string]any)
		if !ok {
			next = map[string]any{}
			m[k] = next
		}

		m = next
	}

	m[keys[len(keys)-1]] = v
}

func (r renderer) overrides(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}

	var extra map[string]any
	if err := yaml.Unmarshal([]byte(raw), &extra); err != nil {
		return fmt.Errorf("%w: %w", ErrOverrides, err)
	}

	return merge(r.doc, extra, "")
}

func merge(dst, src map[string]any, prefix string) error {
	for _, k := range slices.Sorted(maps.Keys(src)) {
		path := k
		if prefix != "" {
			path = prefix + "." + k
		}

		sv := src[k]

		dv, exists := dst[k]
		if !exists {
			dst[k] = sv

			continue
		}

		dstMap, dIsMap := dv.(map[string]any)
		srcMap, sIsMap := sv.(map[string]any)

		if !dIsMap || !sIsMap {
			return fmt.Errorf("%w: %s %w", ErrOverrides, path, ErrConflict)
		}

		if err := merge(dstMap, srcMap, path); err != nil {
			return err
		}
	}

	return nil
}
