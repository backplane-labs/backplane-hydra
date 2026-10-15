package overlay_test

import (
	"errors"
	"testing"
	"time"

	"github.com/backplane-labs/backplane/pkg/backplane/config"

	"github.com/backplane-labs/backplane-hydra/internal/overlay"
)

func defaults() overlay.Settings {
	return overlay.Settings{
		TTL: overlay.TTL{
			AccessToken: time.Hour, RefreshToken: 720 * time.Hour, IDToken: time.Hour, AuthCode: 10 * time.Minute,
			LoginConsentRequest: 30 * time.Minute, AuthenticationSession: 720 * time.Hour,
		},
		Tokens: overlay.Tokens{AccessToken: "opaque", Scope: "wildcard"},
	}
}

// Everything set and the token hook bound: Hydra's schema accepts it.
func TestRenderValid(t *testing.T) {
	t.Parallel()

	s := defaults()
	s.Issuer, s.LoginURL, s.ErrorURL = "https://auth.example.com/", "https://app.example.com/login", "https://app.example.com/error"
	s.Tokens.AccessToken = "jwt"
	s.Claims.AllowedTopLevel = []string{"tenant"}
	s.OIDC = overlay.OIDC{
		SubjectTypes: []string{"public", "pairwise"},
		PairwiseSalt: config.Secret("0123456789abcdef0123456789"),
	}

	doc, err := overlay.Render(s, overlay.Wiring{
		PublicURL: "https://auth.example.com/bp", CallbacksURL: "http://127.0.0.1:8091", Key: "k",
		Bound: func(string) bool { return true },
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := overlay.Validate(doc); err != nil {
		t.Fatal(err)
	}

	urls, _ := doc["urls"].(map[string]any)
	oauth2, _ := doc["oauth2"].(map[string]any)

	if urls["consent"] != "https://auth.example.com/bp/consent" || oauth2["token_hook"] == nil {
		t.Fatalf("consent or token hook missing: %v %v", urls, oauth2)
	}
}

func TestRenderOverrides(t *testing.T) {
	t.Parallel()

	s := defaults()
	s.Overrides = "urls:\n  consent: https://elsewhere/\n"

	if _, err := overlay.Render(s, overlay.Wiring{PublicURL: "http://x"}); !errors.Is(err, overlay.ErrConflict) {
		t.Fatalf("owned key overridden: %v", err)
	}

	s.Overrides = "oauth2:\n  hashers:\n    algorithm: bcrypt\n"

	doc, err := overlay.Render(s, overlay.Wiring{PublicURL: "http://x"})
	if err != nil {
		t.Fatal(err)
	}

	if err := overlay.Validate(doc); err != nil {
		t.Fatal(err)
	}
}
