package auth_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/backplane-labs/backplane-hydra/pkg/auth"
)

// hydra answers introspection: "good" is an active access token until
// revoked, "refresh" an active refresh token; calls counts the calls.
func hydra(t *testing.T, calls *atomic.Int32, revoked *atomic.Bool) string {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)

		if r.URL.Path != "/admin/oauth2/introspect" || r.Header.Get("X-Proxy") != "secret" || r.ParseForm() != nil {
			http.Error(w, "bad request", http.StatusBadRequest)

			return
		}

		switch token := r.PostForm.Get("token"); {
		case token == "refresh":
			_, _ = w.Write([]byte(`{"active":true,"token_use":"refresh_token","client_id":"app"}`))
		case token != "good" || revoked.Load() || (r.PostForm.Get("scope") != "" && r.PostForm.Get("scope") != "orders.read"):
			_, _ = w.Write([]byte(`{"active":false}`))
		default:
			_, _ = w.Write([]byte(`{"active":true,"token_use":"access_token","sub":"user-1","client_id":"app",
				"scope":"openid orders.read","aud":["api"],"exp":4102444800,"iat":1760000000,"ext":{"tenant":"acme"}}`))
		}
	}))
	t.Cleanup(srv.Close)

	return srv.URL
}

func introspection(t *testing.T, url string) auth.Introspection {
	t.Helper()

	i, err := auth.NewIntrospection(url, map[string]string{"X-Proxy": "secret"}, nil)
	if err != nil {
		t.Fatal(err)
	}

	return i
}

func TestIntrospectionAsksEveryTime(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32

	var revoked atomic.Bool

	in := introspection(t, hydra(t, &calls, &revoked))
	ctx := context.Background()

	a, err := in.Verify(ctx, "good")
	if err != nil {
		t.Fatal(err)
	}

	if a.Subject != "user-1" || a.ClientID != "app" || !a.HasScopes("openid", "orders.read") || a.Extra["tenant"] != "acme" ||
		a.Source != auth.FromIntrospection || a.ExpiresAt.Year() != 2100 {
		t.Fatalf("auth = %+v", a)
	}

	if _, err := in.Verify(ctx, "good", "orders.read"); err != nil {
		t.Fatalf("with a granted scope: %v", err)
	}

	if _, err := in.Verify(ctx, "good", "orders.write"); !errors.Is(err, auth.ErrInactive) {
		t.Fatalf("with a scope not granted: %v", err)
	}

	// No cache: the revocation shows on the very next call.
	revoked.Store(true)

	if _, err := in.Verify(ctx, "good"); !errors.Is(err, auth.ErrInactive) {
		t.Fatalf("after revoke: %v", err)
	}

	if n := calls.Load(); n != 4 {
		t.Fatalf("calls = %d, want 4", n)
	}

	if _, err := in.Verify(ctx, "refresh"); !errors.Is(err, auth.ErrInvalid) {
		t.Fatalf("refresh token: %v", err)
	}
}

func TestMiddleware(t *testing.T) {
	t.Parallel()

	issuer := newIssuer(t)
	issuer.add("k1")

	now := time.Now()
	tokens := verifier(t, issuer, &now)
	jwt := issuer.sign("k1", session(now, nil))

	who := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, ok := auth.FromContext(r.Context())
		if !ok {
			_, _ = w.Write([]byte("anonymous"))

			return
		}

		_, _ = w.Write([]byte(got.Source + ":" + got.Subject))
	})

	cases := []struct {
		name       string
		optional   bool
		noTokens   bool
		header     string
		code       int
		body       string
		introspect bool
	}{
		{"jwt", false, false, "Bearer " + jwt, 200, "jwt:user-1", false},
		{"jwt by introspection", false, true, "Bearer " + jwt, 401, "", true},
		{"opaque", false, false, "Bearer good", 200, "introspection:user-1", true},
		{"inactive", false, false, "Bearer nope", 401, "", true},
		{"anonymous required", false, false, "", 401, "", false},
		{"anonymous optional", true, false, "", 200, "anonymous", false},
		{"bad jwt optional", true, false, "Bearer a.b.c", 401, "", false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			var calls atomic.Int32

			var revoked atomic.Bool

			a := auth.Authenticator{Tokens: tokens, Introspection: introspection(t, hydra(t, &calls, &revoked))}
			if c.noTokens {
				a.Tokens = nil
			}

			h := a.Required(who)
			if c.optional {
				h = a.Optional(who)
			}

			req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
			if c.header != "" {
				req.Header.Set("Authorization", c.header)
			}

			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != c.code || (c.body != "" && rec.Body.String() != c.body) {
				t.Fatalf("got %d %q, want %d %q", rec.Code, rec.Body.String(), c.code, c.body)
			}

			if asked := calls.Load() > 0; asked != c.introspect {
				t.Fatalf("introspected %v, want %v", asked, c.introspect)
			}
		})
	}
}
