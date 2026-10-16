// Package it tests backplane-hydra against a real Hydra (make it-up): the
// test is the login provider, backplane-hydra the consent provider, and a
// whole authorization code flow runs through them.
package it_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/backplane-labs/backplane/pkg/backplane/backplanetest"
	"github.com/backplane-labs/backplane/pkg/backplane/config"

	"github.com/backplane-labs/backplane-hydra/internal/activities"
	"github.com/backplane-labs/backplane-hydra/internal/apply"
	"github.com/backplane-labs/backplane-hydra/internal/flows"
	"github.com/backplane-labs/backplane-hydra/internal/ory"
	"github.com/backplane-labs/backplane-hydra/internal/overlay"
)

const (
	adminURL  = "http://127.0.0.1:34445"
	publicURL = "http://127.0.0.1:34444"
	key       = "it-key"
	subject   = "user-1"
	reload    = 2 * time.Second
)

var serial sync.Mutex

type env struct {
	h          *backplanetest.Harness
	flows      *flows.Flows
	activities *activities.Activities
	settings   config.Live[overlay.Settings]
	hydra      ory.Client
	callback   string // the client's redirect URI
}

func defaults() overlay.Settings {
	return overlay.Settings{
		TTL: overlay.TTL{
			AccessToken: time.Hour, RefreshToken: 720 * time.Hour, IDToken: time.Hour, AuthCode: 10 * time.Minute,
			LoginConsentRequest: 30 * time.Minute, AuthenticationSession: 720 * time.Hour,
		},
		Tokens: overlay.Tokens{AccessToken: "opaque", Scope: "wildcard"},
		PKCE:   overlay.PKCE{EnforcedForPublicClients: true},
		Claims: overlay.Claims{MirrorTopLevel: true},
	}
}

func listen(t *testing.T, h http.Handler) string {
	t.Helper()

	lis, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	srv := &http.Server{Handler: h, ReadHeaderTimeout: time.Second}

	go func() { _ = srv.Serve(lis) }()

	t.Cleanup(func() { _ = srv.Close() })

	return "http://" + lis.Addr().String()
}

func start(t *testing.T, bind func(*backplanetest.Harness, *flows.Flows)) env {
	t.Helper()

	return startWith(t, nil, bind)
}

// startWith is start with the settings changed by edit.
func startWith(t *testing.T, edit func(*overlay.Settings), bind func(*backplanetest.Harness, *flows.Flows)) env {
	t.Helper()

	path := os.Getenv("HYDRA_IT_OVERLAY")
	if path == "" {
		t.Skip("HYDRA_IT_OVERLAY not set: make it-up it")
	}

	serial.Lock()
	t.Cleanup(serial.Unlock)

	client, err := ory.New(ory.Options{Admin: adminURL, Public: publicURL})
	if err != nil {
		t.Fatal(err)
	}

	// The login provider: every login is subject's.
	login := listen(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		to, err := client.AcceptLoginRequest(r.Context(), r.URL.Query().Get("login_challenge"),
			ory.AcceptLogin{Subject: subject, Remember: true})
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)

			return
		}

		http.Redirect(w, r, to, http.StatusFound)
	}))

	settings := defaults()
	settings.LoginURL = login + "/login"

	if edit != nil {
		edit(&settings)
	}

	h := backplanetest.New(t, backplanetest.Name("hydra"))
	e := env{h: h, hydra: client, settings: config.LiveOf(settings), callback: "http://127.0.0.1:1/cb"}
	e.flows = flows.New(h.Root(), client, key, e.settings)
	e.activities = activities.New(h.Root(), client)

	public := listen(t, e.flows.Public())
	callbacks := listen(t, e.flows.Callbacks())

	apply.New(
		h.Root(),
		path,
		0o644,
		e.settings,
		config.LiveOf(config.Secret("")),
		e.flows,
		overlay.Wiring{PublicURL: public, CallbacksURL: callbacks, Key: key},
	)

	if bind != nil {
		bind(h, e.flows)
	}

	h.Start()

	host := strings.TrimPrefix(public, "http://")

	waitFor(t, "the overlay names this test's endpoints", func() bool {
		raw, err := os.ReadFile(path)

		return err == nil && bytes.Contains(raw, []byte(host))
	})
	time.Sleep(reload)

	return e
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()

	deadline := time.Now().Add(20 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("not reached: %s", what)
		}

		time.Sleep(200 * time.Millisecond)
	}
}

// newClient creates an OAuth 2.0 client through the activity.
func (e env) newClient(t *testing.T, skipConsent bool) ory.OAuth2Client {
	t.Helper()

	body, _ := json.Marshal(map[string]any{ //nolint:errchkjson // plain values
		"client_name": "it", "grant_types": []string{"authorization_code", "refresh_token"}, "response_types": []string{"code"},
		"redirect_uris": []string{
			e.callback,
		}, "scope": "openid offline_access email", "token_endpoint_auth_method": "client_secret_post",
		"skip_consent": skipConsent,
	})

	c, err := backplanetest.Activity[activities.ClientIn, ory.OAuth2Client](t.Context(), e.h, "CreateClient",
		activities.ClientIn{Client: body})
	if err != nil || c.ClientSecret == "" {
		t.Fatalf("create client: %+v %v", c, err)
	}

	return c
}

// browser follows redirects until the client's redirect URI.
type browser struct{ http *http.Client }

var errLanded = errors.New("landed on the redirect URI")

func newBrowser(t *testing.T, callback string) browser {
	t.Helper()

	jar, _ := cookiejar.New(nil)

	return browser{
		http: &http.Client{
			Jar:     jar,
			Timeout: 20 * time.Second,
			CheckRedirect: func(r *http.Request, _ []*http.Request) error {
				if strings.HasPrefix(r.URL.String(), callback) {
					return errLanded
				}

				return nil
			},
		},
	}
}

// authorize runs the flow: the query the redirect URI receives.
func (b browser) authorize(t *testing.T, c ory.OAuth2Client, callback string) url.Values {
	t.Helper()

	q := url.Values{
		"client_id": {c.ClientID}, "response_type": {"code"}, "scope": {"openid offline_access email"},
		"redirect_uri": {callback}, "state": {"state-0123456789"}, "nonce": {"nonce-0123456789"},
	}

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, publicURL+"/oauth2/auth?"+q.Encode(), http.NoBody)

	res, err := b.http.Do(req)
	if res != nil {
		_ = res.Body.Close()
	}

	var uerr *url.Error
	if !errors.As(err, &uerr) || !errors.Is(err, errLanded) {
		t.Fatalf("the flow did not reach the redirect URI: %v (status %v)", err, res)
	}

	u, _ := url.Parse(uerr.URL)

	return u.Query()
}

// exchange trades a code for tokens.
func exchange(t *testing.T, c ory.OAuth2Client, code, callback string) map[string]any {
	t.Helper()

	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {callback},
		"client_id": {c.ClientID}, "client_secret": {c.ClientSecret},
	}

	req, _ := http.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		publicURL+"/oauth2/token",
		strings.NewReader(form.Encode()),
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	var out map[string]any

	_ = json.NewDecoder(res.Body).Decode(&out)

	if res.StatusCode != http.StatusOK {
		t.Fatalf("token: %d %v", res.StatusCode, out)
	}

	return out
}

func claims(t *testing.T, jwt string) map[string]any {
	t.Helper()

	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", jwt)
	}

	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}

	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}

	return out
}

// Consent bound: its claims land in the ID token, the grant is an event.
func TestConsentClaims(t *testing.T) {
	t.Parallel()

	e := start(t, func(h *backplanetest.Harness, f *flows.Flows) {
		backplanetest.Answer(h, f.ConsentRef(), func(_ context.Context, in flows.ConsentIn) (flows.ConsentOut, error) {
			return flows.ConsentOut{
				Decision: flows.DecisionAccept, IDTokenClaims: json.RawMessage(fmt.Sprintf(`{"email":%q}`, in.Subject+"@example.com")),
			}, nil
		})
	})

	c := e.newClient(t, false)
	q := newBrowser(t, e.callback).authorize(t, c, e.callback)

	if q.Get("code") == "" {
		t.Fatalf("no code: %v", q)
	}

	tokens := exchange(t, c, q.Get("code"), e.callback)

	id := claims(t, fmt.Sprint(tokens["id_token"]))
	if id["sub"] != subject || id["email"] != subject+"@example.com" {
		t.Fatalf("id token claims: %v", id)
	}

	granted := backplanetest.Events(e.h, e.flows.Granted())
	if len(granted) != 1 || granted[0].ClientID != c.ClientID || granted[0].Automatic {
		t.Fatalf("granted: %+v", granted)
	}
}

// Unbound, an untrusted client without a consent UI is refused; a
// trusted one is let through.
func TestConsentDefault(t *testing.T) {
	t.Parallel()

	e := start(t, nil)

	untrusted := e.newClient(t, false)
	if q := newBrowser(t, e.callback).authorize(t, untrusted, e.callback); q.Get("error") != "consent_required" {
		t.Fatalf("untrusted: %v", q)
	}

	trusted := e.newClient(t, true)
	if q := newBrowser(t, e.callback).authorize(t, trusted, e.callback); q.Get("code") == "" {
		t.Fatalf("trusted: %v", q)
	}
}

// TokenClaims sets the access token's claims; introspection shows them.
func TestTokenClaims(t *testing.T) {
	t.Parallel()

	e := start(t, func(h *backplanetest.Harness, f *flows.Flows) {
		backplanetest.Answer(h, f.TokenRef(), func(_ context.Context, in flows.TokenIn) (flows.TokenOut, error) {
			return flows.TokenOut{
				AccessTokenClaims: json.RawMessage(fmt.Sprintf(`{"tenant":"acme","client":%q}`, in.ClientID)),
			}, nil
		})
	})

	c := e.newClient(t, true)
	q := newBrowser(t, e.callback).authorize(t, c, e.callback)
	tokens := exchange(t, c, q.Get("code"), e.callback)

	info, err := e.hydra.Introspect(t.Context(), fmt.Sprint(tokens["access_token"]), "")
	if err != nil || !info.Active || !strings.Contains(string(info.Ext), `"tenant":"acme"`) {
		t.Fatalf("introspection: %+v %v", info, err)
	}
}

// A logout through Hydra lands on backplane-hydra and is an event.
func TestLogout(t *testing.T) {
	t.Parallel()

	e := start(t, nil)

	c := e.newClient(t, true)
	b := newBrowser(t, e.callback)
	b.authorize(t, c, e.callback)

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, publicURL+"/oauth2/sessions/logout", http.NoBody)

	res, err := b.http.Do(req)
	if err != nil {
		t.Fatalf("logout: %v", err)
	}

	_ = res.Body.Close()

	waitFor(t, "LoggedOut", func() bool {
		ev := backplanetest.Events(e.h, e.flows.LoggedOutRef())

		return len(ev) == 1 && ev[0].Subject == subject
	})
}

// Clients through the activities; deleting publishes ClientDeleted.
func TestClients(t *testing.T) {
	t.Parallel()

	e := start(t, nil)
	ctx := t.Context()

	c := e.newClient(t, false)

	got, err := backplanetest.Activity[activities.ClientIDIn, ory.OAuth2Client](ctx, e.h, "GetClient",
		activities.ClientIDIn{ClientID: c.ClientID})
	if err != nil || got.ClientID != c.ClientID || got.ClientSecret != "" {
		t.Fatalf("get: %+v %v", got, err)
	}

	if _, err := backplanetest.Activity[activities.ClientIDIn, activities.Empty](ctx, e.h, "DeleteClient",
		activities.ClientIDIn{ClientID: c.ClientID}); err != nil {
		t.Fatal(err)
	}

	if _, err := e.hydra.GetClient(ctx, c.ClientID); !ory.IsNotFound(err) {
		t.Fatalf("still there: %v", err)
	}

	deleted := backplanetest.Events(e.h, e.activities.ClientEvents("ClientDeleted"))
	if len(deleted) != 1 || deleted[0].ClientID != c.ClientID {
		t.Fatalf("deleted: %+v", deleted)
	}
}

// Saving a client keeps every field Hydra has, not only those this
// service models (the console edits Hydra's own JSON).
func TestClientRoundTrip(t *testing.T) {
	t.Parallel()

	e := start(t, nil)
	ctx := t.Context()
	c := e.newClient(t, false)

	if _, err := backplanetest.Activity[activities.LifespansIn, ory.OAuth2Client](ctx, e.h, "SetClientLifespans", activities.LifespansIn{
		ClientID: c.ClientID, Lifespans: map[string]string{"authorization_code_grant_access_token_lifespan": "15m0s"},
	}); err != nil {
		t.Fatal(err)
	}

	got, err := e.hydra.GetClient(ctx, c.ClientID)
	if err != nil {
		t.Fatal(err)
	}

	var raw map[string]any
	if err := json.Unmarshal(got.WithoutSecret(), &raw); err != nil {
		t.Fatal(err)
	}

	raw["client_name"] = "renamed"
	body, _ := json.Marshal(raw) //nolint:errchkjson // decoded JSON

	if _, err := backplanetest.Activity[activities.ClientIn, ory.OAuth2Client](ctx, e.h, "UpdateClient",
		activities.ClientIn{ClientID: c.ClientID, Client: body}); err != nil {
		t.Fatal(err)
	}

	after, err := e.hydra.GetClient(ctx, c.ClientID)
	if err != nil || after.ClientName != "renamed" ||
		!strings.Contains(string(after.Raw), `"authorization_code_grant_access_token_lifespan":"15m0s"`) {
		t.Fatalf("round trip lost fields: %s %v", after.Raw, err)
	}
}

// Keys: a rotation adds a signing key; a set of one's own can be deleted.
func TestKeys(t *testing.T) {
	t.Parallel()

	e := start(t, nil)
	ctx := t.Context()
	set := fmt.Sprintf("it.keys.%d", time.Now().UnixNano())

	first, err := backplanetest.Activity[activities.RotateKeyIn, activities.KeysOut](
		ctx,
		e.h,
		"RotateKey",
		activities.RotateKeyIn{Set: set, Alg: "ES256"},
	)
	if err != nil || len(first.Keys) != 1 || first.Keys[0].Alg != "ES256" {
		t.Fatalf("rotate: %+v %v", first, err)
	}

	if _, err := backplanetest.Activity[activities.RotateKeyIn, activities.KeysOut](ctx, e.h, "RotateKey", activities.RotateKeyIn{Set: set, Alg: "ES256"}); err != nil {
		t.Fatal(err)
	}

	keys, err := backplanetest.Activity[activities.KeySetIn, activities.KeysOut](
		ctx,
		e.h,
		"GetKeySet",
		activities.KeySetIn{Set: set},
	)
	if err != nil || len(keys.Keys) != 2 {
		t.Fatalf("set: %+v %v", keys, err)
	}

	if _, err := backplanetest.Activity[activities.KeySetIn, activities.Empty](ctx, e.h, "DeleteKeySet", activities.KeySetIn{Set: set}); err != nil {
		t.Fatal(err)
	}

	if _, err := e.hydra.GetKeySet(ctx, set); !ory.IsNotFound(err) {
		t.Fatalf("set still there: %v", err)
	}
}
