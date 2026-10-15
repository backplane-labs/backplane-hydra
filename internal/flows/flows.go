// Package flows serves what Hydra hands over: the consent and logout
// steps of a browser's OAuth 2.0 flow (hook Consent, event LoggedOut) and
// the token hook (hook TokenClaims).
package flows

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"sync"
	"time"

	"github.com/backplane-labs/backplane/pkg/backplane/config"
	"github.com/backplane-labs/backplane/pkg/backplane/deps"
	"github.com/backplane-labs/backplane/pkg/backplane/event"
	"github.com/backplane-labs/backplane/pkg/backplane/hook"

	"github.com/gopherex/xlog"

	"github.com/backplane-labs/backplane-hydra/internal/ory"
	"github.com/backplane-labs/backplane-hydra/internal/overlay"
)

const (
	consentTimeout = 5 * time.Second
	tokenTimeout   = 3 * time.Second
	maxCallback    = 4 << 20
)

// outcomeFailed: a point could not complete.
const outcomeFailed = "failed"

// Decisions of a consent.
const (
	DecisionAccept = "accept"
	DecisionReject = "reject"
	DecisionUI     = "ui"
)

// ConsentIn is a consent Hydra asks for.
type ConsentIn struct {
	Subject    string          `json:"subject"`
	ClientID   string          `json:"client_id"`
	ClientName string          `json:"client_name,omitempty"`
	Metadata   json.RawMessage `json:"client_metadata,omitempty"`
	// SkipConsent: the client is trusted (first-party).
	SkipConsent bool `json:"skip_consent"`
	// Remembered: the subject consented to this client before.
	Remembered        bool            `json:"remembered"`
	RequestedScope    []string        `json:"requested_scope"`
	RequestedAudience []string        `json:"requested_audience,omitempty"`
	ACR               string          `json:"acr,omitempty"`
	AMR               []string        `json:"amr,omitempty"`
	LoginContext      json.RawMessage `json:"login_context,omitempty"`
	OIDCContext       json.RawMessage `json:"oidc_context,omitempty"`
}

// ConsentOut decides it and adds claims.
type ConsentOut struct {
	// Decision is accept, reject or ui; empty: backplane-hydra's default
	// (accept a trusted or remembered client, else the consent UI, else
	// reject).
	Decision string `json:"decision,omitempty" validate:"omitempty,oneof=accept reject ui"`
	// GrantScope defaults to the requested scope.
	GrantScope        []string        `json:"grant_scope,omitempty"`
	GrantAudience     []string        `json:"grant_audience,omitempty"`
	IDTokenClaims     json.RawMessage `json:"id_token_claims,omitempty"`
	AccessTokenClaims json.RawMessage `json:"access_token_claims,omitempty"`
	// Remember the consent; RememberFor seconds (zero: for ever).
	Remember    *bool `json:"remember,omitempty"`
	RememberFor int64 `json:"remember_for,omitempty"`
	// Error and ErrorDescription of a rejection.
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// TokenIn is a token Hydra is about to issue.
type TokenIn struct {
	ClientID        string              `json:"client_id"`
	Subject         string              `json:"subject,omitempty"`
	GrantTypes      []string            `json:"grant_types"`
	RequestedScopes []string            `json:"requested_scopes,omitempty"`
	GrantedScopes   []string            `json:"granted_scopes,omitempty"`
	GrantedAudience []string            `json:"granted_audience,omitempty"`
	Payload         map[string][]string `json:"payload,omitempty"          schemapb:"secret=true"`
	// Session is Hydra's session of the token: its current claims.
	Session json.RawMessage `json:"session,omitempty"`
}

// TokenOut replaces the token's extra claims; empty: unchanged.
type TokenOut struct {
	AccessTokenClaims json.RawMessage `json:"access_token_claims,omitempty"`
	IDTokenClaims     json.RawMessage `json:"id_token_claims,omitempty"`
	// Deny refuses the token (access_denied).
	Deny bool `json:"deny,omitempty"`
}

// ConsentGranted is a consent given.
type ConsentGranted struct {
	Subject  string   `json:"subject"`
	ClientID string   `json:"client_id"`
	Scope    []string `json:"scope"`
	// Automatic: granted without asking (trusted or remembered).
	Automatic bool `json:"automatic"`
}

// LoggedOut is a logout through Hydra.
type LoggedOut struct {
	Subject  string `json:"subject"`
	SID      string `json:"sid,omitempty"`
	ClientID string `json:"client_id,omitempty"`
}

// Flows declares the hooks and events and serves the browser endpoints
// and Hydra's token hook.
type Flows struct {
	deps.Component

	hydra    ory.Client
	key      string
	settings config.Live[overlay.Settings]

	consent   hook.Ref[ConsentIn, ConsentOut]
	token     hook.Ref[TokenIn, TokenOut]
	granted   event.Ref[ConsentGranted]
	loggedOut event.Ref[LoggedOut]

	mu    sync.Mutex
	stats map[string]*Stat
}

// Stat is how one point has been doing since start.
type Stat struct {
	Point       string
	Calls       uint64
	Failures    uint64
	LastAt      time.Time
	LastOutcome string
	LastError   string
	LastLatency time.Duration
}

// New declares the hooks and events under parent.
func New(parent deps.Scope, hydra ory.Client, key string, settings config.Live[overlay.Settings]) *Flows {
	f := &Flows{
		Component: deps.NewComponent(
			parent,
			"flows",
		), hydra: hydra, key: key, settings: settings, stats: map[string]*Stat{},
	}
	f.consent = hook.Declare[ConsentIn, ConsentOut](f, overlay.ConsentHook, hook.DefaultTimeout(consentTimeout),
		hook.Describe("Decide a consent and add the claims of its tokens (e.g. from kratos.GetIdentity)"))
	f.token = hook.Declare[TokenIn, TokenOut](f, overlay.TokenClaimsHook, hook.DefaultTimeout(tokenTimeout),
		hook.Describe("Set the extra claims of every token Hydra issues, or refuse it"))
	f.granted = event.Declare[ConsentGranted](f, "ConsentGranted", event.Describe("a subject consented to a client"))
	f.loggedOut = event.Declare[LoggedOut](f, "LoggedOut", event.Describe("a subject logged out through Hydra"))

	return f
}

// Bound reports whether a hook (short name) is bound.
func (f *Flows) Bound(name string) bool {
	switch name {
	case overlay.ConsentHook:
		return f.consent.Bound()
	case overlay.TokenClaimsHook:
		return f.token.Bound()
	default:
		return false
	}
}

// Hooks are the declared hook names.
func (f *Flows) Hooks() []string { return []string{overlay.ConsentHook, overlay.TokenClaimsHook} }

// BindingChanges signals when the bound hooks change.
func (f *Flows) BindingChanges(ctx context.Context) <-chan struct{} {
	return f.consent.BindingChanges(ctx)
}

// ConsentRef, TokenRef, Granted and LoggedOutRef are the declared refs.
func (f *Flows) ConsentRef() hook.Ref[ConsentIn, ConsentOut] { return f.consent }

// TokenRef is the token hook.
func (f *Flows) TokenRef() hook.Ref[TokenIn, TokenOut] { return f.token }

// Granted is ConsentGranted.
func (f *Flows) Granted() event.Ref[ConsentGranted] { return f.granted }

// LoggedOutRef is LoggedOut.
func (f *Flows) LoggedOutRef() event.Ref[LoggedOut] { return f.loggedOut }

// Stats of every point since start.
func (f *Flows) Stats() []Stat {
	f.mu.Lock()
	defer f.mu.Unlock()

	out := make([]Stat, 0, len(f.stats))
	for _, s := range f.stats {
		out = append(out, *s)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Point < out[j].Point })

	return out
}

func (f *Flows) record(point string, start time.Time, outcome string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	s := f.stats[point]
	if s == nil {
		s = &Stat{Point: point}
		f.stats[point] = s
	}

	s.Calls++
	s.LastAt, s.LastOutcome, s.LastLatency, s.LastError = time.Now(), outcome, time.Since(start), ""

	if err != nil {
		s.Failures++
		s.LastError = err.Error()
	}
}

// Public serves the browser endpoints Hydra redirects to: /consent and
// /logout.
func (f *Flows) Public() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /consent", f.consentStep)
	mux.HandleFunc("GET /logout", f.logoutStep)

	return mux
}

// Callbacks serves Hydra's token hook.
func (f *Flows) Callbacks() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /token-hook", f.tokenHook)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get(overlay.KeyHeader)), []byte(f.key)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)

			return
		}

		mux.ServeHTTP(w, r)
	})
}

// ErrNoChallenge: the browser came without Hydra's challenge.
var ErrNoChallenge = errors.New("the request carries no challenge from Hydra")

// failPage answers a browser step that cannot continue: Hydra's flow is
// lost, there is nowhere to redirect.
func failPage(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, msg+"\n")
}

func (f *Flows) consentStep(w http.ResponseWriter, r *http.Request) {
	start, ctx := time.Now(), r.Context()
	challenge := r.URL.Query().Get("consent_challenge")

	if challenge == "" {
		f.record("consent", start, "bad_request", ErrNoChallenge)
		failPage(w, http.StatusBadRequest, ErrNoChallenge.Error())

		return
	}

	req, err := f.hydra.GetConsentRequest(ctx, challenge)
	if err != nil {
		f.record("consent", start, outcomeFailed, err)
		failPage(w, http.StatusBadGateway, "The consent request could not be read; start over.")

		return
	}

	in := ConsentIn{
		Subject: req.Subject, ClientID: req.Client.ClientID, ClientName: req.Client.ClientName, Metadata: req.Client.Metadata,
		SkipConsent: req.Client.SkipConsent, Remembered: req.Skip, RequestedScope: req.RequestedScope,
		RequestedAudience: req.RequestedAccessTokenAudience, ACR: req.ACR, AMR: req.AMR, LoginContext: req.Context,
		OIDCContext: req.OIDCContext,
	}

	var out ConsentOut

	if f.consent.Bound() {
		out, err = f.consent.Call(ctx, in, hook.Key("hydra-consent-"+challenge))
		if errors.Is(err, hook.ErrNoBinding) {
			out, err = ConsentOut{}, nil
		}
	}

	to, outcome, err := f.decide(ctx, challenge, in, out, err)
	f.record("consent", start, outcome, err)

	if to == "" {
		failPage(w, http.StatusBadGateway, "The consent could not be completed; start over.")

		return
	}

	http.Redirect(w, r, to, http.StatusFound)
}

// decide completes the consent: the redirect, the outcome, the error.
func (f *Flows) decide(
	ctx context.Context,
	challenge string,
	in ConsentIn,
	out ConsentOut,
	hookErr error,
) (string, string, error) {
	s := f.settings.Get()

	if hookErr != nil {
		f.Log().Ctx().Warn(ctx, "consent hook failed: the request is rejected", xlog.Err(hookErr))

		to, err := f.hydra.RejectConsentRequest(ctx, challenge, ory.Reject{
			Error: "temporarily_unavailable", ErrorDescription: "Consent is unavailable right now. Please try again later.",
		})

		return to, outcomeFailed, errors.Join(hookErr, err)
	}

	decision := out.Decision
	if decision == "" {
		switch {
		case in.SkipConsent || in.Remembered:
			decision = DecisionAccept
		case s.Consent.UIURL != "":
			decision = DecisionUI
		default:
			decision = DecisionReject
			out.Error, out.ErrorDescription = "consent_required", "This installation does not ask for consent to this client."
		}
	}

	switch decision {
	case DecisionUI:
		u, err := url.Parse(s.Consent.UIURL)
		if err != nil || s.Consent.UIURL == "" {
			return "", outcomeFailed, fmt.Errorf("consent ui_url %q: %w", s.Consent.UIURL, err)
		}

		q := u.Query()
		q.Set("consent_challenge", challenge)
		u.RawQuery = q.Encode()

		return u.String(), "ui", nil
	case DecisionReject:
		code := out.Error
		if code == "" {
			code = "access_denied"
		}

		to, err := f.hydra.RejectConsentRequest(
			ctx,
			challenge,
			ory.Reject{Error: code, ErrorDescription: out.ErrorDescription},
		)

		return to, "rejected", err
	}

	return f.accept(ctx, challenge, in, out, s)
}

func (f *Flows) accept(
	ctx context.Context,
	challenge string,
	in ConsentIn,
	out ConsentOut,
	s overlay.Settings,
) (string, string, error) {
	scope := out.GrantScope
	if scope == nil {
		scope = in.RequestedScope
	}

	audience := out.GrantAudience
	if audience == nil {
		audience = in.RequestedAudience
	}

	remember, rememberFor := !in.Remembered, int64(s.Consent.RememberFor.Seconds())
	if out.Remember != nil {
		remember, rememberFor = *out.Remember, out.RememberFor
	}

	to, err := f.hydra.AcceptConsentRequest(ctx, challenge, ory.AcceptConsent{
		GrantScope: scope, GrantAudience: audience, Remember: remember, RememberFor: rememberFor,
		Session: ory.ConsentSession{AccessToken: out.AccessTokenClaims, IDToken: out.IDTokenClaims},
	})
	if err != nil {
		return "", outcomeFailed, err
	}

	ev := ConsentGranted{Subject: in.Subject, ClientID: in.ClientID, Scope: scope, Automatic: out.Decision == ""}
	if err := f.granted.Publish(ctx, ev, event.Key(in.Subject), event.ID("consent-"+challenge)); err != nil {
		f.Log().Ctx().Warn(ctx, "consent event not published", xlog.Err(err))
	}

	return to, "accepted", nil
}

func (f *Flows) logoutStep(w http.ResponseWriter, r *http.Request) {
	start, ctx := time.Now(), r.Context()
	challenge := r.URL.Query().Get("logout_challenge")

	if challenge == "" {
		f.record("logout", start, "bad_request", ErrNoChallenge)
		failPage(w, http.StatusBadRequest, ErrNoChallenge.Error())

		return
	}

	req, err := f.hydra.GetLogoutRequest(ctx, challenge)
	if err != nil {
		f.record("logout", start, outcomeFailed, err)
		failPage(w, http.StatusBadGateway, "The logout request could not be read; start over.")

		return
	}

	to, err := f.hydra.AcceptLogoutRequest(ctx, challenge)
	if err != nil {
		f.record("logout", start, outcomeFailed, err)
		failPage(w, http.StatusBadGateway, "The logout could not be completed; start over.")

		return
	}

	ev := LoggedOut{Subject: req.Subject, SID: req.SID}
	if req.Client != nil {
		ev.ClientID = req.Client.ClientID
	}

	if err := f.loggedOut.Publish(ctx, ev, event.Key(req.Subject), event.ID("logout-"+challenge)); err != nil {
		f.Log().Ctx().Warn(ctx, "logout event not published", xlog.Err(err))
	}

	f.record("logout", start, "logged_out", nil)
	http.Redirect(w, r, to, http.StatusFound)
}

// hydraToken is Hydra's token hook body.
type hydraToken struct {
	Session json.RawMessage `json:"session"`
	Request struct {
		ClientID        string              `json:"client_id"`
		RequestedScopes []string            `json:"requested_scopes"`
		GrantedScopes   []string            `json:"granted_scopes"`
		GrantedAudience []string            `json:"granted_audience"`
		GrantTypes      []string            `json:"grant_types"`
		Payload         map[string][]string `json:"payload"`
	} `json:"request"`
}

// subjectOf reads the subject of Hydra's session.
func subjectOf(session json.RawMessage) string {
	var s struct {
		Subject string `json:"subject"`
		IDToken struct {
			Subject       string `json:"subject"`
			IDTokenClaims struct {
				Subject string `json:"sub"`
			} `json:"id_token_claims"`
		} `json:"id_token"`
	}

	_ = json.Unmarshal(session, &s)

	for _, v := range []string{s.Subject, s.IDToken.Subject, s.IDToken.IDTokenClaims.Subject} {
		if v != "" {
			return v
		}
	}

	return ""
}

func (f *Flows) tokenHook(w http.ResponseWriter, r *http.Request) {
	start, ctx := time.Now(), r.Context()

	var body hydraToken

	raw, err := io.ReadAll(io.LimitReader(r.Body, maxCallback))
	if err == nil {
		err = json.Unmarshal(raw, &body)
	}

	if err != nil {
		f.record("token-hook", start, "bad_request", err)
		http.Error(w, "bad request", http.StatusBadRequest)

		return
	}

	if !f.token.Bound() {
		f.record("token-hook", start, "unbound", nil)
		w.WriteHeader(http.StatusNoContent)

		return
	}

	in := TokenIn{
		ClientID: body.Request.ClientID, Subject: subjectOf(body.Session), GrantTypes: body.Request.GrantTypes,
		RequestedScopes: body.Request.RequestedScopes, GrantedScopes: body.Request.GrantedScopes,
		GrantedAudience: body.Request.GrantedAudience, Payload: body.Request.Payload, Session: body.Session,
	}

	out, err := f.token.Call(ctx, in)

	switch {
	case errors.Is(err, hook.ErrNoBinding):
		f.record("token-hook", start, "unbound", nil)
		w.WriteHeader(http.StatusNoContent)
	case err != nil:
		f.record("token-hook", start, outcomeFailed, err)
		f.Log().Ctx().Warn(ctx, "token hook failed: no token is issued", xlog.Err(err))
		http.Error(w, "token hook failed", http.StatusBadGateway)
	case out.Deny:
		f.record("token-hook", start, "denied", nil)
		w.WriteHeader(http.StatusForbidden)
	case len(out.AccessTokenClaims) == 0 && len(out.IDTokenClaims) == 0:
		f.record("token-hook", start, "unchanged", nil)
		w.WriteHeader(http.StatusNoContent)
	default:
		f.record("token-hook", start, "changed", nil)
		w.Header().Set("Content-Type", "application/json")
		// Hydra replaces both sides: a side the hook left empty keeps the
		// session's claims.
		access, id := claimsOf(body.Session)
		if len(out.AccessTokenClaims) > 0 {
			access = out.AccessTokenClaims
		}

		if len(out.IDTokenClaims) > 0 {
			id = out.IDTokenClaims
		}

		if err := json.NewEncoder(w).
			Encode(map[string]any{"session": map[string]json.RawMessage{
				"access_token": orEmpty(access), "id_token": orEmpty(id),
			}}); err != nil {
			f.Log().Ctx().Warn(ctx, "token hook answer not written", xlog.Err(err))
		}
	}
}

// claimsOf are the extra claims of Hydra's session: the access token's
// and the ID token's.
func claimsOf(session json.RawMessage) (json.RawMessage, json.RawMessage) {
	var s struct {
		Extra   json.RawMessage `json:"extra"`
		IDToken struct {
			IDTokenClaims struct {
				Ext json.RawMessage `json:"ext"`
			} `json:"id_token_claims"`
		} `json:"id_token"`
	}

	_ = json.Unmarshal(session, &s)

	return s.Extra, s.IDToken.IDTokenClaims.Ext
}

func orEmpty(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return json.RawMessage("{}")
	}

	return raw
}
