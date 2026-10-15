// Package activities offers Hydra's admin API to wiring: OAuth 2.0
// clients, login, consent and logout requests (for products with their
// own UI), consent and login sessions, token introspection and keys.
package activities

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/backplane-labs/backplane/pkg/backplane/activity"
	"github.com/backplane-labs/backplane/pkg/backplane/deps"
	"github.com/backplane-labs/backplane/pkg/backplane/event"

	"github.com/gopherex/xlog"

	"github.com/backplane-labs/backplane-hydra/internal/ory"
)

const timeout = 15 * time.Second

// Activities are the admin API as activities.
type Activities struct {
	deps.Component

	hydra ory.Client

	clientCreated  event.Ref[ClientEvent]
	clientUpdated  event.Ref[ClientEvent]
	clientDeleted  event.Ref[ClientEvent]
	consentRevoked event.Ref[ConsentRevoked]
}

// ClientEvent is a client created, changed or deleted.
type ClientEvent struct {
	ClientID   string `json:"client_id"`
	ClientName string `json:"client_name,omitempty"`
	By         string `json:"by"`
}

// ConsentRevoked: a subject's consents were revoked (of one client, or
// all when ClientID is empty).
type ConsentRevoked struct {
	Subject  string `json:"subject"`
	ClientID string `json:"client_id,omitempty"`
	By       string `json:"by"`
}

// New declares the activities and events under parent.
func New(parent deps.Scope, hydra ory.Client) *Activities {
	a := &Activities{Component: deps.NewComponent(parent, "activities"), hydra: hydra}
	a.clientCreated = event.Declare[ClientEvent](a, "ClientCreated", event.Describe("an OAuth 2.0 client was created"))
	a.clientUpdated = event.Declare[ClientEvent](a, "ClientUpdated", event.Describe("an OAuth 2.0 client was changed"))
	a.clientDeleted = event.Declare[ClientEvent](a, "ClientDeleted", event.Describe("an OAuth 2.0 client was deleted"))
	a.consentRevoked = event.Declare[ConsentRevoked](
		a,
		"ConsentRevoked",
		event.Describe("a subject's consents were revoked"),
	)

	opts := func(desc string) []activity.Option {
		return []activity.Option{activity.StartToClose(timeout), activity.Describe(desc)}
	}

	activity.Handle(
		a,
		"CreateClient",
		a.createClient,
		opts("Create an OAuth 2.0 client; the result holds its secret")...)
	activity.Handle(a, "GetClient", a.getClient, opts("Read an OAuth 2.0 client")...)
	activity.Handle(a, "ListClients", a.listClients, opts("List OAuth 2.0 clients, a page at a time")...)
	activity.Handle(a, "UpdateClient", a.updateClient, opts("Replace an OAuth 2.0 client")...)
	activity.Handle(a, "DeleteClient", a.deleteClient, opts("Delete an OAuth 2.0 client")...)
	activity.Handle(a, "ListConsents", a.listConsents, opts("List a subject's remembered consents")...)
	activity.Handle(a, "RevokeConsents", a.revokeConsents, opts("Revoke a subject's consents (one client or all)")...)
	activity.Handle(a, "RevokeLoginSessions", a.revokeLogins, opts("End a subject's login sessions")...)
	activity.Handle(a, "GetLoginRequest", a.getLogin, opts("Read a pending login (a custom login UI)")...)
	activity.Handle(a, "AcceptLoginRequest", a.acceptLogin, opts("Accept a pending login: the redirect")...)
	activity.Handle(a, "RejectLoginRequest", a.rejectLogin, opts("Reject a pending login: the redirect")...)
	activity.Handle(a, "GetConsentRequest", a.getConsent, opts("Read a pending consent (a custom consent UI)")...)
	activity.Handle(a, "AcceptConsentRequest", a.acceptConsent, opts("Accept a pending consent: the redirect")...)
	activity.Handle(a, "RejectConsentRequest", a.rejectConsent, opts("Reject a pending consent: the redirect")...)
	activity.Handle(a, "AcceptLogoutRequest", a.acceptLogout, opts("Accept a pending logout: the redirect")...)
	activity.Handle(a, "IntrospectToken", a.introspect, opts("The state of an access or refresh token")...)
	activity.Handle(a, "DeleteTokens", a.deleteTokens, opts("Delete every token of a client")...)

	return a
}

// ClientEvents is a declared client event by name.
func (a *Activities) ClientEvents(name string) event.Ref[ClientEvent] {
	switch name {
	case "ClientCreated":
		return a.clientCreated
	case "ClientUpdated":
		return a.clientUpdated
	default:
		return a.clientDeleted
	}
}

func failure(err error) error {
	if err == nil {
		return nil
	}

	if ory.Temporary(err) {
		return err
	}

	return activity.NonRetryable(err)
}

func (a *Activities) publish(ctx context.Context, ref event.Ref[ClientEvent], ev ClientEvent) {
	if err := ref.Publish(ctx, ev, event.Key(ev.ClientID)); err != nil {
		a.Log().Ctx().Warn(ctx, "client event not published", xlog.String("client", ev.ClientID), xlog.Err(err))
	}
}

// Empty is an activity without a result.
type Empty struct{}

func (a *Activities) createClient(ctx context.Context, in ory.OAuth2Client) (ory.OAuth2Client, error) {
	body, err := json.Marshal(in) //nolint:gosec // the client, secret included, goes to Hydra
	if err != nil {
		return ory.OAuth2Client{}, activity.NonRetryable(fmt.Errorf("client: %w", err))
	}

	out, err := a.hydra.CreateClient(ctx, body)
	if err != nil {
		return out, failure(err)
	}

	a.publish(ctx, a.clientCreated, ClientEvent{ClientID: out.ClientID, ClientName: out.ClientName, By: "wiring"})

	return out, nil
}

// ClientIDIn names a client.
type ClientIDIn struct {
	ClientID string `json:"client_id"`
}

func (a *Activities) getClient(ctx context.Context, in ClientIDIn) (ory.OAuth2Client, error) {
	out, err := a.hydra.GetClient(ctx, in.ClientID)

	return out, failure(err)
}

// ListClientsIn narrows ListClients.
type ListClientsIn struct {
	Name      string `json:"name,omitempty"`
	Owner     string `json:"owner,omitempty"`
	PageSize  int    `json:"page_size,omitempty"`
	PageToken string `json:"page_token,omitempty"`
}

// ListClientsOut is a page of clients.
type ListClientsOut struct {
	Clients       []ory.OAuth2Client `json:"clients"`
	NextPageToken string             `json:"next_page_token,omitempty"`
}

func (a *Activities) listClients(ctx context.Context, in ListClientsIn) (ListClientsOut, error) {
	page, err := a.hydra.ListClients(
		ctx,
		ory.ClientFilter{Name: in.Name, Owner: in.Owner, PageSize: in.PageSize, PageToken: in.PageToken},
	)

	return ListClientsOut{Clients: page.Items, NextPageToken: page.Next}, failure(err)
}

// ErrNoClientID: name the client.
var ErrNoClientID = errors.New("client_id is required")

func (a *Activities) updateClient(ctx context.Context, in ory.OAuth2Client) (ory.OAuth2Client, error) {
	if in.ClientID == "" {
		return ory.OAuth2Client{}, activity.NonRetryable(ErrNoClientID)
	}

	body, err := json.Marshal(in) //nolint:gosec // the client, secret included, goes to Hydra
	if err != nil {
		return ory.OAuth2Client{}, activity.NonRetryable(fmt.Errorf("client: %w", err))
	}

	out, err := a.hydra.SetClient(ctx, in.ClientID, body)
	if err != nil {
		return out, failure(err)
	}

	a.publish(ctx, a.clientUpdated, ClientEvent{ClientID: out.ClientID, ClientName: out.ClientName, By: "wiring"})

	return out, nil
}

func (a *Activities) deleteClient(ctx context.Context, in ClientIDIn) (Empty, error) {
	if err := a.hydra.DeleteClient(ctx, in.ClientID); err != nil && !ory.IsNotFound(err) {
		return Empty{}, failure(err)
	}

	a.publish(ctx, a.clientDeleted, ClientEvent{ClientID: in.ClientID, By: "wiring"})

	return Empty{}, nil
}

// SubjectIn names a subject, optionally narrowed.
type SubjectIn struct {
	Subject string `json:"subject"`
	// ClientID narrows RevokeConsents to one client.
	ClientID string `json:"client_id,omitempty"`
	// SID narrows RevokeLoginSessions to one session.
	SID string `json:"sid,omitempty"`
}

// ConsentsOut are a subject's remembered consents.
type ConsentsOut struct {
	Consents []ory.ConsentGrant `json:"consents"`
}

func (a *Activities) listConsents(ctx context.Context, in SubjectIn) (ConsentsOut, error) {
	var out ConsentsOut

	token := ""

	for {
		page, err := a.hydra.ListConsentSessions(ctx, in.Subject, token)
		if err != nil {
			return out, failure(err)
		}

		out.Consents = append(out.Consents, page.Items...)
		if page.Next == "" {
			return out, nil
		}

		token = page.Next
	}
}

func (a *Activities) revokeConsents(ctx context.Context, in SubjectIn) (Empty, error) {
	if err := a.hydra.RevokeConsentSessions(ctx, in.Subject, in.ClientID); err != nil {
		return Empty{}, failure(err)
	}

	if err := a.consentRevoked.Publish(ctx, ConsentRevoked{Subject: in.Subject, ClientID: in.ClientID, By: "wiring"},
		event.Key(in.Subject)); err != nil {
		a.Log().Ctx().Warn(ctx, "consent event not published", xlog.Err(err))
	}

	return Empty{}, nil
}

func (a *Activities) revokeLogins(ctx context.Context, in SubjectIn) (Empty, error) {
	return Empty{}, failure(a.hydra.RevokeLoginSessions(ctx, in.Subject, in.SID))
}

// ChallengeIn names a pending request.
type ChallengeIn struct {
	Challenge string `json:"challenge"`
}

// RedirectOut is where the browser goes next.
type RedirectOut struct {
	RedirectTo string `json:"redirect_to"`
}

func (a *Activities) getLogin(ctx context.Context, in ChallengeIn) (ory.LoginRequest, error) {
	out, err := a.hydra.GetLoginRequest(ctx, in.Challenge)

	return out, failure(err)
}

// AcceptLoginIn accepts a login.
type AcceptLoginIn struct {
	Challenge string `json:"challenge"`
	ory.AcceptLogin
}

func (a *Activities) acceptLogin(ctx context.Context, in AcceptLoginIn) (RedirectOut, error) {
	to, err := a.hydra.AcceptLoginRequest(ctx, in.Challenge, in.AcceptLogin)

	return RedirectOut{RedirectTo: to}, failure(err)
}

// RejectIn rejects a request.
type RejectIn struct {
	Challenge string `json:"challenge"`
	ory.Reject
}

func (a *Activities) rejectLogin(ctx context.Context, in RejectIn) (RedirectOut, error) {
	to, err := a.hydra.RejectLoginRequest(ctx, in.Challenge, in.Reject)

	return RedirectOut{RedirectTo: to}, failure(err)
}

func (a *Activities) getConsent(ctx context.Context, in ChallengeIn) (ory.ConsentRequest, error) {
	out, err := a.hydra.GetConsentRequest(ctx, in.Challenge)

	return out, failure(err)
}

// AcceptConsentIn accepts a consent.
type AcceptConsentIn struct {
	Challenge string `json:"challenge"`
	ory.AcceptConsent
}

func (a *Activities) acceptConsent(ctx context.Context, in AcceptConsentIn) (RedirectOut, error) {
	to, err := a.hydra.AcceptConsentRequest(ctx, in.Challenge, in.AcceptConsent)

	return RedirectOut{RedirectTo: to}, failure(err)
}

func (a *Activities) rejectConsent(ctx context.Context, in RejectIn) (RedirectOut, error) {
	to, err := a.hydra.RejectConsentRequest(ctx, in.Challenge, in.Reject)

	return RedirectOut{RedirectTo: to}, failure(err)
}

func (a *Activities) acceptLogout(ctx context.Context, in ChallengeIn) (RedirectOut, error) {
	to, err := a.hydra.AcceptLogoutRequest(ctx, in.Challenge)

	return RedirectOut{RedirectTo: to}, failure(err)
}

// IntrospectIn is a token to inspect.
type IntrospectIn struct {
	Token string `json:"token"           schemapb:"secret=true"`
	Scope string `json:"scope,omitempty"`
}

func (a *Activities) introspect(ctx context.Context, in IntrospectIn) (ory.Introspection, error) {
	out, err := a.hydra.Introspect(ctx, in.Token, in.Scope)

	return out, failure(err)
}

func (a *Activities) deleteTokens(ctx context.Context, in ClientIDIn) (Empty, error) {
	return Empty{}, failure(a.hydra.DeleteTokens(ctx, in.ClientID))
}
