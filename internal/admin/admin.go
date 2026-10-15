// Package admin is the console module's API: the Hydra installation, its
// clients, consents, keys and trusted issuers. Every mutation is
// application audit.
package admin

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/backplane-labs/backplane/pkg/backplane"
	"github.com/backplane-labs/backplane/pkg/backplane/deps"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/gopherex/xlog"

	"github.com/backplane-labs/backplane-hydra/internal/apply"
	"github.com/backplane-labs/backplane-hydra/internal/flows"
	"github.com/backplane-labs/backplane-hydra/internal/ory"
	v1 "github.com/backplane-labs/backplane-hydra/proto/hydra/console/v1"
)

// secretBytes is the entropy of a generated client secret.
const secretBytes = 32

// Admin serves AdminService.
type Admin struct {
	v1.UnimplementedAdminServiceServer
	deps.Component

	hydra      ory.Client
	flows      *flows.Flows
	applier    *apply.Applier
	consentURL string
	logoutURL  string
}

// New creates the component under parent; publicURL is backplane-hydra's
// public API as browsers reach it.
func New(parent deps.Scope, h ory.Client, f *flows.Flows, a *apply.Applier, publicURL string) *Admin {
	base := strings.TrimRight(publicURL, "/")

	return &Admin{
		Component: deps.NewComponent(parent, "admin"), hydra: h, flows: f, applier: a,
		consentURL: base + "/consent", logoutURL: base + "/logout",
	}
}

func grpcErr(err error) error {
	if err == nil {
		return nil
	}

	var e *ory.Error
	if errors.As(err, &e) {
		switch {
		case e.Status == http.StatusNotFound:
			return status.Error(codes.NotFound, e.Error())
		case e.Status == http.StatusConflict:
			return status.Error(codes.AlreadyExists, e.Error())
		case e.Status == http.StatusBadRequest:
			return status.Error(codes.InvalidArgument, e.Error())
		case e.Status >= http.StatusInternalServerError:
			return status.Error(codes.Unavailable, e.Error())
		}

		return status.Error(codes.FailedPrecondition, e.Error())
	}

	if errors.Is(err, context.DeadlineExceeded) {
		return status.Error(codes.DeadlineExceeded, err.Error())
	}

	return status.Error(codes.Unavailable, err.Error())
}

func (a *Admin) audit(ctx context.Context, action, subject string, err error, fields ...xlog.Field) {
	outcome := "succeeded"
	if err != nil {
		outcome = "failed"
	}

	fields = append(fields, backplane.Audit(), xlog.String("event.name", action),
		xlog.String(backplane.AuditID, uuid.NewString()), xlog.String(backplane.AuditSubject, subject),
		xlog.String(backplane.AuditActor, "console"), xlog.String(backplane.AuditOutcome, outcome))
	if err != nil {
		fields = append(fields, xlog.Err(err))
	}

	a.Log().Ctx().Info(ctx, action, fields...)
}

func ts(t *time.Time) *timestamppb.Timestamp {
	if t == nil || t.IsZero() {
		return nil
	}

	return timestamppb.New(*t)
}

// GetStatus implements AdminService.
func (a *Admin) GetStatus(ctx context.Context, _ *v1.GetStatusRequest) (*v1.GetStatusResponse, error) {
	out := &v1.GetStatusResponse{
		AdminUrl: a.hydra.AdminURL(), PublicUrl: a.hydra.PublicURL(), ConsentUrl: a.consentURL, LogoutUrl: a.logoutURL,
	}

	if err := a.hydra.Ready(ctx); err != nil {
		out.Problem = err.Error()
	}

	if v, err := a.hydra.Version(ctx); err == nil {
		out.Version = v
	}

	st := a.applier.State()
	out.Overlay = &v1.Overlay{Path: st.Path, Hash: st.Hash}

	if !st.WrittenAt.IsZero() {
		out.Overlay.WrittenAt = timestamppb.New(st.WrittenAt)
	}

	if st.Err != nil {
		out.Overlay.Error = st.Err.Error()
	}

	descriptions := map[string]string{ //nolint:gosec // hook names, not credentials
		"Consent":     "Decides consents and adds the claims of their tokens",
		"TokenClaims": "Sets the extra claims of every issued token",
	}

	for _, name := range a.flows.Hooks() {
		out.Hooks = append(
			out.Hooks,
			&v1.HookPoint{Name: name, Bound: a.flows.Bound(name), Description: descriptions[name]},
		)
	}

	for _, s := range a.flows.Stats() {
		c := &v1.CallbackStat{
			Point: s.Point, Calls: s.Calls, Failures: s.Failures, LastOutcome: s.LastOutcome, LastError: s.LastError,
			LastLatencyMs: float64(s.LastLatency.Microseconds()) / 1000, //nolint:mnd // ms
		}
		if !s.LastAt.IsZero() {
			c.LastAt = timestamppb.New(s.LastAt)
		}

		out.Callbacks = append(out.Callbacks, c)
	}

	out.Discovery = &v1.Discovery{}

	doc, err := a.hydra.Discovery(ctx)
	if err != nil {
		out.Discovery.Error = err.Error()
	} else {
		str := func(k string) string { s, _ := doc[k].(string); return s }
		out.Discovery.Issuer, out.Discovery.AuthorizationEndpoint = str("issuer"), str("authorization_endpoint")
		out.Discovery.TokenEndpoint, out.Discovery.JwksUri = str("token_endpoint"), str("jwks_uri")
	}

	return out, nil
}

// GetOverlay implements AdminService.
func (a *Admin) GetOverlay(context.Context, *v1.GetOverlayRequest) (*v1.GetOverlayResponse, error) {
	content, err := a.applier.Masked()
	if err != nil {
		return &v1.GetOverlayResponse{Error: err.Error()}, nil //nolint:nilerr // reported in the response
	}

	return &v1.GetOverlayResponse{Content: string(content)}, nil
}

func client(c ory.OAuth2Client) *v1.Client {
	c.ClientSecret = ""
	// The secret is cleared above; Hydra's JSON marshals.
	raw, _ := json.MarshalIndent(c, "", "  ") //nolint:gosec,errchkjson // see above //nolint:errchkjson // plain struct

	return &v1.Client{
		ClientId: c.ClientID, ClientName: c.ClientName, GrantTypes: c.GrantTypes, RedirectUris: c.RedirectURIs,
		Scope:       c.Scope,
		SkipConsent: c.SkipConsent, TokenEndpointAuthMethod: c.TokenEndpointAuthMethod, Owner: c.Owner,
		CreatedAt: ts(c.CreatedAt), ClientJson: string(raw),
	}
}

// ListClients implements AdminService.
func (a *Admin) ListClients(ctx context.Context, r *v1.ListClientsRequest) (*v1.ListClientsResponse, error) {
	page, err := a.hydra.ListClients(ctx, ory.ClientFilter{
		Name: r.GetName(), PageSize: int(r.GetPageSize()), PageToken: r.GetPageToken(),
	})
	if err != nil {
		return nil, grpcErr(err)
	}

	out := &v1.ListClientsResponse{NextPageToken: page.Next}
	for i := range page.Items {
		out.Clients = append(out.Clients, client(page.Items[i]))
	}

	return out, nil
}

// GetClient implements AdminService.
func (a *Admin) GetClient(ctx context.Context, r *v1.GetClientRequest) (*v1.GetClientResponse, error) {
	c, err := a.hydra.GetClient(ctx, r.GetClientId())
	if err != nil {
		return nil, grpcErr(err)
	}

	return &v1.GetClientResponse{Client: client(c)}, nil
}

func checkJSON(raw string) error {
	if !json.Valid([]byte(raw)) {
		return status.Error(codes.InvalidArgument, "not valid JSON")
	}

	return nil
}

// CreateClient implements AdminService.
func (a *Admin) CreateClient(ctx context.Context, r *v1.CreateClientRequest) (*v1.CreateClientResponse, error) {
	if err := checkJSON(r.GetClientJson()); err != nil {
		return nil, err
	}

	c, err := a.hydra.CreateClient(ctx, json.RawMessage(r.GetClientJson()))
	a.audit(ctx, "hydra.client.created", "client/"+c.ClientID, err)

	if err != nil {
		return nil, grpcErr(err)
	}

	return &v1.CreateClientResponse{Client: client(c), ClientSecret: c.ClientSecret}, nil
}

// UpdateClient implements AdminService.
func (a *Admin) UpdateClient(ctx context.Context, r *v1.UpdateClientRequest) (*v1.UpdateClientResponse, error) {
	if err := checkJSON(r.GetClientJson()); err != nil {
		return nil, err
	}

	c, err := a.hydra.SetClient(ctx, r.GetClientId(), json.RawMessage(r.GetClientJson()))
	a.audit(ctx, "hydra.client.updated", "client/"+r.GetClientId(), err)

	if err != nil {
		return nil, grpcErr(err)
	}

	return &v1.UpdateClientResponse{Client: client(c)}, nil
}

// DeleteClient implements AdminService.
func (a *Admin) DeleteClient(ctx context.Context, r *v1.DeleteClientRequest) (*v1.DeleteClientResponse, error) {
	err := a.hydra.DeleteClient(ctx, r.GetClientId())
	a.audit(ctx, "hydra.client.deleted", "client/"+r.GetClientId(), err)

	return &v1.DeleteClientResponse{}, grpcErr(err)
}

// RotateClientSecret implements AdminService.
func (a *Admin) RotateClientSecret(
	ctx context.Context,
	r *v1.RotateClientSecretRequest,
) (*v1.RotateClientSecretResponse, error) {
	buf := make([]byte, secretBytes)
	if _, err := rand.Read(buf); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	type op struct {
		Op    string `json:"op"`
		Path  string `json:"path"`
		Value string `json:"value"`
	}

	secret := base64.RawURLEncoding.EncodeToString(buf)

	patch, err := json.Marshal([]op{{Op: "replace", Path: "/client_secret", Value: secret}})
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	_, err = a.hydra.PatchClient(ctx, r.GetClientId(), patch)
	a.audit(ctx, "hydra.client.secret_rotated", "client/"+r.GetClientId(), err)

	if err != nil {
		return nil, grpcErr(err)
	}

	return &v1.RotateClientSecretResponse{ClientSecret: secret}, nil
}

// ListConsents implements AdminService.
func (a *Admin) ListConsents(ctx context.Context, r *v1.ListConsentsRequest) (*v1.ListConsentsResponse, error) {
	out := &v1.ListConsentsResponse{}
	token := ""

	for {
		page, err := a.hydra.ListConsentSessions(ctx, r.GetSubject(), token)
		if err != nil {
			return nil, grpcErr(err)
		}

		for i := range page.Items {
			g := &page.Items[i]
			out.Consents = append(out.Consents, &v1.Consent{
				ClientId: g.ConsentRequest.Client.ClientID, ClientName: g.ConsentRequest.Client.ClientName,
				GrantScope: g.GrantScope, GrantAudience: g.GrantAudience, Remember: g.Remember, RememberFor: g.RememberFor,
				HandledAt: ts(g.HandledAt),
			})
		}

		if page.Next == "" {
			return out, nil
		}

		token = page.Next
	}
}

// RevokeConsents implements AdminService.
func (a *Admin) RevokeConsents(ctx context.Context, r *v1.RevokeConsentsRequest) (*v1.RevokeConsentsResponse, error) {
	err := a.hydra.RevokeConsentSessions(ctx, r.GetSubject(), r.GetClientId())
	a.audit(ctx, "hydra.consents.revoked", "subject/"+r.GetSubject(), err, xlog.String("client", r.GetClientId()))

	return &v1.RevokeConsentsResponse{}, grpcErr(err)
}

// RevokeLoginSessions implements AdminService.
func (a *Admin) RevokeLoginSessions(
	ctx context.Context,
	r *v1.RevokeLoginSessionsRequest,
) (*v1.RevokeLoginSessionsResponse, error) {
	err := a.hydra.RevokeLoginSessions(ctx, r.GetSubject(), "")
	a.audit(ctx, "hydra.logins.revoked", "subject/"+r.GetSubject(), err)

	return &v1.RevokeLoginSessionsResponse{}, grpcErr(err)
}

func keys(in []ory.JWK) []*v1.Key {
	out := make([]*v1.Key, 0, len(in))
	for _, k := range in {
		out = append(out, &v1.Key{Kid: k.KID, Alg: k.Alg, Use: k.Use, Kty: k.Kty})
	}

	return out
}

// GetKeySet implements AdminService.
func (a *Admin) GetKeySet(ctx context.Context, r *v1.GetKeySetRequest) (*v1.GetKeySetResponse, error) {
	ks, err := a.hydra.GetKeySet(ctx, r.GetSet())
	if err != nil {
		return nil, grpcErr(err)
	}

	return &v1.GetKeySetResponse{Keys: keys(ks)}, nil
}

// RotateKey implements AdminService.
func (a *Admin) RotateKey(ctx context.Context, r *v1.RotateKeyRequest) (*v1.RotateKeyResponse, error) {
	use := r.GetUse()
	if use == "" {
		use = "sig"
	}

	ks, err := a.hydra.CreateKey(ctx, r.GetSet(), r.GetAlg(), use, uuid.NewString())
	a.audit(ctx, "hydra.key.rotated", "keyset/"+r.GetSet(), err, xlog.String("alg", r.GetAlg()))

	if err != nil {
		return nil, grpcErr(err)
	}

	return &v1.RotateKeyResponse{Keys: keys(ks)}, nil
}

// DeleteKey implements AdminService.
func (a *Admin) DeleteKey(ctx context.Context, r *v1.DeleteKeyRequest) (*v1.DeleteKeyResponse, error) {
	err := a.hydra.DeleteKey(ctx, r.GetSet(), r.GetKid())
	a.audit(ctx, "hydra.key.deleted", "keyset/"+r.GetSet()+"/"+r.GetKid(), err)

	return &v1.DeleteKeyResponse{}, grpcErr(err)
}

func issuer(t ory.TrustedIssuer) *v1.TrustedIssuer {
	return &v1.TrustedIssuer{
		Id: t.ID, Issuer: t.Issuer, Subject: t.Subject, AllowAnySubject: t.AllowAnySubject, Scope: t.Scope,
		ExpiresAt: ts(t.ExpiresAt), KeyId: t.PublicKey.KID,
	}
}

// ListTrustedIssuers implements AdminService.
func (a *Admin) ListTrustedIssuers(
	ctx context.Context,
	_ *v1.ListTrustedIssuersRequest,
) (*v1.ListTrustedIssuersResponse, error) {
	list, err := a.hydra.ListTrustedIssuers(ctx)
	if err != nil {
		return nil, grpcErr(err)
	}

	out := &v1.ListTrustedIssuersResponse{}
	for i := range list {
		out.Issuers = append(out.Issuers, issuer(list[i]))
	}

	return out, nil
}

// TrustIssuer implements AdminService.
func (a *Admin) TrustIssuer(ctx context.Context, r *v1.TrustIssuerRequest) (*v1.TrustIssuerResponse, error) {
	if err := checkJSON(r.GetIssuerJson()); err != nil {
		return nil, err
	}

	t, err := a.hydra.TrustIssuer(ctx, json.RawMessage(r.GetIssuerJson()))
	a.audit(ctx, "hydra.issuer.trusted", "issuer/"+t.ID, err)

	if err != nil {
		return nil, grpcErr(err)
	}

	return &v1.TrustIssuerResponse{Issuer: issuer(t)}, nil
}

// DeleteTrustedIssuer implements AdminService.
func (a *Admin) DeleteTrustedIssuer(
	ctx context.Context,
	r *v1.DeleteTrustedIssuerRequest,
) (*v1.DeleteTrustedIssuerResponse, error) {
	err := a.hydra.DeleteTrustedIssuer(ctx, r.GetId())
	a.audit(ctx, "hydra.issuer.deleted", "issuer/"+r.GetId(), err)

	return &v1.DeleteTrustedIssuerResponse{}, grpcErr(err)
}

// Introspect implements AdminService.
func (a *Admin) Introspect(ctx context.Context, r *v1.IntrospectRequest) (*v1.IntrospectResponse, error) {
	info, err := a.hydra.Introspect(ctx, r.GetToken(), "")
	if err != nil {
		return nil, grpcErr(err)
	}

	out := &v1.IntrospectResponse{
		Active: info.Active, Subject: info.Subject, ClientId: info.ClientID, Scope: info.Scope, TokenUse: info.TokenUse,
		ExtJson: string(info.Ext),
	}
	if info.ExpiresAt > 0 {
		out.ExpiresAt = timestamppb.New(time.Unix(info.ExpiresAt, 0))
	}

	if info.IssuedAt > 0 {
		out.IssuedAt = timestamppb.New(time.Unix(info.IssuedAt, 0))
	}

	return out, nil
}
