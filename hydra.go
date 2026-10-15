// Package hydra is backplane-hydra as a library: Main runs it. It joins an
// Ory Hydra installation to Backplane: consent and token claims become
// hooks, logouts and consents events, the admin API activities and a
// console module, and the settings an operator edits are written to a
// configuration overlay Hydra reloads.
package hydra

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/backplane-labs/backplane/pkg/backplane"
	"github.com/backplane-labs/backplane/pkg/backplane/api"
	"github.com/backplane-labs/backplane/pkg/backplane/config"
	"github.com/backplane-labs/backplane/pkg/backplane/deps"
	"github.com/backplane-labs/backplane/pkg/backplane/drivers/standard"
	"google.golang.org/grpc"

	"github.com/gopherex/xprobe/pkg/probe"

	"github.com/backplane-labs/backplane-hydra/internal/activities"
	"github.com/backplane-labs/backplane-hydra/internal/admin"
	"github.com/backplane-labs/backplane-hydra/internal/apply"
	"github.com/backplane-labs/backplane-hydra/internal/flows"
	"github.com/backplane-labs/backplane-hydra/internal/ory"
	"github.com/backplane-labs/backplane-hydra/internal/overlay"
	"github.com/backplane-labs/backplane-hydra/internal/ui"
	hydraconsolev1 "github.com/backplane-labs/backplane-hydra/proto/hydra/console/v1"
)

// Config is the whole configuration: file (BACKPLANE_CONFIG_FILE) < env
// HYDRA_* (BACKPLANE_* for the SDK block) < Consul KV for Live fields.
type Config struct {
	config.Backplane `json:"backplane"`

	// Hydra is the installation.
	Hydra Connection `json:"hydra"`
	// PublicURL is this service's public API as browsers reach it: Hydra
	// redirects them to its /consent and /logout.
	PublicURL string `json:"public_url" schemapb:"description=This service's public URL as browsers reach it"`
	// Callbacks is the listener Hydra calls (the token hook).
	Callbacks Callbacks `json:"callbacks"`
	// Overlay is the file Hydra loads after its own (-c base -c overlay),
	// shared with the Hydra container; empty: nothing is written.
	Overlay string `json:"overlay,omitempty" schemapb:"description=Path of the overlay file Hydra loads (empty: snippets only)"`
	// OverlayMode is the file's permission bits (octal).
	OverlayMode string `json:"overlay_mode,omitempty" schemapb:"default=0644"`
	// PairwiseSalt salts pairwise subject identifiers; live, kept apart
	// from the settings.
	PairwiseSalt config.Live[config.Secret] `json:"pairwise_salt,omitempty" schemapb:"description=Salt of pairwise subject identifiers"`
	// Settings are Hydra's settings rendered into the overlay; live.
	Settings config.Live[overlay.Settings] `json:"settings"`
}

// Connection to Hydra.
type Connection struct {
	AdminURL  string                   `json:"admin_url"         schemapb:"default=http://127.0.0.1:4445"`
	PublicURL string                   `json:"public_url"        schemapb:"default=http://127.0.0.1:4444"`
	Headers   map[string]config.Secret `json:"headers,omitempty"`
	Timeout   time.Duration            `json:"timeout"           schemapb:"default=10s"`
}

// Callbacks listener.
type Callbacks struct {
	Listen string `json:"listen" schemapb:"default=:8091"`
	// URL is the listener as Hydra reaches it.
	URL string `json:"url" schemapb:"default=http://127.0.0.1:8091"`
	// Key authenticates Hydra; empty: derived from the internal secret.
	Key config.Secret `json:"key,omitempty"`
}

// Validate what the schema cannot: the settings must render into a
// configuration Hydra accepts.
func (c *Config) Validate() error {
	every := func(string) bool { return true }

	doc, err := overlay.Render(c.Settings.Get(), overlay.Secrets{}, overlay.Wiring{
		PublicURL: c.PublicURL, CallbacksURL: c.Callbacks.URL, Key: "k", Bound: every,
	})
	if err != nil {
		return fmt.Errorf("settings: %w", err)
	}

	if err := overlay.Validate(doc); err != nil {
		return fmt.Errorf("settings: %w", err)
	}

	return nil
}

// ErrNoKey: neither a callbacks key nor an internal secret is configured.
var ErrNoKey = errors.New("hydra: callbacks.key or backplane.internal_secret is required")

// ErrOverlayMode: overlay_mode is not octal permission bits.
var ErrOverlayMode = errors.New("hydra: overlay_mode must be octal permission bits like 0640")

// ErrPublicURL: browsers must reach the consent endpoint.
var ErrPublicURL = errors.New("hydra: public_url is required (Hydra redirects browsers to its /consent)")

func (c *Config) callbackKey() (string, error) {
	if k := c.Callbacks.Key.Reveal(); k != "" {
		return k, nil
	}

	secret := c.InternalSecret.Reveal()
	if secret == "" {
		return "", ErrNoKey
	}

	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte("backplane-hydra callbacks"))

	return hex.EncodeToString(m.Sum(nil)), nil
}

// State is the service's tree.
type State struct {
	Hydra      deps.Dependency[ory.Client]
	Flows      *flows.Flows
	Applier    *apply.Applier
	Activities *activities.Activities
	Admin      *admin.Admin

	callbacks string
}

// Main runs backplane-hydra until a signal stops it, exiting on error.
func Main() {
	if err := Run(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// Run runs backplane-hydra until ctx ends or a signal stops it.
func Run(ctx context.Context) error {
	svc, err := backplane.Open(ctx, newState, standard.Drivers())
	if err != nil {
		return fmt.Errorf("hydra: %w", err)
	}

	st := svc.State()

	svc.HTTP("/", st.Flows.Public())
	svc.HTTP("/", st.Flows.Callbacks(), api.Listen(st.callbacks))
	svc.Internal(func(r grpc.ServiceRegistrar) { hydraconsolev1.RegisterAdminServiceServer(r, st.Admin) })

	if bundle := ui.Bundle(); bundle != nil {
		svc.UI(bundle)
	}

	svc.ReadinessProbe(probe.FromError(st.Applier.Ready))

	if err := svc.Run(ctx); err != nil {
		return fmt.Errorf("hydra: %w", err)
	}

	return nil
}

func newState(root backplane.Root[Config]) (*State, error) {
	cfg := root.Config()

	if cfg.PublicURL == "" {
		return nil, ErrPublicURL
	}

	key, err := cfg.callbackKey()
	if err != nil {
		return nil, err
	}

	mode, err := strconv.ParseUint(cfg.OverlayMode, 8, 32)
	if err != nil || mode > 0o777 {
		return nil, fmt.Errorf("%w: %q", ErrOverlayMode, cfg.OverlayMode)
	}

	headers := map[string]string{}
	for k, v := range cfg.Hydra.Headers {
		headers[k] = v.Reveal()
	}

	client, err := ory.New(ory.Options{
		Admin: cfg.Hydra.AdminURL, Public: cfg.Hydra.PublicURL, Headers: headers, Timeout: cfg.Hydra.Timeout,
	})
	if err != nil {
		return nil, fmt.Errorf("hydra: %w", err)
	}

	st := &State{
		Hydra:     deps.NewDependency[ory.Client](root, dependency{client: client}),
		callbacks: cfg.Callbacks.Listen,
	}
	st.Flows = flows.New(root, client, key, cfg.Settings)
	st.Applier = apply.New(
		root,
		cfg.Overlay,
		os.FileMode(mode),
		cfg.Settings,
		cfg.PairwiseSalt,
		st.Flows,
		overlay.Wiring{
			PublicURL: cfg.PublicURL, CallbacksURL: cfg.Callbacks.URL, Key: key,
		},
	)
	st.Activities = activities.New(root, client)
	st.Admin = admin.New(root, client, st.Flows, st.Applier, cfg.PublicURL)

	return st, nil
}

// dependency is the Hydra installation: ready while its admin API is.
type dependency struct{ client ory.Client }

func (dependency) Name() string { return "hydra" }

func (d dependency) Provide(context.Context, deps.Scope) (ory.Client, error) { return d.client, nil }

func (d dependency) Probe(ctx context.Context, _ ory.Client) error {
	if err := d.client.Ready(ctx); err != nil {
		return fmt.Errorf("hydra at %s: %w", d.client.AdminURL(), err)
	}

	return nil
}

func (dependency) Close(context.Context, ory.Client) error { return nil }
