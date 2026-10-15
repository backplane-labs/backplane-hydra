# backplane-hydra

[Ory Hydra](https://www.ory.sh/hydra/) joined to a Backplane installation.
Hydra stays a stock installation (official image, official chart); this
service sits next to it:

- **Consent → hook `hydra.Consent`.** Hydra sends browsers to this service's
  `/consent`. A binding decides (accept, reject, or a consent UI) and adds the
  claims of the tokens — typically from `kratos.GetIdentity`. Unbound, a
  trusted client (`skip_consent`) or a remembered consent is accepted; any
  other goes to `settings.consent.ui_url`, or is refused (`consent_required`).
- **Tokens → hook `hydra.TokenClaims`** (Hydra's token hook, written into
  Hydra's configuration only while bound): set the extra claims of every token
  or refuse it.
- **Logout** through Hydra lands on `/logout`, is accepted and published as
  `LoggedOut` — wire it to `kratos.RevokeSessions` to end the identity's
  sessions too. Consents publish `ConsentGranted`.
- **Admin API → activities**: `CreateClient` (answers the secret),
  `GetClient`, `ListClients`, `UpdateClient`, `PatchClient`, `SetClientLifespans`,
  `DeleteClient`, `ListConsents`,
  `RevokeConsents`, `RevokeLoginSessions`, the login/consent/logout request
  steps for products with their own UI (and `RejectLogoutRequest`,
  `AcceptDeviceRequest`), `IntrospectToken`, `DeleteTokens`, key sets
  (`GetKeySet`, `RotateKey`, `ImportKey`, `DeleteKey`, `DeleteKeySet`), trusted
  issuers (`ListTrustedIssuers`, `TrustIssuer`, `DeleteTrustedIssuer`);
  client changes publish `ClientCreated/Updated/Deleted`.
- **Console module**: Hydra's state and discovery, clients (Hydra's own JSON
  with completion and checks, secrets shown once, rotation, token deletion), a
  subject's consents and login sessions, key sets (rotation, import, deletion),
  trusted JWT issuers, token introspection, and a Settings page that saves
  revisions of this service's configuration. Every operator change is application audit.
- **Settings from the console**: issuer, login/registration/error URLs, TTLs,
  token strategies, PKCE, claims, consent defaults, OIDC subject types,
  refresh rotation — live.

## With Kratos

Kratos is Hydra's login provider: Hydra's `settings.login_url` is Kratos's
login UI, and backplane-kratos's `settings.oauth2_provider.url` is Hydra's
admin API. The consent binding gives tokens the identity's traits:

```yaml
hook: hydra.Consent
steps:
  identity:
    activity: kratos.GetIdentity
    input: {id: req.subject}
result:
  id_token_claims: {email: identity.traits.email}
```

## How Hydra picks up the settings

As with backplane-kratos: Hydra runs with the deployment's file and an
overlay this service writes (`hydra serve all -c base.yml -c overlay.yml`) on
a volume shared with this sidecar; `deployments/examples/helm-values.yaml`
does it with the official chart. The overlay owns `urls.consent` and
`urls.logout` (this service's endpoints), the token hook, and what the settings
model; `dsn`, `serve`, `secrets` stay the deployment's.

## Configuration

| Key | |
| --- | --- |
| `hydra.admin_url`, `hydra.public_url` | Hydra's APIs (default `127.0.0.1:4445/4444`) |
| `public_url` | This service as browsers reach it (Hydra redirects them to its `/consent`, `/logout`) |
| `callbacks.listen`, `callbacks.url`, `callbacks.key` | Where Hydra calls the token hook (default `:8091`) |
| `overlay`, `overlay_mode` | The overlay file and its permissions |
| `settings` | Live: the Hydra settings above, edited on the module's Settings page |
| `pairwise_salt` | Live secret kept apart from the settings |

## Develop

```sh
make configure configure-web   # tools into ./bin, web dependencies
make gen web build             # protos, console module, binary
make test                      # unit tests
make it-up it                  # a whole OAuth 2.0 flow against a real Hydra (docker)
```

Hydra v26.2.0; the overlay is validated against its configuration schema
before it is written.
