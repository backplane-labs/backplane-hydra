export default {
  overview: 'Overview', clients: 'Clients', subjects: 'Subjects', keys: 'Keys', issuers: 'Trusted issuers', tokens: 'Tokens',
  refresh: 'Refresh', loading: 'Loading', error: 'Could not load. Check the connection, the service and Hydra.',
  standalone: 'Standalone · local fixtures', embedded: 'Embedded in Backplane', light: 'Light theme', dark: 'Dark theme',
  missing: 'Page not found', back: 'Back to the overview', delete: 'Delete', save: 'Save', saving: 'Saving…', create: 'Create', creating: 'Creating…',
  previous: 'Previous', next: 'Next', revoke: 'Revoke', no: 'no', created: 'Created', expires: 'Expires', state: 'State', active: 'active', inactive: 'inactive',

  overviewTitle: 'Ory Hydra', overviewDescription: 'The OAuth 2.0 and OpenID Connect provider this service joins to Backplane: consent and token claims as hooks, its admin API as activities. Settings are edited on the service\'s Settings page and written to the overlay Hydra reloads.',
  hydraDown: 'Hydra is not ready', overlayRejected: 'The settings were not applied', hydra: 'Hydra', issuer: 'Issuer', overlay: 'Overlay', snippets: 'Snippets',
  snippetsHint: 'No overlay file: paste the configuration below into Hydra\'s.', endpoints: 'Browser endpoints', endpointsHint: 'Hydra sends browsers here for consent and logout (urls.consent, urls.logout).',
  consentUrl: 'Consent', logoutUrl: 'Logout', hooks: 'Hooks', hooksFooter: 'Bind hydra.Consent to add claims (e.g. kratos.GetIdentity) or decide consent; bind hydra.TokenClaims to shape every token.',
  isBound: 'bound', unbound: 'unbound', callbacks: 'Calls since start', noCallbacks: 'Nothing yet.', point: 'Point', calls: 'Calls', last: 'Last', outcome: 'Outcome', failures: '{{count}} failed',
  overlayContent: 'Overlay', overlayContentHint: 'What Hydra loads after its own file; secrets are masked here.',

  clientsTitle: 'OAuth 2.0 clients', clientsDescription: 'Applications that sign users in through Hydra. Changes go to Hydra\'s admin API and are audited.',
  newClient: 'New client', newClientHint: 'Hydra\'s client JSON. The ID and secret are generated; the secret is shown once.', searchClients: 'Filter by name',
  noClients: 'No clients yet.', client: 'Client', grants: 'Grants', auth: 'Token auth', consent: 'Consent', trusted: 'trusted', asks: 'asks', clientId: 'Client ID',
  clientJson: 'Client', clientObject: 'A client is a JSON object.', redirectRequired: 'The authorization code grant needs redirect_uris.', unknownKey: 'Hydra knows no key "{{key}}".',
  deleteClientTitle: 'Delete this client?', deleteClientDescription: 'Its tokens stop working and it can no longer sign users in.',
  secret: 'Secret', secretHint: 'Hydra keeps only a hash: a new secret is the way to recover one.', secretOnce: 'Shown once — copy it now',
  rotateSecret: 'Rotate secret', rotateSecretTitle: 'Rotate the secret?', rotateSecretDescription: 'The current secret stops working at once.',

  subjectsTitle: 'Subjects', subjectsDescription: 'A user\'s consents to clients and login sessions. Revoking a consent invalidates the tokens issued under it.',
  subject: 'Subject', subjectHint: 'The subject (e.g. a Kratos identity id)', look: 'Show', consents: 'Consents', noConsents: 'No remembered consents.', scopes: 'Scopes',
  remembered: 'Remembered', granted: 'Granted', forever: 'for ever', forSeconds: 'for {{count}} s',
  revokeAllConsents: 'Revoke all consents', revokeAllConsentsTitle: 'Revoke every consent?', revokeAllConsentsDescription: 'Every client asks again; their tokens stop working.',
  revokeConsentTitle: 'Revoke this consent?', revokeConsentDescription: 'The client asks again; its tokens for this user stop working.',
  endLogins: 'End login sessions', endLoginsTitle: 'End every login session?', endLoginsDescription: 'The next authorization asks the user to log in again.',

  keysTitle: 'Signing keys', keysDescription: 'The keys Hydra signs ID tokens and JWT access tokens with. Rotation adds a key that signs from now on; older keys keep verifying until deleted.',
  keySet: 'Key set', alg: 'Algorithm', use: 'Use', kid: 'Key ID', signing: 'signs', noKeys: 'No keys.', keysFooter: 'Private parts never leave Hydra.',
  rotateKey: 'Rotate', rotateKeyTitle: 'Add a new signing key?', rotateKeyDescription: 'New tokens are signed with it; clients refresh the JWKS.',
  deleteKeyTitle: 'Delete this key?', deleteKeyDescription: 'Tokens it signed no longer verify.',

  issuersTitle: 'Trusted issuers', issuersDescription: 'Issuers whose signed JWTs Hydra accepts as authorization grants (RFC 7523).', noIssuers: 'No trusted issuers.',
  anySubject: 'any subject', trustIssuer: 'Trust an issuer', trustIssuerHint: 'Hydra\'s trustOAuth2JwtGrantIssuer JSON with the issuer\'s public key.', trust: 'Trust',
  deleteIssuerTitle: 'Stop trusting this issuer?', deleteIssuerDescription: 'Its grants are refused from now on.',

  tokensTitle: 'Tokens', tokensDescription: 'Inspect an access or refresh token.', introspect: 'Introspect', token: 'Token', claims: 'Claims',
};
