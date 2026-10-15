import { create } from '@bufbuild/protobuf';
import { timestampNow } from '@bufbuild/protobuf/wkt';
import type { ClientRuntime, ClientConstructor, ClientState } from '@backplane-labs/backplane-client';
import {
  ClientSchema, GetClientResponseSchema, GetKeySetResponseSchema, GetOverlayResponseSchema, GetStatusResponseSchema, IntrospectResponseSchema,
  ListClientsResponseSchema, ListConsentsResponseSchema, ListTrustedIssuersResponseSchema,
} from './gen/proto/hydra/console/v1/admin_pb';

const state: ClientState = { connection: 'connected', session: null, connectionId: 1 };
const app = create(ClientSchema, {
  clientId: '3f2b0f0e-6c1a-4c55-9c1e-2c6f0b2a8d11', clientName: 'Shop web', grantTypes: ['authorization_code', 'refresh_token'], redirectUris: ['https://shop.example/cb'],
  scope: 'openid offline_access email', skipConsent: true, tokenEndpointAuthMethod: 'client_secret_basic', createdAt: timestampNow(),
  clientJson: JSON.stringify({ client_name: 'Shop web', grant_types: ['authorization_code', 'refresh_token'], redirect_uris: ['https://shop.example/cb'], skip_consent: true }, null, 2),
});

/** Explicit local fixture of AdminService. */
export const fixtureClient: ClientRuntime = {
  getSnapshot: () => state, subscribe: () => () => {},
  client<T extends object>(constructor: ClientConstructor<T>): T {
    if (!('getStatus' in constructor.prototype)) throw new Error(`No fixture for ${constructor.name}`);
    return {
      async getStatus() { return create(GetStatusResponseSchema, {
        adminUrl: 'http://127.0.0.1:4445', publicUrl: 'http://127.0.0.1:4444', version: 'v26.2.0', consentUrl: 'https://auth.example.com/bp/consent', logoutUrl: 'https://auth.example.com/bp/logout',
        overlay: { path: '/etc/backplane/hydra.yml', hash: '9ab0c3d1', writtenAt: timestampNow() }, discovery: { issuer: 'https://auth.example.com/', tokenEndpoint: 'https://auth.example.com/oauth2/token' },
        hooks: [{ name: 'Consent', bound: true, description: 'Decides consents and adds the claims of their tokens' }, { name: 'TokenClaims', bound: false, description: 'Sets the extra claims of every issued token' }],
        callbacks: [{ point: 'consent', calls: 42n, lastOutcome: 'accepted', lastAt: timestampNow(), lastLatencyMs: 23.4 }],
      }); },
      async getOverlay() { return create(GetOverlayResponseSchema, { content: 'urls:\n  consent: https://auth.example.com/bp/consent\n' }); },
      async listClients() { return create(ListClientsResponseSchema, { clients: [app] }); },
      async getClient() { return create(GetClientResponseSchema, { client: app }); },
      async listConsents() { return create(ListConsentsResponseSchema, { consents: [{ clientId: app.clientId, clientName: app.clientName, grantScope: ['openid', 'email'], remember: true, handledAt: timestampNow() }] }); },
      async getKeySet() { return create(GetKeySetResponseSchema, { keys: [{ kid: 'b1f7…', alg: 'RS256', use: 'sig', kty: 'RSA' }, { kid: '0a42…', alg: 'RS256', use: 'sig', kty: 'RSA' }] }); },
      async listTrustedIssuers() { return create(ListTrustedIssuersResponseSchema, { issuers: [] }); },
      async introspect() { return create(IntrospectResponseSchema, { active: true, subject: 'user-1', clientId: app.clientId, scope: 'openid email', tokenUse: 'access_token', expiresAt: timestampNow(), extJson: '{"tenant":"acme"}' }); },
    } as unknown as T;
  },
};
