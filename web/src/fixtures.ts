import type { ClientConstructor, ClientRuntime, ClientState } from '@backplane-labs/backplane-client';
import { create, type Message } from '@bufbuild/protobuf';
import { timestampNow } from '@bufbuild/protobuf/wkt';
import { FakeSocket, type Interceptor, route, WsTransport } from '@gopherex/ws-proto-transport';
import {
  ClientSchema,
  GetClientResponseSchema,
  GetKeySetResponseSchema,
  GetOverlayResponseSchema,
  GetStatusResponseSchema,
  IntrospectResponseSchema,
  ListClientsResponseSchema,
  ListConsentsResponseSchema,
  ListTrustedIssuersResponseSchema,
} from './gen/proto/hydra/console/v1/admin_pb';

const state: ClientState = { connection: 'connected', session: null, connectionId: 1 };
const app = create(ClientSchema, {
  clientId: '3f2b0f0e-6c1a-4c55-9c1e-2c6f0b2a8d11',
  clientName: 'Shop web',
  grantTypes: ['authorization_code', 'refresh_token'],
  redirectUris: ['https://shop.example/cb'],
  scope: 'openid offline_access email',
  skipConsent: true,
  tokenEndpointAuthMethod: 'client_secret_basic',
  createdAt: timestampNow(),
  clientJson: JSON.stringify(
    {
      client_name: 'Shop web',
      grant_types: ['authorization_code', 'refresh_token'],
      redirect_uris: ['https://shop.example/cb'],
      skip_consent: true,
    },
    null,
    2,
  ),
});

/** The fixture answers by RPC route; the client is the real generated one over a fake socket. */
const fixtureInterceptor: Interceptor = () => (req) => {
  if (req.stream) throw new Error(`No fixture for stream ${route(req.method)}`);
  const answer: Record<string, () => Message> = {
    '/hydra.console.v1.AdminService/GetStatus': () =>
      create(GetStatusResponseSchema, {
        adminUrl: 'http://127.0.0.1:4445',
        publicUrl: 'http://127.0.0.1:4444',
        version: 'v26.2.0',
        consentUrl: 'https://auth.example.com/bp/consent',
        logoutUrl: 'https://auth.example.com/bp/logout',
        overlay: { path: '/etc/backplane/hydra.yml', hash: '9ab0c3d1', writtenAt: timestampNow() },
        discovery: { issuer: 'https://auth.example.com/', tokenEndpoint: 'https://auth.example.com/oauth2/token' },
        hooks: [
          { name: 'Consent', bound: true, description: 'Decides consents and adds the claims of their tokens' },
          { name: 'TokenClaims', bound: false, description: 'Sets the extra claims of every issued token' },
        ],
        callbacks: [
          { point: 'consent', calls: 42n, lastOutcome: 'accepted', lastAt: timestampNow(), lastLatencyMs: 23.4 },
        ],
      }),
    '/hydra.console.v1.AdminService/GetOverlay': () =>
      create(GetOverlayResponseSchema, { content: 'urls:\n  consent: https://auth.example.com/bp/consent\n' }),
    '/hydra.console.v1.AdminService/ListClients': () => create(ListClientsResponseSchema, { clients: [app] }),
    '/hydra.console.v1.AdminService/GetClient': () => create(GetClientResponseSchema, { client: app }),
    '/hydra.console.v1.AdminService/ListConsents': () =>
      create(ListConsentsResponseSchema, {
        consents: [
          {
            clientId: app.clientId,
            clientName: app.clientName,
            grantScope: ['openid', 'email'],
            remember: true,
            handledAt: timestampNow(),
          },
        ],
      }),
    '/hydra.console.v1.AdminService/GetKeySet': () =>
      create(GetKeySetResponseSchema, {
        keys: [
          { kid: 'b1f7…', alg: 'RS256', use: 'sig', kty: 'RSA' },
          { kid: '0a42…', alg: 'RS256', use: 'sig', kty: 'RSA' },
        ],
      }),
    '/hydra.console.v1.AdminService/ListTrustedIssuers': () =>
      create(ListTrustedIssuersResponseSchema, { issuers: [] }),
    '/hydra.console.v1.AdminService/Introspect': () =>
      create(IntrospectResponseSchema, {
        active: true,
        subject: 'user-1',
        clientId: app.clientId,
        scope: 'openid email',
        tokenUse: 'access_token',
        expiresAt: timestampNow(),
        extJson: '{"tenant":"acme"}',
      }),
  };
  const handler = answer[route(req.method)];
  if (handler === undefined) throw new Error(`No fixture for ${route(req.method)}`);
  return Promise.resolve({ stream: false, method: req.method, header: {}, message: handler(), trailer: {} });
};

/** Explicit local fixture of AdminService. */
export const fixtureClient: ClientRuntime = {
  getSnapshot: () => state,
  subscribe: () => () => {},
  client<T extends object>(clientConstructor: ClientConstructor<T>): T {
    if (!('getStatus' in clientConstructor.prototype)) throw new Error(`No fixture for ${clientConstructor.name}`);
    return new clientConstructor(WsTransport.fromSocket(new FakeSocket(), { interceptors: [fixtureInterceptor] }));
  },
};
