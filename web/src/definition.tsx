import { useEffect, useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { create } from '@bufbuild/protobuf';
import { timestampDate, type Timestamp as PbTimestamp } from '@bufbuild/protobuf/wkt';
import { useClient } from '@backplane-labs/backplane-react';
import { definePlugin, usePluginContext, usePluginNavigate } from '@backplane-labs/backplane-plugin-sdk';
import { ConnectionNotice, usePlatformAction, usePlatformQuery } from '@backplane-labs/backplane-platform-ui';
import { CodeEditor, type EditorDiagnostic } from '@backplane-labs/backplane-editors';
import {
  Badge, Button, ClipboardButton, ConfirmAction, DetailDrawer, EmptyState, Input, KeyValueList, NativeSelect, PageHeader, Panel, SearchInput,
  SecretInput, Skeleton, Stack, StatRow, StatTile, StatusBadge, Table, TableBody, TableCell, TableHead, TableHeader, TableRow, Timestamp,
} from '@backplane-labs/backplane-ui';
import { AdminServiceClient } from './gen/proto/hydra/console/v1/admin_ws_pb';
import {
  CreateClientRequestSchema, DeleteClientRequestSchema, DeleteKeyRequestSchema, DeleteTrustedIssuerRequestSchema, GetClientRequestSchema,
  GetKeySetRequestSchema, GetOverlayRequestSchema, GetStatusRequestSchema, IntrospectRequestSchema, ListClientsRequestSchema, ListConsentsRequestSchema,
  ListTrustedIssuersRequestSchema, RevokeConsentsRequestSchema, RevokeLoginSessionsRequestSchema, RotateClientSecretRequestSchema, RotateKeyRequestSchema,
  TrustIssuerRequestSchema, UpdateClientRequestSchema, type IntrospectResponse,
} from './gen/proto/hydra/console/v1/admin_pb';
import navigation from './navigation';

const mono = { fontFamily: 'var(--font-mono)' } as const;
const muted = { color: 'var(--muted-foreground)', fontSize: 12 } as const;
const date = (value?: PbTimestamp) => value ? timestampDate(value) : undefined;
function useText() { return useTranslation('module.hydra').t; }

function Loading() {
  const t = useText();
  return <Stack gap={8} style={{ padding: 12 }} role="status" aria-label={t('loading')}><Skeleton style={{ height: 28 }} /><Skeleton style={{ height: 28 }} /></Stack>;
}
function Failure({ error }: { error: unknown }) {
  const t = useText();
  return <EmptyState role="alert" title={t('error')} description={error instanceof Error ? error.message : String(error)} />;
}
function ActionError({ error }: { error: unknown }) {
  if (error === undefined) return null;
  return <span role="alert" style={{ color: 'var(--destructive)', fontSize: 12 }}>{error instanceof Error ? error.message : String(error)}</span>;
}
function Header({ title, description, actions }: { title: string; description: string; actions?: ReactNode }) {
  const t = useText(), context = usePluginContext();
  return <PageHeader title={title} description={description} meta={<Badge variant="outline">{t(context.environment)}</Badge>} actions={actions} />;
}

/** The installation: Hydra, the overlay, the hooks and the discovery document. */
function Overview() {
  const t = useText(), client = useClient(AdminServiceClient), { mode } = usePluginContext();
  const [tick, setTick] = useState(0);
  useEffect(() => { const id = setInterval(() => setTick((n) => n + 1), 10_000); return () => clearInterval(id); }, []);
  const status = usePlatformQuery(`hydra:status:${tick}`, (signal) => client.getStatus(create(GetStatusRequestSchema), { signal }), { keep: true });
  const overlay = usePlatformQuery(`hydra:overlay:${tick}`, (signal) => client.getOverlay(create(GetOverlayRequestSchema), { signal }), { keep: true });
  const s = status.value;
  return <Stack gap={16}><ConnectionNotice />
    <Header title={t('overviewTitle')} description={t('overviewDescription')} actions={<Button variant="outline" size="sm" onClick={() => { status.refresh(); overlay.refresh(); }}>{t('refresh')}</Button>} />
    {status.error !== undefined ? <Failure error={status.error} /> : !s ? <Loading /> : <>
      {s.problem && <p role="alert" style={{ margin: 0 }}><StatusBadge tone="danger">{t('hydraDown')}</StatusBadge> <span style={{ fontSize: 13 }}>{s.problem}</span></p>}
      {s.overlay?.error && <p role="alert" style={{ margin: 0 }}><StatusBadge tone="danger">{t('overlayRejected')}</StatusBadge> <span style={{ fontSize: 13 }}>{s.overlay.error}</span></p>}
      <StatRow>
        <StatTile label={t('hydra')} value={s.version || '—'} tone={s.problem ? 'danger' : 'success'} hint={<span style={mono}>{s.adminUrl}</span>} />
        <StatTile label={t('issuer')} value={s.discovery?.issuer || '—'} tone={s.discovery?.error ? 'danger' : 'neutral'} hint={s.discovery?.error || s.discovery?.tokenEndpoint} />
        <StatTile label={t('overlay')} value={s.overlay?.path ? (s.overlay.hash || '—') : t('snippets')} hint={s.overlay?.path ? <Timestamp value={date(s.overlay.writtenAt)} /> : t('snippetsHint')} />
      </StatRow>
      <Panel title={t('endpoints')} description={t('endpointsHint')}>
        <KeyValueList items={[{ label: t('consentUrl'), value: <span style={mono}>{s.consentUrl}</span> }, { label: t('logoutUrl'), value: <span style={mono}>{s.logoutUrl}</span> }]} />
      </Panel>
      <Panel title={t('hooks')} count={s.hooks.length} flush footer={<span style={muted}>{t('hooksFooter')}</span>}>
        <Table><TableBody>{s.hooks.map((h) => <TableRow key={h.name}><TableCell style={mono}>hydra.{h.name}</TableCell>
          <TableCell>{h.bound ? <StatusBadge tone="success">{t('isBound')}</StatusBadge> : <Badge variant="outline">{t('unbound')}</Badge>}</TableCell>
          <TableCell style={muted}>{h.description}</TableCell></TableRow>)}</TableBody></Table>
      </Panel>
      <Panel title={t('callbacks')} count={s.callbacks.length} flush>
        {!s.callbacks.length ? <EmptyState title={t('noCallbacks')} /> : <Table>
          <TableHeader><TableRow><TableHead>{t('point')}</TableHead><TableHead>{t('calls')}</TableHead><TableHead>{t('last')}</TableHead><TableHead>{t('outcome')}</TableHead></TableRow></TableHeader>
          <TableBody>{s.callbacks.map((c) => <TableRow key={c.point}><TableCell style={mono}>{c.point}</TableCell>
            <TableCell>{String(c.calls)}{c.failures > 0n && <span style={{ color: 'var(--destructive)' }}> · {t('failures', { count: Number(c.failures) })}</span>}</TableCell>
            <TableCell><Timestamp value={date(c.lastAt)} /> <span style={muted}>{c.lastLatencyMs.toFixed(1)} ms</span></TableCell>
            <TableCell><Badge variant="outline">{c.lastOutcome}</Badge> {c.lastError && <span style={{ ...muted, color: 'var(--destructive)' }}>{c.lastError}</span>}</TableCell></TableRow>)}</TableBody></Table>}
      </Panel>
      <Panel title={t('overlayContent')} description={t('overlayContentHint')}>
        {overlay.value?.error ? <p role="alert" style={{ margin: 0, color: 'var(--destructive)' }}>{overlay.value.error}</p>
          : <CodeEditor label={t('overlayContent')} value={overlay.value?.content ?? ''} language="yaml" mode={mode} readOnly height={320} />}
      </Panel>
    </>}
  </Stack>;
}

// ——— clients ———

const clientKeys = ['client_name', 'grant_types', 'response_types', 'redirect_uris', 'post_logout_redirect_uris', 'scope', 'audience', 'token_endpoint_auth_method',
  'skip_consent', 'skip_logout_consent', 'access_token_strategy', 'subject_type', 'owner', 'contacts', 'client_uri', 'logo_uri', 'policy_uri', 'tos_uri',
  'allowed_cors_origins', 'jwks_uri', 'frontchannel_logout_uri', 'backchannel_logout_uri', 'metadata'];

const scaffold = JSON.stringify({
  client_name: '', grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'], redirect_uris: ['https://app.example.com/callback'],
  scope: 'openid offline_access email', token_endpoint_auth_method: 'client_secret_basic', skip_consent: false,
}, null, 2);

/** Hydra's client JSON: scaffolded, its keys completed, checked. */
function ClientEditor({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  const t = useText(), { mode } = usePluginContext();
  return <CodeEditor label={t('clientJson')} value={value} onChange={onChange} language="json" mode={mode} height={320}
    complete={async ({ value: text, position }) => /[{,]\s*"[^"]*$/.test(text.slice(0, position)) ? clientKeys.map((k) => ({ label: k, apply: k })) : null}
    validate={async (text) => {
      let parsed: unknown;
      try { parsed = JSON.parse(text || '{}'); } catch (e) { return [{ from: 0, to: text.length, severity: 'error', message: e instanceof Error ? e.message : String(e) }]; }
      const out: EditorDiagnostic[] = [];
      if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return [{ from: 0, to: text.length, severity: 'error', message: t('clientObject') }];
      const c = parsed as Record<string, unknown>;
      if (Array.isArray(c.grant_types) && c.grant_types.includes('authorization_code') && !(Array.isArray(c.redirect_uris) && c.redirect_uris.length))
        out.push({ from: 0, to: 1, severity: 'error', message: t('redirectRequired') });
      for (const key of Object.keys(c)) if (!clientKeys.includes(key) && key !== 'client_id' && key !== 'created_at' && key !== 'updated_at' && !key.endsWith('_lifespan')) {
        const at = text.indexOf(`"${key}"`); out.push({ from: Math.max(0, at), to: Math.max(0, at) + key.length + 2, severity: 'warning', message: t('unknownKey', { key }) });
      }
      return out;
    }} />;
}

function Secret({ secret }: { secret: string }) {
  const t = useText();
  return <Stack gap={4}><StatusBadge tone="warning">{t('secretOnce')}</StatusBadge>
    <Stack direction="row" gap={8} style={{ alignItems: 'center' }}><span style={{ ...mono, wordBreak: 'break-all' }}>{secret}</span><ClipboardButton value={secret} /></Stack></Stack>;
}

function Clients() {
  const t = useText(), client = useClient(AdminServiceClient);
  const [name, setName] = useState(''), [applied, setApplied] = useState(''), [pages, setPages] = useState<string[]>(['']), [open, setOpen] = useState<string>(), [creating, setCreating] = useState(false);
  const page = pages[pages.length - 1] ?? '';
  useEffect(() => { const id = setTimeout(() => { setApplied(name.trim()); setPages(['']); }, 300); return () => clearTimeout(id); }, [name]);
  const list = usePlatformQuery(`hydra:clients:${applied}:${page}`, (signal) => client.listClients(create(ListClientsRequestSchema, { name: applied, pageToken: page, pageSize: 50 }), { signal }), { keep: true });
  return <Stack gap={16}><ConnectionNotice />
    <Header title={t('clientsTitle')} description={t('clientsDescription')} actions={<Stack direction="row" gap={8}><Button size="sm" onClick={() => setCreating(true)}>{t('newClient')}</Button><Button variant="outline" size="sm" onClick={list.refresh}>{t('refresh')}</Button></Stack>} />
    <SearchInput value={name} onValueChange={setName} label={t('searchClients')} placeholder={t('searchClients')} />
    <Panel title={t('clients')} count={list.value?.clients.length} flush footer={<Stack direction="row" gap={8}>
      <Button size="sm" variant="outline" disabled={pages.length < 2} onClick={() => setPages(pages.slice(0, -1))}>{t('previous')}</Button>
      <Button size="sm" variant="outline" disabled={!list.value?.nextPageToken} onClick={() => list.value && setPages([...pages, list.value.nextPageToken])}>{t('next')}</Button></Stack>}>
      {list.error !== undefined ? <Failure error={list.error} /> : !list.value ? <Loading /> : !list.value.clients.length ? <EmptyState title={t('noClients')} />
        : <Table><TableHeader><TableRow><TableHead>{t('client')}</TableHead><TableHead>{t('grants')}</TableHead><TableHead>{t('auth')}</TableHead><TableHead>{t('consent')}</TableHead><TableHead>{t('created')}</TableHead></TableRow></TableHeader>
          <TableBody>{list.value.clients.map((c) => <TableRow key={c.clientId} style={{ cursor: 'pointer' }} onClick={() => setOpen(c.clientId)}>
            <TableCell><Stack gap={2}><span>{c.clientName || '—'}</span><span style={{ ...muted, ...mono }}>{c.clientId}</span></Stack></TableCell>
            <TableCell><Stack direction="row" gap={4}>{c.grantTypes.map((g) => <Badge key={g} variant="outline">{g}</Badge>)}</Stack></TableCell>
            <TableCell style={mono}>{c.tokenEndpointAuthMethod}</TableCell>
            <TableCell>{c.skipConsent ? <StatusBadge tone="success">{t('trusted')}</StatusBadge> : <Badge variant="outline">{t('asks')}</Badge>}</TableCell>
            <TableCell><Timestamp value={date(c.createdAt)} /></TableCell></TableRow>)}</TableBody></Table>}
    </Panel>
    {open && <ClientCard id={open} onClose={() => setOpen(undefined)} onChanged={list.refresh} />}
    {creating && <CreateClient onClose={() => setCreating(false)} onCreated={list.refresh} />}
  </Stack>;
}

function ClientCard({ id, onClose, onChanged }: { id: string; onClose: () => void; onChanged: () => void }) {
  const t = useText(), client = useClient(AdminServiceClient), save = usePlatformAction<void>(), rotate = usePlatformAction<string>();
  const card = usePlatformQuery(`hydra:client:${id}`, (signal) => client.getClient(create(GetClientRequestSchema, { clientId: id }), { signal }));
  const [json, setJson] = useState('');
  useEffect(() => { if (card.value?.client) setJson(card.value.client.clientJson); }, [card.value]);
  const c = card.value?.client;
  return <DetailDrawer open onOpenChange={(o) => !o && onClose()} size="lg" title={c?.clientName || id} description={<span style={mono}>{id}</span>}
    actions={<ConfirmAction trigger={<Button size="sm" variant="destructive">{t('delete')}</Button>} title={t('deleteClientTitle')} description={t('deleteClientDescription')} confirmLabel={t('delete')}
      onConfirm={async (signal) => { await client.deleteClient(create(DeleteClientRequestSchema, { clientId: id }), { signal }); onChanged(); onClose(); }} />}>
    {card.error !== undefined ? <Failure error={card.error} /> : !c ? <Loading /> : <Stack gap={16}>
      <Panel title={t('client')} actions={<Stack direction="row" gap={8} style={{ alignItems: 'center' }}><ActionError error={save.error} />
        <Button size="sm" disabled={save.pending} onClick={() => void save.run(async (signal) => { await client.updateClient(create(UpdateClientRequestSchema, { clientId: id, clientJson: json }), { signal }); card.refresh(); onChanged(); })}>{save.pending ? t('saving') : t('save')}</Button></Stack>}>
        <ClientEditor value={json} onChange={setJson} />
      </Panel>
      <Panel title={t('secret')} description={t('secretHint')}>
        {rotate.value ? <Secret secret={rotate.value} /> : <Stack direction="row" gap={8} style={{ alignItems: 'center' }}>
          <ConfirmAction trigger={<Button size="sm" variant="outline">{t('rotateSecret')}</Button>} title={t('rotateSecretTitle')} description={t('rotateSecretDescription')} confirmLabel={t('rotateSecret')}
            onConfirm={async () => { await rotate.run(async (signal) => (await client.rotateClientSecret(create(RotateClientSecretRequestSchema, { clientId: id }), { signal })).clientSecret); }} />
          <ActionError error={rotate.error} /></Stack>}
      </Panel>
    </Stack>}
  </DetailDrawer>;
}

function CreateClient({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const t = useText(), client = useClient(AdminServiceClient), make = usePlatformAction<{ id: string; secret: string }>();
  const [json, setJson] = useState(scaffold);
  return <DetailDrawer open onOpenChange={(o) => !o && onClose()} size="lg" title={t('newClient')} description={t('newClientHint')}>
    <Stack gap={12}>
      {make.value ? <Stack gap={8}><KeyValueList items={[{ label: t('clientId'), value: <span style={mono}>{make.value.id}</span> }]} />{make.value.secret && <Secret secret={make.value.secret} />}</Stack> : <>
        <ClientEditor value={json} onChange={setJson} />
        <Stack direction="row" gap={8} style={{ alignItems: 'center' }}>
          <Button size="sm" disabled={make.pending} onClick={() => void make.run(async (signal) => {
            const res = await client.createClient(create(CreateClientRequestSchema, { clientJson: json }), { signal }); onCreated();
            return { id: res.client?.clientId ?? '', secret: res.clientSecret };
          })}>{make.pending ? t('creating') : t('create')}</Button><ActionError error={make.error} />
        </Stack></>}
    </Stack>
  </DetailDrawer>;
}

// ——— subjects ———

function Subjects() {
  const t = useText(), client = useClient(AdminServiceClient);
  const [subject, setSubject] = useState(''), [applied, setApplied] = useState('');
  const list = usePlatformQuery(`hydra:consents:${applied}`, (signal) => applied ? client.listConsents(create(ListConsentsRequestSchema, { subject: applied }), { signal }) : Promise.resolve(undefined), { keep: true });
  return <Stack gap={16}><ConnectionNotice />
    <Header title={t('subjectsTitle')} description={t('subjectsDescription')} />
    <Stack direction="row" gap={8}><Input aria-label={t('subject')} placeholder={t('subjectHint')} value={subject} onChange={(e) => setSubject(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && setApplied(subject.trim())} style={{ maxWidth: 420 }} />
      <Button size="sm" onClick={() => setApplied(subject.trim())}>{t('look')}</Button></Stack>
    {applied && <Panel title={t('consents')} count={list.value?.consents.length} flush actions={<Stack direction="row" gap={8}>
      <ConfirmAction trigger={<Button size="sm" variant="outline">{t('revokeAllConsents')}</Button>} title={t('revokeAllConsentsTitle')} description={t('revokeAllConsentsDescription')} confirmLabel={t('revoke')}
        onConfirm={async (signal) => { await client.revokeConsents(create(RevokeConsentsRequestSchema, { subject: applied }), { signal }); list.refresh(); }} />
      <ConfirmAction trigger={<Button size="sm" variant="outline">{t('endLogins')}</Button>} title={t('endLoginsTitle')} description={t('endLoginsDescription')} confirmLabel={t('endLogins')}
        onConfirm={async (signal) => { await client.revokeLoginSessions(create(RevokeLoginSessionsRequestSchema, { subject: applied }), { signal }); }} /></Stack>}>
      {list.error !== undefined ? <Failure error={list.error} /> : !list.value ? <Loading /> : !list.value.consents.length ? <EmptyState title={t('noConsents')} />
        : <Table><TableHeader><TableRow><TableHead>{t('client')}</TableHead><TableHead>{t('scopes')}</TableHead><TableHead>{t('remembered')}</TableHead><TableHead>{t('granted')}</TableHead><TableHead /></TableRow></TableHeader>
          <TableBody>{list.value.consents.map((c) => <TableRow key={c.clientId}>
            <TableCell><Stack gap={2}><span>{c.clientName || '—'}</span><span style={{ ...muted, ...mono }}>{c.clientId}</span></Stack></TableCell>
            <TableCell><Stack direction="row" gap={4}>{c.grantScope.map((s) => <Badge key={s} variant="outline">{s}</Badge>)}</Stack></TableCell>
            <TableCell>{c.remember ? (c.rememberFor ? t('forSeconds', { count: Number(c.rememberFor) }) : t('forever')) : t('no')}</TableCell>
            <TableCell><Timestamp value={date(c.handledAt)} /></TableCell>
            <TableCell style={{ textAlign: 'right' }}><ConfirmAction trigger={<Button size="sm" variant="outline">{t('revoke')}</Button>} title={t('revokeConsentTitle')} description={t('revokeConsentDescription')} confirmLabel={t('revoke')}
              onConfirm={async (signal) => { await client.revokeConsents(create(RevokeConsentsRequestSchema, { subject: applied, clientId: c.clientId }), { signal }); list.refresh(); }} /></TableCell>
          </TableRow>)}</TableBody></Table>}
    </Panel>}
  </Stack>;
}

// ——— keys ———

const sets = ['hydra.openid.id-token', 'hydra.jwt.access-token'] as const;

function Keys() {
  const t = useText(), client = useClient(AdminServiceClient);
  const [set, setSet] = useState<string>(sets[0]), [alg, setAlg] = useState('RS256');
  const keys = usePlatformQuery(`hydra:keys:${set}`, (signal) => client.getKeySet(create(GetKeySetRequestSchema, { set }), { signal }), { keep: true });
  const rotate = usePlatformAction<void>();
  return <Stack gap={16}><ConnectionNotice />
    <Header title={t('keysTitle')} description={t('keysDescription')} />
    <Stack direction="row" gap={8} style={{ alignItems: 'center' }}>
      <NativeSelect aria-label={t('keySet')} value={set} onChange={(e) => setSet(e.target.value)}>{sets.map((s) => <option key={s} value={s}>{s}</option>)}</NativeSelect>
      <NativeSelect aria-label={t('alg')} value={alg} onChange={(e) => setAlg(e.target.value)}>{['RS256', 'ES256', 'ES512', 'EdDSA'].map((a) => <option key={a} value={a}>{a}</option>)}</NativeSelect>
      <ConfirmAction trigger={<Button size="sm">{t('rotateKey')}</Button>} title={t('rotateKeyTitle')} description={t('rotateKeyDescription')} confirmLabel={t('rotateKey')}
        onConfirm={async () => { await rotate.run(async (signal) => { await client.rotateKey(create(RotateKeyRequestSchema, { set, alg }), { signal }); keys.refresh(); }); }} />
      <ActionError error={rotate.error} />
    </Stack>
    <Panel title={set} count={keys.value?.keys.length} flush footer={<span style={muted}>{t('keysFooter')}</span>}>
      {keys.error !== undefined ? <Failure error={keys.error} /> : !keys.value ? <Loading /> : !keys.value.keys.length ? <EmptyState title={t('noKeys')} />
        : <Table><TableHeader><TableRow><TableHead>{t('kid')}</TableHead><TableHead>{t('alg')}</TableHead><TableHead>{t('use')}</TableHead><TableHead /></TableRow></TableHeader>
          <TableBody>{keys.value.keys.map((k, i) => <TableRow key={k.kid}><TableCell style={mono}>{k.kid}{i === 0 && <Badge variant="outline" style={{ marginLeft: 8 }}>{t('signing')}</Badge>}</TableCell>
            <TableCell>{k.alg}</TableCell><TableCell>{k.use}</TableCell>
            <TableCell style={{ textAlign: 'right' }}>{keys.value!.keys.length > 1 && <ConfirmAction trigger={<Button size="sm" variant="outline">{t('delete')}</Button>} title={t('deleteKeyTitle')} description={t('deleteKeyDescription')} confirmLabel={t('delete')}
              onConfirm={async (signal) => { await client.deleteKey(create(DeleteKeyRequestSchema, { set, kid: k.kid }), { signal }); keys.refresh(); }} />}</TableCell></TableRow>)}</TableBody></Table>}
    </Panel>
  </Stack>;
}

// ——— trusted issuers ———

const issuerScaffold = JSON.stringify({ issuer: 'https://partner.example.com', subject: '', allow_any_subject: false, scope: ['api'], expires_at: '2027-01-01T00:00:00Z', jwk: { kty: 'RSA', kid: '', alg: 'RS256', use: 'sig', n: '', e: 'AQAB' } }, null, 2);

function Issuers() {
  const t = useText(), client = useClient(AdminServiceClient), { mode } = usePluginContext();
  const list = usePlatformQuery('hydra:issuers', (signal) => client.listTrustedIssuers(create(ListTrustedIssuersRequestSchema), { signal }), { keep: true });
  const [json, setJson] = useState(issuerScaffold), trust = usePlatformAction<void>();
  return <Stack gap={16}><ConnectionNotice />
    <Header title={t('issuersTitle')} description={t('issuersDescription')} />
    <Panel title={t('issuers')} count={list.value?.issuers.length} flush>
      {list.error !== undefined ? <Failure error={list.error} /> : !list.value ? <Loading /> : !list.value.issuers.length ? <EmptyState title={t('noIssuers')} />
        : <Table><TableHeader><TableRow><TableHead>{t('issuer')}</TableHead><TableHead>{t('subject')}</TableHead><TableHead>{t('scopes')}</TableHead><TableHead>{t('expires')}</TableHead><TableHead /></TableRow></TableHeader>
          <TableBody>{list.value.issuers.map((i) => <TableRow key={i.id}><TableCell style={mono}>{i.issuer}</TableCell><TableCell>{i.allowAnySubject ? t('anySubject') : i.subject}</TableCell>
            <TableCell><Stack direction="row" gap={4}>{i.scope.map((s) => <Badge key={s} variant="outline">{s}</Badge>)}</Stack></TableCell><TableCell><Timestamp value={date(i.expiresAt)} /></TableCell>
            <TableCell style={{ textAlign: 'right' }}><ConfirmAction trigger={<Button size="sm" variant="outline">{t('delete')}</Button>} title={t('deleteIssuerTitle')} description={t('deleteIssuerDescription')} confirmLabel={t('delete')}
              onConfirm={async (signal) => { await client.deleteTrustedIssuer(create(DeleteTrustedIssuerRequestSchema, { id: i.id }), { signal }); list.refresh(); }} /></TableCell></TableRow>)}</TableBody></Table>}
    </Panel>
    <Panel title={t('trustIssuer')} description={t('trustIssuerHint')} actions={<Stack direction="row" gap={8} style={{ alignItems: 'center' }}><ActionError error={trust.error} />
      <Button size="sm" disabled={trust.pending} onClick={() => void trust.run(async (signal) => { await client.trustIssuer(create(TrustIssuerRequestSchema, { issuerJson: json }), { signal }); list.refresh(); })}>{t('trust')}</Button></Stack>}>
      <CodeEditor label={t('trustIssuer')} value={json} onChange={setJson} language="json" mode={mode} height={240} />
    </Panel>
  </Stack>;
}

// ——— tokens ———

function Tokens() {
  const t = useText(), client = useClient(AdminServiceClient), { mode } = usePluginContext();
  const [token, setToken] = useState(''), inspect = usePlatformAction<IntrospectResponse>();
  const v = inspect.value;
  return <Stack gap={16}><ConnectionNotice />
    <Header title={t('tokensTitle')} description={t('tokensDescription')} />
    <Panel title={t('introspect')}>
      <Stack gap={8}>
        <SecretInput label={t('token')} value={token} onValueChange={setToken} />
        <Stack direction="row" gap={8} style={{ alignItems: 'center' }}><Button size="sm" disabled={!token || inspect.pending}
          onClick={() => void inspect.run((signal) => client.introspect(create(IntrospectRequestSchema, { token }), { signal }))}>{t('introspect')}</Button><ActionError error={inspect.error} /></Stack>
        {v && <Stack gap={8}><KeyValueList items={[
          { label: t('state'), value: v.active ? <StatusBadge tone="success">{t('active')}</StatusBadge> : <StatusBadge tone="danger">{t('inactive')}</StatusBadge> },
          { label: t('subject'), value: v.subject || '—' }, { label: t('clientId'), value: v.clientId || '—' }, { label: t('scopes'), value: v.scope || '—' },
          { label: t('use'), value: v.tokenUse || '—' }, { label: t('expires'), value: <Timestamp value={date(v.expiresAt)} absolute /> },
        ]} />{v.extJson && <CodeEditor label={t('claims')} value={JSON.stringify(JSON.parse(v.extJson), null, 2)} language="json" mode={mode} readOnly height={160} />}</Stack>}
      </Stack>
    </Panel>
  </Stack>;
}

function Missing() {
  const t = useText(), navigate = usePluginNavigate();
  return <Panel><EmptyState title={<h1 style={{ margin: 0, fontSize: 16, fontWeight: 500 }}>{t('missing')}</h1>} action={<Button size="sm" variant="outline" onClick={() => navigate('')}>{t('back')}</Button>} /></Panel>;
}

export const definition = definePlugin({
  ...navigation,
  routes: [
    { index: true, element: <Overview /> }, { path: 'clients', element: <Clients /> }, { path: 'subjects', element: <Subjects /> },
    { path: 'keys', element: <Keys /> }, { path: 'issuers', element: <Issuers /> }, { path: 'tokens', element: <Tokens /> }, { path: '*', element: <Missing /> },
  ],
});
