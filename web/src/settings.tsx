import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { usePluginContext } from '@backplane-labs/backplane-plugin-sdk';
import { ConnectionNotice } from '@backplane-labs/backplane-platform-ui';
import { CodeEditor } from '@backplane-labs/backplane-editors';
import { Badge, Button, EmptyState, PageHeader, Panel, SecretInput, Skeleton, Stack, StatusBadge } from '@backplane-labs/backplane-ui';
import { Choice, Duration, Lines, NumberField, Row, SaveBar, Text, Toggle, useLiveConfig } from './settings-kit';

const S = 'settings';
const durationFields = ['ttl.access_token', 'ttl.refresh_token', 'ttl.id_token', 'ttl.auth_code', 'ttl.login_consent_request', 'ttl.authentication_session',
  'consent.remember_for', 'refresh.rotation_grace_period'] as const;

function useText() { return useTranslation('module.hydra').t; }

/** Hydra's settings: written to the overlay Hydra reloads, as a revision of this service's configuration. */
export function Settings() {
  const t = useText(), cfg = useLiveConfig('hydra', { settings: durationFields }), { mode } = usePluginContext();
  const [salt, setSalt] = useState('');
  const labels = {
    comment: t('changeComment'), validate: t('validate'), save: t('saveRevision'), saving: t('saving'), reset: t('reset'),
    valid: t('valid'), saved: t('savedRevision'), unsaved: t('unsaved'), revision: t('revision'),
  };
  const overrides = cfg.get(S, 'overrides');
  return <Stack gap={16}><ConnectionNotice />
    <PageHeader title={t('settingsTitle')} description={t('settingsDescription')} />
    {cfg.error !== undefined ? <EmptyState role="alert" title={t('error')} /> : cfg.loading
      ? <Stack gap={8} role="status" aria-label={t('loading')}><Skeleton style={{ height: 120 }} /></Stack> : <>
        <SaveBar cfg={cfg} labels={labels} />
        <Panel title={t('urlsSection')} description={t('urlsHint')}>
          <Text cfg={cfg} path={S} field="issuer" label={t('issuer')} placeholder="https://auth.example.com/" />
          <Text cfg={cfg} path={S} field="login_url" label={t('loginUrl')} placeholder="https://app.example.com/login" />
          <Text cfg={cfg} path={S} field="registration_url" label={t('registrationUrl')} />
          <Text cfg={cfg} path={S} field="error_url" label={t('errorUrl')} />
          <Text cfg={cfg} path={S} field="post_logout_redirect" label={t('postLogout')} />
        </Panel>
        <Panel title={t('consentSection')} description={t('consentHint')}>
          <Text cfg={cfg} path={S} field="consent.ui_url" label={t('consentUi')} hint={t('consentUiHint')} />
          <Duration cfg={cfg} path={S} field="consent.remember_for" label={t('rememberFor')} hint={t('rememberForHint')} />
        </Panel>
        <Panel title={t('ttlSection')}>
          <Duration cfg={cfg} path={S} field="ttl.access_token" label={t('ttlAccess')} />
          <Duration cfg={cfg} path={S} field="ttl.refresh_token" label={t('ttlRefresh')} />
          <Duration cfg={cfg} path={S} field="ttl.id_token" label={t('ttlId')} />
          <Duration cfg={cfg} path={S} field="ttl.auth_code" label={t('ttlCode')} />
          <Duration cfg={cfg} path={S} field="ttl.login_consent_request" label={t('ttlRequest')} />
          <Duration cfg={cfg} path={S} field="ttl.authentication_session" label={t('ttlSession')} hint={t('ttlSessionHint')} />
        </Panel>
        <Panel title={t('tokensSection')}>
          <Choice cfg={cfg} path={S} field="tokens.access_token" label={t('accessTokenKind')} options={['opaque', 'jwt']} />
          <Choice cfg={cfg} path={S} field="tokens.scope" label={t('scopeMatching')} options={['wildcard', 'exact']} />
          <Toggle cfg={cfg} path={S} field="pkce.enforced" label={t('pkce')} />
          <Toggle cfg={cfg} path={S} field="pkce.enforced_for_public_clients" label={t('pkcePublic')} />
          <Toggle cfg={cfg} path={S} field="claims.mirror_top_level" label={t('mirror')} />
          <Lines cfg={cfg} path={S} field="claims.allowed_top_level" label={t('topLevel')} hint={t('onePerLine')} />
          <Toggle cfg={cfg} path={S} field="claims.client_credentials_default_scope" label={t('ccScope')} />
          <Toggle cfg={cfg} path={S} field="claims.expose_internal_errors" label={t('exposeErrors')} />
          <Duration cfg={cfg} path={S} field="refresh.rotation_grace_period" label={t('graceTime')} hint={t('graceHint')} />
          <NumberField cfg={cfg} path={S} field="refresh.rotation_grace_reuse_count" label={t('graceReuse')} min={0} />
        </Panel>
        <Panel title={t('oidcSection')}>
          <Toggle cfg={cfg} path={S} field="oidc.dynamic_client_registration" label={t('dcr')} />
          <Lines cfg={cfg} path={S} field="oidc.subject_types" label={t('subjectTypes')} hint={t('subjectTypesHint')} />
          <Row label={t('pairwiseSalt')} hint={t('pairwiseSaltHint')}><Stack gap={8}>
            {cfg.get('pairwise_salt') ? <StatusBadge tone="success">{t('secretSet')}</StatusBadge> : <Badge variant="outline">{t('secretMissing')}</Badge>}
            <Stack direction="row" gap={8}><SecretInput label={t('pairwiseSalt')} value={salt} onValueChange={setSalt} />
              <Button size="sm" variant="outline" disabled={salt.length < 16} onClick={() => cfg.set('pairwise_salt', undefined, salt)}>{t('stageSecret')}</Button></Stack>
          </Stack></Row>
        </Panel>
        <Panel title={t('overridesSection')} description={t('overridesHint')}>
          <CodeEditor label={t('overridesSection')} value={typeof overrides === 'string' ? overrides : ''} onChange={(v) => cfg.set(S, 'overrides', v || undefined)} language="yaml" mode={mode} height={160} />
        </Panel>
        <SaveBar cfg={cfg} labels={labels} />
      </>}
  </Stack>;
}
