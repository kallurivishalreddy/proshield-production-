import React, { useMemo, useState } from 'react';
import {
  X,
  Cpu,
  ArrowRight,
  ArrowLeft,
  CheckCircle,
  AlertTriangle,
  ShieldCheck,
  Copy,
  KeyRound,
  Layers
} from 'lucide-react';
import { useSoc } from '../../context/SocContext';

/**
 * Phase 5.2 — Source Architecture 2.0: the six-step source workflow.
 *
 *   1 Identity → 2 Capability → 3 Connection → 4 Credentials →
 *   5 Validation → 6 Enable & Verify
 *
 * Every step drives the REAL backend:
 *   source.list_types / capability.list  (real catalogues, no hardcoding)
 *   source.register (+ explicit capability_id / mapping_profile_id)
 *   source.configure → source.validate → source.enable
 *   source.issue_token (single-use `sit-…`, shown ONCE in a dismissible
 *   credential panel — never in a toast)
 *
 * Truthfulness rules enforced here:
 *  • the capability picker lists only REAL registry rows the backend would
 *    actually accept (status `active`, implementation_ref ≠ `planned`);
 *  • the connector `source_type` is derived from the capability's own
 *    `implementation_ref`, so source and capability identity cannot drift;
 *  • the wizard never advances past a step the backend rejected.
 */
export const AddSourceModal: React.FC = () => {
  const {
    isAddSourceModalOpen,
    setAddSourceModalOpen,
    registryCapabilities,
    capabilityError,
    capabilities,
    addSource
  } = useSoc();

  const [step, setStep] = useState<1 | 2 | 3 | 4 | 5 | 6>(1);
  const [deploying, setDeploying] = useState(false);
  const [deployError, setDeployError] = useState<string | null>(null);
  const [issuedToken, setIssuedToken] = useState<string | null>(null);
  const [newHumanId, setNewHumanId] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  // ---- form state -------------------------------------------------------
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [tagsInput, setTagsInput] = useState('');
  const [capabilityId, setCapabilityId] = useState('');
  const [mappingProfileId, setMappingProfileId] = useState('');
  const [endpoint, setEndpoint] = useState('');
  const [destination, setDestination] = useState('');
  const [assetTagsInput, setAssetTagsInput] = useState('');

  // The real supported connector types (source.list_types) — used to
  // cross-check that a capability's implementation is actually runnable.
  const supportedTypes = useMemo(
    () => new Set(capabilities.map(c => c.name)),
    [capabilities]
  );

  // Bindable capabilities: exactly the rule the backend enforces
  // (BINDABLE_CAPABILITY_STATUSES = {active} and implementation_ref ≠ planned).
  const bindable = useMemo(
    () =>
      registryCapabilities.filter(
        c =>
          c.status === 'active' &&
          c.implementation_ref !== 'planned' &&
          supportedTypes.has(c.implementation_ref)
      ),
    [registryCapabilities, supportedTypes]
  );

  const selectedCapability = registryCapabilities.find(c => c.capability_id === capabilityId);
  // The connector type is the capability's OWN implementation_ref: the single
  // link between capability identity and source identity.
  const sourceType = selectedCapability ? selectedCapability.implementation_ref : '';

  // Mapping profiles the selected capability declares FOR THIS source type.
  const profilesForType = useMemo(() => {
    if (!selectedCapability) return [];
    return (selectedCapability.mapping_profiles || []).filter(
      p => p.source_type === sourceType
    );
  }, [selectedCapability, sourceType]);

  if (!isAddSourceModalOpen) return null;

  const handleDeploy = async (enable: boolean) => {
    setDeploying(true);
    setDeployError(null);
    const tags = tagsInput.split(',').map(t => t.trim()).filter(Boolean);
    const assetTags = assetTagsInput.split(',').map(t => t.trim()).filter(Boolean);
    const res = await addSource({
      name: name || 'Unnamed source',
      description: description || undefined,
      sourceType,
      capabilityId: capabilityId || undefined,
      mappingProfileId: mappingProfileId || null,
      endpoint: endpoint || undefined,
      tags: [...tags, ...assetTags],
      enable
    });
    setDeploying(false);
    if (res.ok) {
      setIssuedToken(res.token);
      if (res.sourceInstanceId) setNewHumanId(res.sourceInstanceId);
      setStep(6);
    } else {
      // The backend's own safe message, never a generic "something failed".
      setDeployError(
        res.error ||
          'The backend rejected a lifecycle step. The source was NOT fully deployed.'
      );
    }
  };

  const handleReset = () => {
    setAddSourceModalOpen(false);
    setTimeout(() => {
      setStep(1);
      setName('');
      setDescription('');
      setTagsInput('');
      setEndpoint('');
      setDestination('');
      setAssetTagsInput('');
      setDeployError(null);
      setCapabilityId('');
      setMappingProfileId('');
      setIssuedToken(null);
      setNewHumanId(null);
      setCopied(false);
    }, 200);
  };

  const copyToken = async () => {
    if (!issuedToken) return;
    try {
      await navigator.clipboard.writeText(issuedToken);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      setCopied(false);
    }
  };

  const stepsList = [
    { num: 1, label: 'Identity', why: 'Name this instance so analysts can find it later.' },
    { num: 2, label: 'Capability', why: 'Choose the capability that owns this instance.' },
    { num: 3, label: 'Connection', why: 'Tell ProShield where telemetry comes from.' },
    { num: 4, label: 'Credentials', why: 'How this instance proves its identity to the ingress.' },
    { num: 5, label: 'Validation', why: 'Review, then run the real backend lifecycle.' },
    { num: 6, label: 'Enable & verify', why: 'Confirm the source is enabled and ready.' },
  ];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div
        data-testid="source-wizard"
        data-wizard-step={step}
        className="relative w-full max-w-2xl rounded-xl bg-[#0F1420] border border-slate-700 shadow-2xl overflow-hidden"
      >
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-slate-800 bg-[#0A0D15]">
          <div className="flex items-center gap-2.5">
            <div className="p-1.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-500/30">
              <Cpu className="w-4 h-4" />
            </div>
            <div>
              <span className="text-[10px] font-mono font-semibold uppercase tracking-wider text-slate-400">
                Step {step} of 6 · Connected
              </span>
              <h3 className="text-sm font-semibold text-slate-100">
                Add source
              </h3>
              <p className="text-[11px] text-slate-400 mt-0.5">{stepsList[step - 1].why}</p>
            </div>
          </div>
          <button
            onClick={handleReset}
            className="p-1 rounded text-slate-400 hover:text-white transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Step indicator */}
        <div className="flex items-center gap-1 px-4 py-2.5 border-b border-slate-800 bg-[#0A0D15]/60 overflow-x-auto">
          {stepsList.map(s => (
            <React.Fragment key={s.num}>
              <span
                className={`text-[10px] font-mono px-2 py-0.5 rounded whitespace-nowrap ${
                  step === s.num
                    ? 'bg-cyan-950 text-cyan-300 border border-cyan-600 font-bold'
                    : step > s.num
                    ? 'bg-emerald-950/60 text-emerald-400 border border-emerald-800'
                    : 'bg-slate-900 text-slate-500 border border-slate-800'
                }`}
              >
                {s.num}. {s.label}
              </span>
              {s.num < 6 && <span className="text-slate-700 text-[10px]">→</span>}
            </React.Fragment>
          ))}
        </div>

        {/* Body */}
        <div className="p-5 space-y-4 text-xs min-h-[280px]">
          {/* STEP 1: IDENTITY */}
          {step === 1 && (
            <div className="space-y-3">
              <div>
                <label className="block text-[11px] font-semibold text-slate-300 mb-1 font-mono uppercase tracking-wider">Instance Name *</label>
                <input
                  data-testid="wizard-name"
                  value={name}
                  onChange={e => setName(e.target.value)}
                  placeholder="Production NGINX Gateway"
                  className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500 font-mono"
                />
              </div>
              <div>
                <label className="block text-[11px] font-semibold text-slate-300 mb-1 font-mono uppercase tracking-wider">Description</label>
                <textarea
                  rows={2}
                  value={description}
                  onChange={e => setDescription(e.target.value)}
                  placeholder="What this source instance monitors…"
                  className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500"
                />
              </div>
              <div>
                <label className="block text-[11px] font-semibold text-slate-300 mb-1 font-mono uppercase tracking-wider">
                  Tags (UPPERCASE, e.g. PROD, NGINX-EDGE)
                </label>
                <input
                  value={tagsInput}
                  onChange={e => setTagsInput(e.target.value)}
                  placeholder="PROD, DMZ"
                  className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500 font-mono"
                />
                <p className="text-[10px] text-slate-500 mt-1">
                  Backend constraint: 1–64 chars, pattern ^[A-Z][A-Z0-9_-]*$ — violations are rejected with HTTP 400.
                </p>
              </div>
            </div>
          )}

          {/* STEP 2: CAPABILITY (real registry) */}
          {step === 2 && (
            <div className="space-y-3">
              <p className="text-slate-400">
                Capabilities come from the REAL registry{' '}
                (<code className="text-cyan-300">capability.list</code>). Only capabilities the
                backend would actually accept are offered: status <code>active</code> and a real
                connector implementation. The connector type is taken from the capability's own
                implementation reference, so a source can never claim a capability that does not
                own it.
              </p>
              {capabilityError && (
                <div className="p-3 rounded-lg bg-amber-950/30 border border-amber-500/40 text-amber-300 flex items-start gap-2">
                  <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                  <span>{capabilityError}</span>
                </div>
              )}
              {bindable.length === 0 ? (
                <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 text-slate-400">
                  No bindable capabilities are available. A capability is bindable only when it is{' '}
                  <strong>active</strong> and has a shipped connector implementation. Planned
                  capabilities cannot own a source — bind one after its connector ships.
                </div>
              ) : (
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  {bindable.map(c => (
                    <button
                      key={c.capability_id}
                      type="button"
                      data-testid={`wizard-cap-${c.capability_id}`}
                      onClick={() => {
                        setCapabilityId(c.capability_id);
                        setMappingProfileId('');
                      }}
                      className={`p-3 rounded-lg border text-left transition-all ${
                        capabilityId === c.capability_id
                          ? 'bg-cyan-950/60 border-cyan-500 text-cyan-200'
                          : 'bg-slate-900 border-slate-800 text-slate-300 hover:border-slate-600'
                      }`}
                    >
                      <div className="font-mono font-bold text-xs">{c.name}</div>
                      <div className="text-[10px] text-slate-500 mt-0.5 font-mono">
                        {c.capability_id} v{c.version} impl: {c.implementation_ref}
                      </div>
                      <div className="text-[10px] text-slate-500 mt-0.5">{c.description}</div>
                    </button>
                  ))}
                </div>
              )}

              {selectedCapability && (
                <div className="p-3 rounded-lg bg-slate-900 border border-slate-700 space-y-2">
                  <div className="flex items-center gap-2 font-mono text-[11px] text-slate-300">
                    <Layers className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Binding preview (server-authoritative)</span>
                  </div>
                  <dl className="grid grid-cols-2 gap-x-3 gap-y-1 font-mono text-[10px]">
                    <dt className="text-slate-500">capability_id</dt>
                    <dd className="text-cyan-300">{selectedCapability.capability_id}</dd>
                    <dt className="text-slate-500">capability_version</dt>
                    <dd className="text-slate-200">{selectedCapability.version}</dd>
                    <dt className="text-slate-500">connector (source_type)</dt>
                    <dd className="text-slate-200">{sourceType}</dd>
                    <dt className="text-slate-500">mapping_profile_id</dt>
                    <dd className="text-slate-200">
                      {mappingProfileId || (
                        <span className="text-slate-500">not set (optional)</span>
                      )}
                    </dd>
                  </dl>
                  {profilesForType.length > 0 && (
                    <div>
                      <label className="block text-[10px] font-semibold text-slate-400 mb-1 font-mono uppercase tracking-wider">
                        Mapping profile declared by this capability for “{sourceType}”
                      </label>
                      <select
                        value={mappingProfileId}
                        onChange={e => setMappingProfileId(e.target.value)}
                        className="w-full px-2.5 py-1.5 rounded-lg bg-slate-950 border border-slate-700 text-slate-100 font-mono focus:outline-none focus:border-cyan-500"
                      >
                        <option value="">
                          {profilesForType.length === 1
                            ? 'auto (the only declared profile)'
                            : 'none declared — select one'}
                        </option>
                        {profilesForType.map(p => (
                          <option key={p.profile_id} value={p.profile_id}>
                            {p.profile_id}
                          </option>
                        ))}
                      </select>
                    </div>
                  )}
                  {profilesForType.length === 0 && (
                    <p className="text-[10px] text-slate-500">
                      This capability declares no mapping profile for “{sourceType}”. The backend
                      will accept the binding without a profile.
                    </p>
                  )}
                </div>
              )}
            </div>
          )}

          {/* STEP 3: CONNECTION */}
          {step === 3 && (
            <div className="space-y-3">
              <div>
                <label className="block text-[11px] font-semibold text-slate-300 mb-1 font-mono uppercase tracking-wider">
                  Ingest Endpoint (push)
                </label>
                <input
                  value={endpoint}
                  onChange={e => setEndpoint(e.target.value)}
                  placeholder="https://ingest.example.com/hook"
                  className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500 font-mono"
                />
                <p className="text-[10px] text-slate-500 mt-1">
                  Persisted via <code className="text-cyan-300">source.configure</code>. The backend
                  requires an <code>https://</code> endpoint before{' '}
                  <code className="text-cyan-300">source.validate</code> accepts the source. Leave
                  empty to configure later — validation then fails truthfully.
                </p>
              </div>
              <div>
                <label className="block text-[11px] font-semibold text-slate-300 mb-1 font-mono uppercase tracking-wider">
                  Destination label
                </label>
                <input
                  value={destination}
                  onChange={e => setDestination(e.target.value)}
                  placeholder="web-api-01"
                  className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500 font-mono"
                />
              </div>
              <div>
                <label className="block text-[11px] font-semibold text-slate-300 mb-1 font-mono uppercase tracking-wider">
                  Asset tags (lowercase, e.g. web-app, dmz)
                </label>
                <input
                  value={assetTagsInput}
                  onChange={e => setAssetTagsInput(e.target.value)}
                  placeholder="web-app, dmz"
                  className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500 font-mono"
                />
              </div>
            </div>
          )}

          {/* STEP 4: CREDENTIALS */}
          {step === 4 && (
            <div className="space-y-3">
              <div className="p-3.5 rounded-lg bg-slate-900 border border-slate-800 space-y-2">
                <div className="flex items-center gap-2">
                  <KeyRound className="w-4 h-4 text-cyan-400" />
                  <h4 className="text-xs font-bold text-cyan-300 font-mono">
                    Source identity credential (backend-issued)
                  </h4>
                </div>
                <ul className="list-disc pl-4 space-y-1 text-slate-300">
                  <li>
                    The credential is an HMAC-signed <code className="text-cyan-300">sit-…</code>{' '}
                    token minted only by the backend.
                  </li>
                  <li>
                    It identifies <strong>this source instance</strong> — not the capability and
                    not the connector type. One instance's token can never authenticate another.
                  </li>
                  <li>
                    Tokens are <strong>single-use</strong>: a replayed token is rejected by the
                    ingress replay store.
                  </li>
                  <li>
                    The backend refuses to issue a credential unless the source is{' '}
                    <strong>bound to a capability</strong> and has reached{' '}
                    <code>validated</code> or <code>enabled</code> — which is why issuance happens
                    in the final step, not here.
                  </li>
                </ul>
                <p className="text-[10px] text-slate-500">
                  No token is shown on this step because none exists yet. ProShield never
                  fabricates a credential in the UI.
                </p>
              </div>
            </div>
          )}

          {/* STEP 5: VALIDATION */}
          {step === 5 && (
            <div className="space-y-3">
              <div className="p-3.5 rounded-lg bg-slate-900 border border-slate-800 space-y-1.5 font-mono text-xs">
                <div className="flex justify-between"><span className="text-slate-400">Instance Name:</span><span className="text-slate-100 font-bold">{name || '—'}</span></div>
                <div className="flex justify-between"><span className="text-slate-400">Capability:</span><span className="text-cyan-300">{selectedCapability ? `${selectedCapability.capability_id} (v${selectedCapability.version})` : '—'}</span></div>
                <div className="flex justify-between"><span className="text-slate-400">Connector:</span><span className="text-slate-100">{sourceType || '—'}</span></div>
                <div className="flex justify-between"><span className="text-slate-400">Mapping profile:</span><span className="text-slate-100">{mappingProfileId || '—'}</span></div>
                <div className="flex justify-between"><span className="text-slate-400">Endpoint:</span><span className="text-slate-100 break-all">{endpoint || '(configure later)'}</span></div>
                <div className="flex justify-between"><span className="text-slate-400">Destination:</span><span className="text-slate-100">{destination || '—'}</span></div>
              </div>
              <p className="text-slate-400">
                Deploying runs the REAL backend lifecycle:{' '}
                <code className="text-cyan-300">register (with an explicit capability
                binding)</code> → <code>configure</code> → <code>validate</code> →{' '}
                <code>enable</code> → <code>issue_token</code>. A rejected step stops the flow and
                the source is left in its true backend state — nothing is faked.
              </p>
              {deployError && (
                <div className="p-2.5 rounded-lg bg-rose-950/40 border border-rose-500/40 text-rose-300 font-mono" role="alert">
                  <div className="font-bold mb-0.5">Backend rejected the deployment</div>
                  {deployError}
                </div>
              )}
            </div>
          )}

          {/* STEP 6: ENABLE & VERIFY */}
          {step === 6 && (
            <div className="space-y-4 py-2">
              <div className="text-center">
                <div className="w-12 h-12 rounded-full bg-emerald-950/80 border border-emerald-500/40 text-emerald-400 flex items-center justify-center mx-auto shadow-[0_0_20px_rgba(16,185,129,0.3)]">
                  <ShieldCheck className="w-6 h-6" />
                </div>
                <h4 className="text-base font-bold text-slate-100 font-mono mt-2">
                  {issuedToken ? 'SOURCE ENABLED ON THE BACKEND' : 'SOURCE SAVED (NOT ENABLED)'}
                </h4>
                <p className="text-xs text-slate-400 mt-1">
                  Backend-confirmed lifecycle: registered → validated
                  {issuedToken ? ' → enabled → credential issued' : ' (enable skipped)'}.
                </p>
              </div>

              {issuedToken ? (
                <div className="p-3.5 rounded-lg bg-amber-950/25 border border-amber-500/40 space-y-2">
                  <div className="flex items-center gap-2 text-amber-300 font-mono text-xs font-bold">
                    <KeyRound className="w-3.5 h-3.5" />
                    Copy this credential now — it is shown once
                  </div>
                  <div className="flex items-center gap-2">
                    <code className="flex-1 px-2.5 py-2 rounded bg-slate-950 border border-slate-700 text-[10px] font-mono text-emerald-300 break-all">
                      {issuedToken}
                    </code>
                    <button
                      type="button"
                      onClick={copyToken}
                      className="shrink-0 flex items-center gap-1 px-2.5 py-2 rounded bg-slate-800 hover:bg-slate-700 border border-slate-600 text-cyan-300 font-mono text-[10px]"
                    >
                      <Copy className="w-3.5 h-3.5" />
                      {copied ? 'Copied' : 'Copy'}
                    </button>
                  </div>
                  <p className="text-[10px] text-amber-200/80">
                    Single-use. <code>source.list</code> never re-serves it. Rotate it from the
                    Sources page at any time: rotation issues a NEW credential and audits the
                    change, and outstanding credentials that were never used are NOT revoked — they
                    stay valid until they are used once or their lifetime window expires
                    (documented deferral: no revocation list in this release).
                  </p>
                </div>
              ) : (
                <div className="p-3.5 rounded-lg bg-slate-900 border border-slate-700 text-slate-300">
                  The source was registered, configured and validated, but was NOT enabled, so no
                  credential was issued. Enable it from the Sources page when ready — the credential
                  is issued then.
                </div>
              )}

              {newHumanId && (
                <p className="text-[10px] text-slate-500 font-mono text-center break-all">
                  source_instance_id: {newHumanId}
                </p>
              )}
            </div>
          )}
        </div>

        {/* Footer Navigation */}
        <div className="flex items-center justify-between p-4 border-t border-slate-800 bg-[#0A0D15]">
          <button
            type="button"
            disabled={step === 1 || deploying}
            onClick={() => setStep((step - 1) as any)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-slate-400 hover:text-white disabled:opacity-30 disabled:cursor-not-allowed font-mono text-xs transition-colors"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            <span>Back</span>
          </button>

          {step < 5 ? (
            <button
              type="button"
              data-testid="wizard-continue"
              disabled={(step === 1 && !name.trim()) || (step === 2 && !capabilityId)}
              onClick={() => setStep((step + 1) as any)}
              className="flex items-center gap-1.5 px-4 py-1.5 rounded-lg bg-slate-100 hover:bg-white disabled:bg-slate-800 disabled:text-slate-600 text-slate-900 font-mono font-semibold text-xs transition-colors"
            >
              <span>Continue</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          ) : step === 5 ? (
            <div className="flex items-center gap-2">
              <button
                type="button"
                data-testid="wizard-validate-only"
                disabled={deploying}
                onClick={() => handleDeploy(false)}
                title="Register, configure and validate only — enable later from the Sources page"
                className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-slate-200 font-mono text-xs border border-slate-700 transition-colors"
              >
                Validate only
              </button>
              <button
                type="button"
                data-testid="wizard-deploy-enable"
                disabled={deploying}
                onClick={() => handleDeploy(true)}
                className="flex items-center gap-1.5 px-5 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:bg-slate-800 disabled:text-slate-600 text-white font-mono font-semibold text-xs transition-colors"
              >
                <CheckCircle className="w-3.5 h-3.5" />
                <span>{deploying ? 'Deploying…' : 'Deploy & enable'}</span>
              </button>
            </div>
          ) : (
            <button
              type="button"
              data-testid="wizard-close"
              onClick={handleReset}
              className="flex items-center gap-1.5 px-5 py-1.5 rounded-lg bg-slate-100 hover:bg-white text-slate-900 font-mono font-semibold text-xs transition-colors"
            >
              <span>Close</span>
            </button>
          )}
        </div>
      </div>
    </div>
  );
};
