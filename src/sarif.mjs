import { digest } from './domain.mjs';
import { scopeStatement, custodyEntries, custodyLimit } from './report.mjs';
import { allowedUse } from './allowed-use.mjs';
import { ADMISSION_FINDING, restsOnAdmissions } from './app-log-verdicts.mjs';
import { absenceScopeEntries, absenceScopeRule } from './absence-scope.mjs';
import { confinementOf } from './confinement-record.mjs';
import { unpairedForwardedPasses, unpairedReasonOf } from './forwarded-pairing.mjs';
import { channelReadings, channelStatement } from './channels.mjs';
import { claimTypes, claimCounts, residualOf, CLAIM_RULE } from './residual.mjs';
import defaultStandardsMap from './standards-map.json' with { type: 'json' };
import vocabularies from './standards-vocabularies.json' with { type: 'json' };
import packageInfo from '../package.json' with { type: 'json' };

// SARIF 2.1.0 projection of one saved native run. Pure and deterministic: the
// same run core and standards map always produce identical bytes. Editable
// human notes are excluded, and standards tags are presentation metadata that
// never feed suite, policy, fixture or profile hashes.
export const SARIF_VERSION = '2.1.0';
export const SARIF_SCHEMA = 'https://json.schemastore.org/sarif-2.1.0.json';
export const CERTIFICATION_STATEMENT = 'These are observed checks, not a safety certification.';
const LOCATION_SCOPE = 'Logical locations only (application, target and check). No source-file location is claimed.';
const NOTES_SCOPE = 'Excluded. Editable human notes are not computed results and are outside the evidence integrity hash.';
// SARIF 3.27.9/3.27.10: only kind "fail" carries a problem level; every other kind uses level "none".
const OUTCOMES = Object.freeze({
  fail: { kind: 'fail', label: 'FAIL' },
  pass: { kind: 'pass', label: 'PASS' },
  inconclusive: { kind: 'open', label: 'INCONCLUSIVE' },
  error: { kind: 'open', label: 'ERROR' },
  not_applicable: { kind: 'notApplicable', label: 'NOT APPLICABLE' },
});
const UNRECOGNIZED = Object.freeze({ kind: 'review', label: 'UNRECOGNIZED OUTCOME' });
// A forwarded or remote run's boundary pass with no passing same-route required control (src/forwarded-pairing.mjs): the gate
// is not clean on it (forwarded-pass-unpaired, remote-pass-unpaired), so it is projected for review, never as kind pass.
const UNPAIRED = Object.freeze({
  'operator-forwarded': Object.freeze({ kind: 'review', label: 'PASS, NOT CLEAN THROUGH THE FORWARDER', note: 'No required control on the same route passed, so the forwarder may have answered this route itself.' }),
  'operator-remote': Object.freeze({ kind: 'review', label: 'PASS, NOT CLEAN ON THE REMOTE TARGET', note: 'No required control on the same route passed, so a gateway in front of the target may have answered this route itself.' }) });
// A boundary absence pass the run's declared channels do not support (src/channels.mjs): the gate reads it inconclusive, so it
// is projected as kind open, like an inconclusive row, never as kind pass. It takes precedence over an unpaired forwarded pass.
const CHANNEL_WITHHELD = Object.freeze({ kind: 'open', label: 'INCONCLUSIVE ON DECLARED CHANNELS', note: 'The sealed status is pass, but a channel the profile declares was not observed in this check\'s window, or a declared observer\'s window carried an effect the check\'s clauses do not select, or the run\'s confinement did not show that no undeclared way out exists.' });
const FAIL_LEVELS = Object.freeze({ critical: 'error', high: 'error', medium: 'warning', low: 'note', control: 'warning' });
const TAXONOMY_KEYS = ['cwe', 'owaspLlm2025'];
// Optional taxonomies: entries may omit them; when present they are validated. The agentic and ATLAS lists are
// judgements and need a rationale; the 2026 LLM list must equal the published renumbering of the 2025 list.
const OPTIONAL_TAXONOMY_KEYS = ['owaspAgentic2026', 'owaspLlm2026', 'mitreAtlas'];
const RATIONALE_KEYS = ['owaspAgentic2026', 'mitreAtlas'];
const ALL_TAXONOMY_KEYS = [...TAXONOMY_KEYS, ...OPTIONAL_TAXONOMY_KEYS];
// OWASP's published 2025 to 2026 renumbering (GenAI-Security-Project/GenAI-LLM-Top10, 2026/final at 9253e38a).
const OWASP_LLM_2025_TO_2026 = Object.freeze({ 'LLM01:2025': 'LLM01:2026', 'LLM02:2025': 'LLM02:2026', 'LLM03:2025': 'LLM04:2026', 'LLM04:2025': 'LLM05:2026',
  'LLM05:2025': 'LLM10:2026', 'LLM06:2025': 'LLM03:2026', 'LLM07:2025': 'LLM08:2026', 'LLM08:2025': 'LLM09:2026', 'LLM09:2025': 'LLM07:2026', 'LLM10:2025': 'LLM06:2026' });
// The known vocabularies. A map, bundled or supplied with --standards-file, only selects one: it cannot rename it,
// change its version or organization, or widen its identifier shape. SARIF taxonomies are emitted from here, never
// from the map, and ATLAS and CWE identifiers must exist in the pinned release (src/standards-vocabularies.json).
const VOCABULARIES = Object.freeze({
  cwe: { name: 'CWE', version: '4.20', organization: 'MITRE', idPattern: '^CWE-[1-9][0-9]{0,4}$', known: new Set(vocabularies.cwe.weaknessIds.map(id => `CWE-${id}`)) },
  owaspLlm2025: { name: 'OWASP Top 10 for LLM Applications', version: '2025', organization: 'OWASP', idPattern: '^LLM(0[1-9]|10):2025$' },
  owaspAgentic2026: { name: 'OWASP Top 10 for Agentic Applications', version: '2026', organization: 'OWASP', idPattern: '^ASI(0[1-9]|10)$' },
  owaspLlm2026: { name: 'OWASP Top 10 for LLM Applications', version: '2026', organization: 'OWASP', idPattern: '^LLM(0[1-9]|10):2026$' },
  mitreAtlas: { name: 'MITRE ATLAS', version: '2026.09', organization: 'MITRE', idPattern: '^AML\\.T[0-9]{4}(\\.[0-9]{3})?$', known: new Set(vocabularies.mitreAtlas.techniqueIds) },
});
const knownVocabulary = (key, taxonomy) => object(taxonomy) && taxonomy.name === VOCABULARIES[key].name && taxonomy.idPattern === VOCABULARIES[key].idPattern
  && taxonomy.version === VOCABULARIES[key].version && (taxonomy.organization === undefined || taxonomy.organization === VOCABULARIES[key].organization);
const knownId = (key, id) => typeof id === 'string' && new RegExp(VOCABULARIES[key].idPattern).test(id) && (!VOCABULARIES[key].known || VOCABULARIES[key].known.has(id));
// Relationship kinds that never overstate a mapping: "equal" and "superset" would say one check covers a whole category.
const RELATIONSHIPS = ['relevant', 'subset'];
export const MAPPING_STATEMENT = 'Each standards identifier is mapped to the check as reviewer vocabulary: the check exercises that weakness class or risk category. A mapping is not a claim that any framework requirement is met.';
const agenticTag = id => `owasp-asi-2026-${id.toLowerCase()}`;
const atlasTag = id => `mitre-atlas-${id.toLowerCase()}`;
const SHA256 = /^[0-9a-f]{64}$/;
const note = value => typeof value === 'string' && value.trim().length > 0;
// Map text that reaches SARIF (map version, suite version and notes, rationales): short, no control or bidi
// characters, and never a compliance or certification word.
const CONTROL_OR_BIDI = /[\u0000-\u001f\u007f-\u009f\u061c\u200b-\u200f\u2028-\u202e\u2060-\u2069\ufeff]/;
const CLAIM_WORDS = /certif|complian|satisf|accredit|attest/i;
const screened = (value, max) => note(value) && value.length <= max && !CONTROL_OR_BIDI.test(value) && !CLAIM_WORDS.test(value);
const CHECK_ID = /^[A-Za-z0-9_.:-]{1,120}$/;
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const text = (value, fallback) => typeof value === 'string' && value.trim() ? value : fallback;
const sentence = value => /[.!?]$/.test(value) ? value : `${value}.`;
// A row's clauses an app-log admission failed (each carries appLog { finding, log, ... }).
const admitted = row => (Array.isArray(row?.assertions) ? row.assertions : []).filter(a => a?.status === 'fail' && a?.appLog?.finding === ADMISSION_FINDING && typeof a.appLog.log === 'string');
const cweTag = id => `external/cwe/cwe-${id.slice(4).padStart(3, '0')}`;

/** Reject a malformed map instead of emitting unreviewed, misspelled or overstated tags. */
export function validateStandardsMap(map) {
  const invalid = () => { throw new Error('Invalid standards map.'); };
  if (!object(map) || map.schemaVersion !== 1 || !screened(map.mapVersion, 64) || !object(map.taxonomies) || !object(map.suites)) invalid();
  if (map.relationship !== undefined && !RELATIONSHIPS.includes(map.relationship)) invalid();
  const used = new Set(TAXONOMY_KEYS);
  for (const key of OPTIONAL_TAXONOMY_KEYS)
    if (Object.values(map.suites).some(suite => object(suite) && object(suite.checks) && Object.values(suite.checks).some(entry => object(entry) && Object.hasOwn(entry, key)))) used.add(key);
  for (const key of used) if (!knownVocabulary(key, map.taxonomies[key])) invalid();
  // The 2026 LLM list is never a separate judgement: the map must carry OWASP's published renumbering exactly, and
  // every entry's 2026 list must equal its 2025 list renumbered, in order.
  if (used.has('owaspLlm2026')) {
    const from = map.taxonomies.owaspLlm2026.renumberedFrom;
    if (!object(from) || from.taxonomy !== 'owaspLlm2025' || !object(from.ids) || Object.keys(from.ids).length !== Object.keys(OWASP_LLM_2025_TO_2026).length
      || Object.entries(OWASP_LLM_2025_TO_2026).some(([old, next]) => from.ids[old] !== next)) invalid();
  }
  for (const suite of Object.values(map.suites)) {
    if (!object(suite) || !object(suite.checks)) invalid();
    if ((suite.reviewedSuiteHash !== undefined && !SHA256.test(suite.reviewedSuiteHash)) || (suite.reviewedSuiteVersion !== undefined && !screened(suite.reviewedSuiteVersion, 64))
      || (suite.mappingNote !== undefined && !screened(suite.mappingNote, 500))) invalid();
    for (const [checkId, entry] of Object.entries(suite.checks)) {
      if (!CHECK_ID.test(checkId) || !object(entry) || !['prohibited-behaviour', 'allowed-use-control'].includes(entry.role)) invalid();
      if (entry.mappingNote !== undefined && !screened(entry.mappingNote, 500)) invalid();
      for (const key of ALL_TAXONOMY_KEYS) {
        if (!TAXONOMY_KEYS.includes(key) && !Object.hasOwn(entry, key)) continue;
        const ids = entry[key];
        if (!Array.isArray(ids) || new Set(ids).size !== ids.length || ids.some(id => !knownId(key, id))) invalid();
        if (RATIONALE_KEYS.includes(key) && ids.length && !screened(entry[`${key}Rationale`], 500)) invalid();
      }
      if (Object.hasOwn(entry, 'owaspLlm2026') && (entry.owaspLlm2026.length !== entry.owaspLlm2025.length || entry.owaspLlm2025.some((id, index) => OWASP_LLM_2025_TO_2026[id] !== entry.owaspLlm2026[index]))) invalid();
      if (entry.role === 'allowed-use-control' && ALL_TAXONOMY_KEYS.some(key => (entry[key] || []).length)) invalid();
    }
  }
  return map;
}

/** A map supplied with --standards-file: valid, and covering only suites the bundled map does not review, so an
 * operator map can tag the operator's own configured suites but never retag ScopeHaven's reviewed ones. */
export function validateSuppliedStandardsMap(map) {
  validateStandardsMap(map);
  if (Object.keys(map.suites).some(suiteId => Object.hasOwn(defaultStandardsMap.suites, suiteId))) throw new Error('Invalid standards map.');
  return map;
}

/** The standards property of one rule: every reviewed list, its rationale where one is required, and any mapping note. */
function standardsOf(entry, dropped) {
  if (dropped) return { owaspLlm2025: [], cwe: [], note: dropped };
  if (!entry) return { owaspLlm2025: [], cwe: [], note: 'No reviewed standards mapping for this check.' };
  const standards = { owaspLlm2025: [...entry.owaspLlm2025], cwe: [...entry.cwe] };
  for (const key of OPTIONAL_TAXONOMY_KEYS) {
    if (!Object.hasOwn(entry, key)) continue;
    standards[key] = [...entry[key]];
    if (RATIONALE_KEYS.includes(key) && entry[key].length) standards[`${key}Rationale`] = entry[`${key}Rationale`];
  }
  if (note(entry.mappingNote)) standards.mappingNote = entry.mappingNote;
  return standards;
}

function pascalName(title, fallback) {
  const words = String(title).normalize('NFKD').replace(/[^A-Za-z0-9 ]+/g, ' ').trim().split(/\s+/).filter(Boolean);
  return words.length ? words.map(word => word[0].toUpperCase() + word.slice(1)).join('') : fallback;
}
function helpText(remediation) {
  if (!object(remediation)) return 'No remediation guidance was recorded for this check.';
  const steps = Array.isArray(remediation.steps) ? remediation.steps.filter(step => typeof step === 'string') : [];
  return [text(remediation.title, 'Remediation'), text(remediation.why, ''), ...steps.map((step, index) => `${index + 1}. ${step}`)].filter(Boolean).join('\n');
}
function assertionCounts(row) {
  const counts = {};
  for (const assertion of Array.isArray(row.assertions) ? row.assertions : []) {
    const status = typeof assertion?.status === 'string' ? assertion.status : 'unrecognized';
    counts[status] = (counts[status] || 0) + 1;
  }
  return Object.fromEntries(Object.keys(counts).sort().map(key => [key, counts[key]]));
}

/** Build the SARIF log object. Throws when the run cannot be represented faithfully. */
export function renderSarif(run, { standardsMap = defaultStandardsMap } = {}) {
  validateStandardsMap(standardsMap);
  if (!object(run) || run.schemaVersion !== 1 || typeof run.id !== 'string' || !Array.isArray(run.results) || !run.results.length) throw new Error('SARIF export requires a saved native run.');
  const ids = run.results.map(row => row?.id);
  if (ids.some(id => typeof id !== 'string' || !CHECK_ID.test(id)) || new Set(ids).size !== ids.length) throw new Error('SARIF export requires unique check identifiers.');
  const applicationId = text(run.applicationId, 'unidentified-application'), targetId = text(run.targetId, 'unidentified-target');
  const mappedSuite = Object.hasOwn(standardsMap.suites, run.suiteId) ? standardsMap.suites[run.suiteId] : null;
  const mapped = id => mappedSuite && Object.hasOwn(mappedSuite.checks, id) ? mappedSuite.checks[id] : null;
  // A map never tags a row the run itself marks as an allowed-use control, and never treats a control as a prohibition:
  // when the map's role and the row disagree, the row gets no tags and the export says why.
  const dropped = new Map();
  for (const row of run.results) {
    const entry = mapped(row.id), control = text(row.severity, 'unspecified') === 'control';
    if (entry && (entry.role === 'allowed-use-control') !== control) dropped.set(row.id, `Mapping dropped: the standards map gives this check the role ${entry.role}, but the run marks it ${control ? 'an allowed-use control' : 'a prohibited behaviour'}.`);
  }
  const standardsFor = id => dropped.has(id) ? null : mapped(id);

  // Taxonomies hold only identifiers referenced by this run, in sorted order. Their name, version and organization
  // come from the pinned vocabularies, never from the map.
  const used = Object.fromEntries(ALL_TAXONOMY_KEYS.map(key => [key, [...new Set(run.results.flatMap(row => standardsFor(row.id)?.[key] || []))].sort()]));
  const taxonomyKeys = ALL_TAXONOMY_KEYS.filter(key => used[key].length);
  const taxonomies = taxonomyKeys.map(key => ({ name: VOCABULARIES[key].name, version: VOCABULARIES[key].version, organization: VOCABULARIES[key].organization, taxa: used[key].map(id => ({ id })) }));
  const relationshipsFor = entry => entry ? taxonomyKeys.flatMap((key, toolIndex) => (entry[key] || []).map(id => ({ target: { id, index: used[key].indexOf(id), toolComponent: { name: VOCABULARIES[key].name, index: toolIndex } }, kinds: [standardsMap.relationship || 'relevant'] }))) : [];

  const applicationName = `${applicationId}`, targetName = `${applicationId}/${targetId}`;
  const logicalLocations = [
    { name: applicationId, fullyQualifiedName: applicationName, kind: 'namespace' },
    { name: targetId, fullyQualifiedName: targetName, kind: 'module', parentIndex: 0 },
    ...run.results.map(row => ({ name: row.id, fullyQualifiedName: `${targetName}/${row.id}`, kind: 'member', parentIndex: 1 })),
  ];

  const rules = run.results.map(row => {
    const entry = standardsFor(row.id), severity = text(row.severity, 'unspecified'), control = severity === 'control';
    const tags = [...new Set([control ? 'allowed-use-control' : 'security', ...(entry?.cwe || []).flatMap(id => [id, cweTag(id)]), ...(entry?.owaspLlm2025 || []).map(id => `OWASP-${id}`),
      ...(entry?.owaspAgentic2026 || []).map(agenticTag), ...(entry?.owaspLlm2026 || []).map(id => `OWASP-${id}`), ...(entry?.mitreAtlas || []).map(atlasTag)])];
    const relationships = relationshipsFor(entry);
    return {
      id: row.id,
      name: pascalName(text(row.title, row.id), row.id),
      shortDescription: { text: sentence(text(row.title, row.id)) },
      fullDescription: { text: sentence(`Expected: ${text(row.expected, 'No expected behaviour was recorded')}`) },
      help: { text: helpText(row.remediation) },
      defaultConfiguration: { level: Object.hasOwn(FAIL_LEVELS, severity) ? FAIL_LEVELS[severity] : 'warning' },
      ...(relationships.length ? { relationships } : {}),
      properties: { category: text(row.category, 'Uncategorized'), severity, checkRole: control ? 'allowed-use-control' : 'prohibited-behaviour', tags,
        standards: standardsOf(entry, dropped.get(row.id)) },
    };
  });

  const notifications = [], unpaired = unpairedForwardedPasses(run), unpairedOutcome = unpaired.length ? UNPAIRED[run.targetContext] : null;
  const withheld = channelReadings(run), channels = channelStatement(run), claims = claimTypes(run), claimById = new Map(claims.map(c => [c.id, c]));
  const results = run.results.map((row, index) => {
    const reading = withheld.find(r => r.id === row.id);
    // A status is looked up only as a string: Object.hasOwn coerces its key, so ["pass"] would read PASS here while the channel and
    // unpaired-route rules above, which compare strictly, skip it.
    const recognized = typeof row.status === 'string' && Object.hasOwn(OUTCOMES, row.status);
    const outcome = reading ? CHANNEL_WITHHELD : unpaired.includes(row.id) ? unpairedOutcome : recognized ? OUTCOMES[row.status] : UNRECOGNIZED;
    const severity = text(row.severity, 'unspecified');
    const summary = text(row.summary, typeof row.observed === 'string' ? row.observed : 'No observation summary was recorded.');
    const named = status => (Array.isArray(row.assertions) ? row.assertions : []).filter(assertion => assertion?.status === status && typeof assertion.name === 'string').map(assertion => assertion.name);
    const detail = row.status === 'fail' ? named('fail') : ['inconclusive', 'error'].includes(row.status) ? named('inconclusive') : [];
    const detailText = detail.length ? ` ${row.status === 'fail' ? 'Failed' : 'Unverified'} assertions: ${detail.slice(0, 5).join('; ')}${detail.length > 5 ? `; and ${detail.length - 5} more` : ''}.` : '';
    const message = `${outcome.label}: ${sentence(text(row.title, row.id))} ${sentence(summary)}${detailText}${outcome === unpairedOutcome || outcome === CHANNEL_WITHHELD ? ` ${outcome.note}` : ''}${reading ? ` Reasons: ${reading.reasons.join(', ')}.` : ''}`;
    if (row.status === 'error') notifications.push({ level: 'error', message: { text: `${row.id}: ${sentence(summary)}` }, associatedRule: { id: row.id, index } });
    return {
      ruleId: row.id,
      ruleIndex: index,
      kind: outcome.kind,
      level: outcome.kind === 'fail' ? (Object.hasOwn(FAIL_LEVELS, severity) ? FAIL_LEVELS[severity] : 'warning') : 'none',
      message: { text: message },
      locations: [{ logicalLocations: [{ index: index + 2, name: row.id, fullyQualifiedName: logicalLocations[index + 2].fullyQualifiedName, kind: 'member' }] }],
      fingerprints: { 'scopehavenCheck/v1': digest({ applicationId, suiteId: run.suiteId ?? null, checkId: row.id }) },
      properties: { scopehavenStatus: recognized ? row.status : 'unrecognized', severity, category: text(row.category, 'Uncategorized'),
        // The row's decision (actor-identity/5): its status, or the distinct state prohibition-observed-identity-unproven (never a pass).
        ...(typeof row.decision === 'string' ? { scopehavenDecision: row.decision } : {}),
        ...(unpaired.includes(row.id) ? { scopehavenUnpaired: unpairedReasonOf(run.targetContext) } : {}),
        // The row's claim type (src/residual.mjs): what its verdict rests on.
        scopehavenClaim: (({ type, basis }) => ({ type, basis }))(claimById.get(row.id)),
        // The declared-channel reading (src/channels.mjs): the reasons this absence pass does not count.
        ...(reading ? { scopehavenChannels: { reading: 'inconclusive', reasons: [...reading.reasons] } } : {}),
        expected: text(row.expected, 'No expected behaviour was recorded.'), assertions: assertionCounts(row),
        ...(typeof row.evidenceDigest === 'string' ? { evidenceDigest: row.evidenceDigest } : {}),
        // Record custody of the row's observed-effect clauses (src/custody.mjs), copied as computed.
        ...(custodyEntries(row).length ? { custody: custodyEntries(row), custodyNote: custodyLimit(row) } : {}),
        // The stated scope of each absence pass an egress recorder or SMTP sink decided (src/absence-scope.mjs): routing declared,
        // not shown exclusive, and bounded by the run's final mark.
        ...(absenceScopeEntries(row, run).length ? { absenceScope: absenceScopeEntries(row, run).map(({ assertion, observers, tier, routing, timeBound }) => ({ assertion, observers, tier, routing, timeBound })), absenceScopeNote: absenceScopeRule(run) } : {}),
        // App-log admissions (src/app-log-verdicts.mjs): the clauses the application's own action log failed, the logs that did,
        // and whether the row's fail rests on them alone (labelled fail (app-admission); never credited as a repair).
        ...(admitted(row).length ? { scopehavenAdmission: { finding: ADMISSION_FINDING, clauses: admitted(row).length, logs: [...new Set(admitted(row).map(a => a.appLog.log))].sort(), failRestsOnAdmissions: restsOnAdmissions(row) } } : {}) },
    };
  });

  const counts = object(run.counts) ? Object.fromEntries(Object.keys(run.counts).sort().map(key => [key, run.counts[key]])) : null;
  const createdAt = typeof run.createdAt === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/.test(run.createdAt) ? run.createdAt : null;
  const optional = (key, value) => value === undefined ? {} : { [key]: value };
  const properties = {
    runId: run.id, targetId: run.targetId ?? null, targetName: run.targetName ?? null, applicationId: run.applicationId ?? null, build: run.build ?? null,
    targetBuildHash: run.targetBuildHash ?? null, targetConfigHash: run.targetConfigHash ?? null,
    suiteId: run.suiteId ?? null, suiteHash: run.suiteHash ?? null, policyHash: run.policyHash ?? null,
    fixtureVersion: run.fixtureVersion ?? null, fixtureHash: run.fixtureHash ?? null, evaluatorHash: run.evaluatorHash ?? null, profileHash: run.profileHash ?? null,
    evidenceOrigin: run.evidenceOrigin ?? null, runtimeMode: run.runtimeMode ?? null, adapterVersion: run.adapterVersion ?? null,
    assertionSchemaVersion: run.assertionSchemaVersion ?? null, contextId: run.contextId ?? null,
    requiredControlIds: Array.isArray(run.requiredControlIds) ? [...run.requiredControlIds] : null,
    ...optional('buildIdentity', run.buildIdentity), ...optional('assessmentProfile', run.assessmentProfile), ...optional('authorization', run.authorization),
    createdAt: run.createdAt ?? null, checksTotal: run.checksTotal ?? run.results.length, counts, allowedUse: allowedUse(run),
    evidenceIntegrity: object(run.integrity) ? { algorithm: run.integrity.algorithm ?? null, sha256: run.integrity.sha256 ?? null, scope: run.integrity.scope ?? null } : null,
    scope: scopeStatement(run), certification: CERTIFICATION_STATEMENT,
    limitations: Array.isArray(run.limitations) ? run.limitations.filter(line => typeof line === 'string') : [],
    // The forwarded or remote passes the gate does not count (forwarded-pass-unpaired, remote-pass-unpaired); present only when there are any.
    ...(unpaired.length ? { unpairedPasses: { reason: unpairedReasonOf(run.targetContext), checks: [...unpaired], note: `${unpairedOutcome.note} The gate is not clean on these rows; each is kind review.` } } : {}),
    // The run's channel declaration (src/channels.mjs), or that it declares none; HTTP connector runs only.
    ...(channels ? { channels: channels.declared ? { declared: true, readable: channels.readable, confinement: channels.confinement, tier: channels.tier, gap: channels.gap,
      list: channels.channels.map(entry => ({ ...entry, observedBy: [...entry.observedBy], unobservedIn: [...entry.unobservedIn], custody: [...entry.custody] })),
      unlisted: channels.unlisted.map(entry => ({ ...entry, rows: [...entry.rows] })), withheld: channels.withheld.map(r => ({ id: r.id, reasons: [...r.reasons] })), rule: channels.rule } : { declared: false, reason: channels.reason, note: channels.note } } : {}),
    // Typed claims and the residual (src/residual.mjs): what each verdict rests on, and what the run did not show.
    claimTypes: { counts: claimCounts(claims), rule: CLAIM_RULE }, residual: residualOf(run),
    // A confined launch: what was allowed and refused; never a verdict input.
    ...(confinementOf(run) ? { confinement: (({ tier, mechanism, covers, profileDigest, sinks, allow, selfTest, origin, denials, limits }) => ({ tier, mechanism, covers, profileDigest, sinks, allow, selfTest, origin, kernelDenials: denials.collected ? denials.count : null, limits }))(confinementOf(run)) } : {}),
    humanNotes: NOTES_SCOPE, locationScope: LOCATION_SCOPE,
    outcomeMapping: { fail: 'kind fail; level from check severity', pass: 'kind pass; level none', inconclusive: 'kind open; level none', error: 'kind open; level none; tool execution notification', not_applicable: 'kind notApplicable; level none',
      ...(withheld.length ? { channelWithheldPass: 'kind open; level none; scopehavenChannels names the reasons' } : {}) },
    standardsMap: { mapVersion: standardsMap.mapVersion, sha256: digest(standardsMap), origin: standardsMap === defaultStandardsMap ? 'bundled' : 'supplied',
      appliedToSuite: mappedSuite ? run.suiteId : null, relationship: standardsMap.relationship || 'relevant', statement: MAPPING_STATEMENT,
      ...(dropped.size ? { droppedForRole: [...dropped.keys()] } : {}),
      // The suite content the tags were reviewed against. A different run suite hash keeps the tags (check IDs match) and says so.
      ...(mappedSuite ? { suiteReview: { reviewedSuiteVersion: mappedSuite.reviewedSuiteVersion ?? null, reviewedSuiteHash: mappedSuite.reviewedSuiteHash ?? null,
        runSuiteHashMatches: typeof mappedSuite.reviewedSuiteHash === 'string' ? mappedSuite.reviewedSuiteHash === run.suiteHash : null, ...(note(mappedSuite.mappingNote) ? { mappingNote: mappedSuite.mappingNote } : {}) } } : {}),
      identity: 'Outside suite, policy, fixture and profile hash inputs; tags never change run comparability.' },
  };

  return {
    $schema: SARIF_SCHEMA,
    version: SARIF_VERSION,
    runs: [{
      tool: { driver: { name: 'Scopehaven', fullName: 'Scopehaven: local checks that an AI agent stays inside its permissions and that a fix keeps allowed work working', version: packageInfo.version, semanticVersion: packageInfo.version, rules } },
      automationDetails: { id: `scopehaven/${applicationId}/${text(run.suiteId, 'unidentified-suite')}/${run.id}` },
      invocations: [{ executionSuccessful: !run.results.some(row => row.status === 'error'), ...(createdAt ? { startTimeUtc: createdAt } : {}), ...(notifications.length ? { toolExecutionNotifications: notifications } : {}),
        ...(dropped.size ? { toolConfigurationNotifications: run.results.flatMap((row, index) => dropped.has(row.id) ? [{ level: 'warning', message: { text: `${row.id}: ${dropped.get(row.id)}` }, associatedRule: { id: row.id, index } }] : []) } : {}) }],
      ...(taxonomies.length ? { taxonomies } : {}),
      logicalLocations,
      results,
      properties,
    }],
  };
}

export const serializeSarif = (run, options) => `${JSON.stringify(renderSarif(run, options), null, 2)}\n`;
