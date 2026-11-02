// A synthetic authorization record for tests that run a configured target through assess, the gate,
// the dashboard, a sequence or a conversation spec: it names the target, every endpoint the run contacts and every
// credentialed actor, valid from a day ago for thirty days, so a test never expires with the calendar.
import { writeFileSync } from 'node:fs';
import { checksumAuthorization, contactedEndpoints, AUTHORIZATION_SCHEMA } from '../../src/authorization.mjs';

const DAY = 86400000, at = ms => new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z');
// target: a profile, or a sequence or conversation spec reshaped as { id, applicationId, origin, observers?, actors }.
export function testAuthorization(target, { origins = [], edit = () => {} } = {}) {
  const record = { schema: AUTHORIZATION_SCHEMA, id: `test-${String(target.id).slice(0, 60)}`, target: { id: target.id, applicationId: target.applicationId },
    origins: [...new Set([...contactedEndpoints(target), ...origins])],
    identities: [...new Set(Object.values(target.actors ?? {}).filter(actor => actor && Object.hasOwn(actor, 'credentialEnv')).map(actor => actor.principalId))],
    validFrom: at(Date.now() - DAY), validUntil: at(Date.now() + 30 * DAY), signer: { name: 'Test owner', role: 'Owner of the synthetic target' }, signedAt: at(Date.now() - DAY) };
  if (!record.identities.length) record.identities = ['no-credentialed-actor'];
  edit(record);
  return checksumAuthorization(record);
}
// Writes the record (mode 0600) and returns its path.
export function writeTestAuthorization(path, target, options) {
  writeFileSync(path, JSON.stringify(testAuthorization(target, options)), { mode: 0o600 });
  return path;
}
// The --authorization arguments for a sequence run: a record naming the sequence, --origin, the observers and the
// hold gate's upstream (when one is used), written beside the run's other files.
export function sequenceAuthorizationArgs(path, sequence, { origin, observers = [], gateUpstream } = {}) {
  return ['--authorization', writeTestAuthorization(path, { id: sequence.id, applicationId: sequence.applicationId, origin, observers, actors: sequence.actors }, { origins: gateUpstream === undefined ? [] : [gateUpstream] })];
}
// The --authorization arguments for a conversation spec: its observers read the spec's own origin, so the record
// names the spec, that origin and its credentialed actors.
export function conversationAuthorizationArgs(path, spec) {
  return ['--authorization', writeTestAuthorization(path, { id: spec.id, applicationId: spec.applicationId, origin: spec.origin, actors: spec.actors })];
}
