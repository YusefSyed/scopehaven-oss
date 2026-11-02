// The documents describe the model identity behaviour that ships.
// Reads local files only.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { OWNED_TAP_ENV } from '../src/http-model-identity.mjs';

const read = path => readFile(new URL(`../${path}`, import.meta.url), 'utf8');
const DOCS = ['README.md', 'docs/ONBOARDING.md', 'integrations/model-identity/README.md', 'integrations/regression-gate/README.md', 'integrations/github-action/README.md'];

test('no document says the connector does not record a model identity, or that the action has no strict input', async () => {
  for (const path of DOCS) {
    const text = await read(path);
    assert.doesNotMatch(text, /does not write (a model identity|`modelIdentity`)|into runs yet|cannot occur here|has no input for/, path);
    assert.doesNotMatch(text, /vendor reports do not pin weights/, path);
  }
});

test('the gate guide lists every strict reason in its exit table and the no-baseline refusal', async () => {
  const text = await read('integrations/regression-gate/README.md');
  const exit1 = text.split('\n').find(line => line.startsWith('| `1` |'));
  for (const reason of ['repair-not-attributable', 'model-identity-malformed', 'model-identity-not-recorded', 'model-identity-unverified']) assert.ok(exit1.includes(`\`${reason}\``), reason);
  const exit2 = text.split('\n').find(line => line.startsWith('| `2` |'));
  assert.match(exit2, /--require-model-identity` without `--baseline`, `invalid-options`/);
});

test('every guide that describes the strict policy names custody and the owned-tap settings', async () => {
  for (const path of ['docs/ONBOARDING.md', 'integrations/model-identity/README.md', 'integrations/regression-gate/README.md', 'integrations/github-action/README.md']) {
    const text = await read(path);
    for (const term of ['`tap-memory`', '`subject-writable-custody`', OWNED_TAP_ENV.upstream, OWNED_TAP_ENV.port]) assert.ok(text.includes(term), `${path}: ${term}`);
  }
});

// What the strict policy cannot see (stored-run edits, calls around the tap), and the file reading's effect.
test('the strict sections state the stored-baseline and routing limits, and no guide calls a tap-file reading harmless', async () => {
  for (const path of ['integrations/github-action/README.md', 'integrations/regression-gate/README.md', 'integrations/model-identity/README.md', 'docs/ONBOARDING.md', 'integrations/github-action/action.yml']) {
    const text = await read(path);
    assert.match(text, /checksum, not a signature/, path);
    assert.match(text, /sees only calls sent to (its|the tap) port/, path);
    assert.doesNotMatch(text, /still compared as a reading/, path);
  }
  const action = await read('integrations/github-action/README.md');
  const table = action.slice(action.indexOf('## Inputs'), action.indexOf('## Outputs'));
  assert.match(table.split('\n').find(line => line.startsWith('| `require-model-identity` |')), /checksum, not a signature/);
  for (const path of ['integrations/github-action/README.md', 'integrations/regression-gate/README.md']) assert.match(await read(path), /model identity policy was not met/, path);
});

test('the onboarding guide names exactly the files the HTTP evaluator identity hashes', async () => {
  const source = await read('src/http-connector.mjs');
  // Paths as the guide writes them: src/ names bare, integration modules from the project root.
  const list = /const evaluatorHash = digest\(\(await Promise\.all\(\[([^\]]+)\]/.exec(source)[1].match(/'[^']+'/g).map(name => name.slice(1, -1).replace(/^\.\.\//, ''));
  // Captures, lifecycle and settlement add http-captures, http-lifecycle and http-settlement: nineteen files; pairing adds http-pairing: twenty;
  // declared body fields and claim rules add body-fields and http-claims: twenty-two; keyed retries
  // add idempotency: twenty-three; background attribution adds http-attribution: twenty-four;
  // the upstream outcome of a forwarded egress send adds effect-outcome: twenty-five;
  // the effect horizon and run budget add http-timing: twenty-six.
  // attribution through returned ids adds id-closure: twenty-seven.
  // the egress and SMTP collector digest adds collector-identity: twenty-eight.
  // the run-end drain record and its rules add run-end-drain: twenty-nine.
  // identity option B adds http-rests-on (the restsOn release, actor-identity/6): thirty.
  // the provider feed adds provider-feed-rules (its profile rules) and mail-address (the shared recipient rules): thirty-two.
  // value-leak adds tenant-values (json.noForeignValues): thirty-three.
  // app logs add app-log-rules (their declaration and line mapping) and app-log-verdicts (their records and binding): thirty-five.
  // later outcomes add later-outcome (the verdict stage over a provider feed's later outcomes): thirty-six.
  // suspend-aware custody time adds suspend-clock (the host suspend record and the settle extension): thirty-seven.
  // in-doubt resolution adds in-doubt (the resolution core and its transport-record resolver): thirty-eight.
  // the request feed adds request-feed-rules (its declaration and its in-doubt derivation) and key-identity (the key collapse's
  // identity and retention rule, moved out of idempotency so the request feed shares it): forty.
  // read-back adds read-back-rules (its declaration and its in-doubt derivation): forty-one.
  // other names of a declared provider add public-suffix (the registrable domain of a host) and public-suffix-list (the vendored
  // Public Suffix List subset, MPL-2.0): forty-three.
  // remote https targets add remote-target (a remote https target's origin form, address classes and DNS pin): forty-four.
  // signed webhooks add webhook-driver (the signed-webhook driver): forty-five.
  // catalog-identity (the run's catalog identity, which the shared validator checks) makes forty-six.
  // two-identities (the single-identity rule and the generated mirror checks) makes forty-seven.
  // read-back in HTTP checks adds http-readback (the read-back judgement, seal and recompute) and pg-readback (the declaration, record
  // and judge it uses): forty-nine.
  const words = ['zero', 'one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine', 'ten', 'eleven', 'twelve', 'thirteen', 'fourteen', 'fifteen', 'sixteen', 'seventeen', 'eighteen', 'nineteen', 'twenty', 'twenty-one', 'twenty-two', 'twenty-three', 'twenty-four', 'twenty-five', 'twenty-six', 'twenty-seven', 'twenty-eight', 'twenty-nine', 'thirty', 'thirty-one', 'thirty-two', 'thirty-three', 'thirty-four', 'thirty-five', 'thirty-six', 'thirty-seven', 'thirty-eight', 'thirty-nine', 'forty', 'forty-one', 'forty-two', 'forty-three', 'forty-four', 'forty-five', 'forty-six', 'forty-seven', 'forty-eight', 'forty-nine'];
  const text = await read('docs/ONBOARDING.md');
  const at = text.indexOf('The HTTP evaluator identity (`evaluatorHash`) is a digest of');
  assert.ok(at >= 0);
  const sentence = text.slice(at, text.indexOf('so it moves with any change', at));
  assert.ok(sentence.includes(`a digest of ${words[list.length]} source files`), sentence.slice(0, 120));
  assert.ok(sentence.includes(`${words[list.filter(name => !name.startsWith('integrations/')).length]} in \`src/\``), sentence.slice(0, 160));
  for (const name of list) assert.ok(sentence.includes(`\`${name}\``), name);
});
