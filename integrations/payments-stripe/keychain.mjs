// The stage-2 key reader: reads one generic password from the macOS Keychain with
// `security find-generic-password -a <account> -s <service> -w` into memory and returns it. The value is never printed, logged,
// written or put in an error message: a failure says only which item and why (missing, unreadable, empty or malformed). describeKey()
// is what may be shown: whether a value is present, its prefix class and its length, never any of its characters.
// Tests pass a stub `security` binary (securityBin); no test reads the real Keychain.
import { execFile } from 'node:child_process';

export const KEYCHAIN_ACCOUNT = 'scopehaven';
export const STAGE2_SERVICES = Object.freeze({ desk: 'scopehaven-stripe-n14-desk', read: 'scopehaven-stripe-n14-read' });
const SERVICE = /^[a-z0-9][a-z0-9-]{2,63}$/;
const CLASSES = Object.freeze([['rk_test', /^rk_test_/], ['sk_test', /^sk_test_/], ['rk_live', /^rk_live_/], ['sk_live', /^sk_live_/], ['pk', /^pk_(?:test|live)_/]]);
export const RESTRICTED_TEST_KEY = /^rk_test_[A-Za-z0-9]{16,128}$/;

// Presence, prefix class and length only.
export function describeKey(value) {
  if (typeof value !== 'string' || !value.length) return { present: false, class: null, length: 0, restrictedTestKey: false };
  const found = CLASSES.find(([, re]) => re.test(value));
  return { present: true, class: found ? found[0] : 'other', length: value.length, restrictedTestKey: RESTRICTED_TEST_KEY.test(value) };
}

export function readKeychainSecret(service, { account = KEYCHAIN_ACCOUNT, securityBin = '/usr/bin/security', timeoutMs = 10000 } = {}) {
  if (typeof service !== 'string' || !SERVICE.test(service)) return Promise.reject(new Error('service is a Keychain item name (lowercase letters, digits, dashes).'));
  if (typeof account !== 'string' || !SERVICE.test(account)) return Promise.reject(new Error('account is a Keychain account name.'));
  return new Promise((resolve, reject) => {
    // No shell; the value comes back on stdout and stays in this closure. stderr is discarded, so nothing the tool prints is kept.
    execFile(securityBin, ['find-generic-password', '-a', account, '-s', service, '-w'], { timeout: timeoutMs, maxBuffer: 64 * 1024, encoding: 'utf8', shell: false, env: { PATH: '/usr/bin:/bin' } }, (error, stdout) => {
      if (error) return reject(new Error(`Keychain item ${service} (account ${account}) could not be read: ${error.code === 44 ? 'not found' : error.killed ? 'timed out' : 'the security tool failed'}.`));
      const value = String(stdout).replace(/\n$/, '');
      if (!value.length) return reject(new Error(`Keychain item ${service} is empty.`));
      if (/\s/.test(value)) return reject(new Error(`Keychain item ${service} holds whitespace; store the key alone.`));
      resolve(value);
    });
  });
}

// Both stage-2 keys, checked: each a restricted test key (rk_test_), and the two different. Returns { desk, read } in memory and the
// shareable description of each.
export async function readStage2Keys(options = {}) {
  const desk = await readKeychainSecret(STAGE2_SERVICES.desk, options), read = await readKeychainSecret(STAGE2_SERVICES.read, options);
  const described = { desk: describeKey(desk), read: describeKey(read) };
  for (const [name, d] of Object.entries(described)) if (!d.restrictedTestKey) throw new Error(`the ${name} key is not a restricted test key (class ${d.class}, length ${d.length}); stage 2 takes rk_test_ keys only.`);
  if (desk === read) throw new Error('the desk key and the read key are the same key; stage 2 needs two keys.');
  return { keys: { desk, read }, described };
}
