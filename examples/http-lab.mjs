import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import { open, rename, unlink } from 'node:fs/promises';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { resolve } from 'node:path';
import { createStore } from '../src/store.mjs';
import { assertRuntime } from '../src/runtime.mjs';
import { checksumAuthorization, AUTHORIZATION_SCHEMA } from '../src/authorization.mjs';

export function makeLabProfile(origin, buildLabel = 'lab-repaired') {
  const status = expected => ({ kind: 'status.equals', expected });
  const base = (id, title, severity, actorId, path, assertions, evidenceRequirement = 'response') => ({ id, title, category: 'Local application contracts', severity, actorId, method: 'GET', path, evidenceRequirement, assertions });
  return {
    id: 'http-lab', name: 'Separate HTTP application', applicationId: 'owned-http-lab', origin, buildLabel, contextId: 'synthetic-records-v1',
    actors: { member: { credentialEnv: 'SCOPEHAVEN_TARGET_LAB_MEMBER_TOKEN', identityValue: 'lab-member-aster', principalId: 'lab-member-aster', tenantId: 'aster', role: 'member' }, anonymous: { principalId: 'anonymous' } },
    requiredControlIds: ['WHOAMI', 'OWN-RECORD', 'IDENTITY'], checks: [
      base('WHOAMI', 'The configured account is a member', 'control', 'member', '/me', [status(200), { kind: 'json.equals', pointer: '/role', expected: 'member' }]),
      base('OWN-RECORD', 'The member receives their own record', 'control', 'member', '/records/own', [status(200), { kind: 'json.equals', pointer: '/record/tenant', expected: 'aster' }]),
      base('FOREIGN-STATUS', 'The foreign-record endpoint returns a denial', 'high', 'member', '/records/foreign', [status(403)]),
      base('ANONYMOUS', 'An anonymous request receives 401', 'high', 'anonymous', '/records/own', [status(401)]),
      base('BACKEND-UNVERIFIED', 'Protected content is not retrieved internally', 'critical', 'member', '/records/foreign', [status(403), { kind: 'json.notContains', pointer: '/reply', expected: 'COBALT_LAB_PRIVATE' }], 'backend'),
      { ...base('ECHO', 'A JSON POST completes its response contract', 'low', 'member', '/echo', [status(200), { kind: 'json.equals', pointer: '/accepted', expected: true }]), method: 'POST', body: { message: 'synthetic local test' } },
      // Positive identity evidence: the session names this member. Appended so earlier check indexes stay stable.
      base('IDENTITY', 'The session belongs to the configured member', 'control', 'member', '/me', [status(200), { kind: 'json.equals', pointer: '/principalId', expected: 'lab-member-aster' }]),
    ],
  };
}

export async function createHttpLab({ port = 0, build = 'repaired' } = {}) {
  assertRuntime();
  const memberToken = randomBytes(24).toString('base64url'); let mode = build;
  const server = createServer(async (req, res) => {
    const send = (status, value) => { res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }); res.end(JSON.stringify(value)); };
    // Nothing may escape this async handler: an unhandled rejection ends the lab process.
    try { await handle(req, res, send); } catch { try { if (!res.headersSent) send(500, { reply: 'Internal error.' }); else res.end(); } catch { res.destroy(); } }
  });
  async function handle(req, res, send) {
    if (req.headers.host !== `127.0.0.1:${server.address().port}` || req.headers.origin) return send(403, { reply: 'Forbidden.' });
    let path;
    try { path = new URL(req.url, 'http://owned-lab.local').pathname; } catch { return send(400, { reply: 'Bad request.' }); } // "//" is no URL
    // Like many web apps, the lab accepts its session as a Bearer header or as a
    // `lab_session` cookie (profile actor field "credentialCookie": "lab_session").
    const cookieSession = (req.headers.cookie || '').split(';').map(part => part.trim()).includes(`lab_session=${memberToken}`);
    if (req.headers.authorization !== `Bearer ${memberToken}` && !cookieSession) return send(401, { reply: 'Authentication required.' });
    if (req.method === 'GET' && path === '/me') return send(200, { role: 'member', tenant: 'aster', principalId: 'lab-member-aster' });
    if (req.method === 'GET' && path === '/records/own') return send(200, { record: { tenant: 'aster', label: 'Owned synthetic record' } });
    if (req.method === 'GET' && path === '/records/foreign') return mode === 'baseline' ? send(200, { reply: 'COBALT_LAB_PRIVATE', record: { tenant: 'cobalt' } }) : send(403, { reply: 'Access denied.' });
    if (req.method === 'POST' && path === '/echo') {
      let bytes = 0;
      for await (const chunk of req) { bytes += chunk.length; if (bytes > 8192) return send(413, { reply: 'Too large.' }); }
      // Intentional echo in an owned lab proves the connector does not persist
      // secrets or arbitrary target response text. These never leave loopback.
      return send(200, { accepted: true, credentialEcho: memberToken, arbitraryCustomerText: 'SYNTHETIC_PRIVATE_RESPONSE_DO_NOT_STORE' });
    }
    send(404, { reply: 'Not found.' });
  }
  server.requestTimeout = 5000;
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, '127.0.0.1', resolve); });
  return { origin: `http://127.0.0.1:${server.address().port}`, memberToken,
    setBuild: value => { if (!['baseline', 'repaired'].includes(value)) throw new Error('Unknown lab build.'); mode = value; },
    close: () => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }) };
}

// The lab's own authorization record: the owned synthetic lab, its loopback origin and its member
// account, from a minute ago for one day. Synthetic: it authorizes requests to this lab only.
export function makeLabAuthorization(origin, { now = new Date(), hours = 24 } = {}) {
  const at = ms => new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z');
  return checksumAuthorization({ schema: AUTHORIZATION_SCHEMA, id: 'owned-http-lab', target: { id: 'http-lab', applicationId: 'owned-http-lab' }, origins: [origin], identities: ['lab-member-aster'],
    validFrom: at(now.getTime() - 60000), validUntil: at(now.getTime() + hours * 3600000), signer: { name: 'Scopehaven owned lab', role: 'Owner of the synthetic lab' }, signedAt: at(now.getTime() - 60000) });
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  const ipc = process.env.SCOPEHAVEN_LAB_IPC === '1' && Boolean(process.send);
  const lab = await createHttpLab({ port: ipc ? 0 : Number(process.env.SCOPEHAVEN_LAB_PORT || 4319), build: ipc ? 'baseline' : 'repaired' });
  if (ipc) {
    process.send({ type: 'ready', origin: lab.origin, memberToken: lab.memberToken });
    process.on('message', message => { if (message?.type === 'build' && ['baseline', 'repaired'].includes(message.build)) { lab.setBuild(message.build); process.send({ type: 'build-ready' }); } });
  } else {
    const root = fileURLToPath(new URL('../', import.meta.url));
    await createStore(resolve(root, 'data')).ready;
    const privateWrite = async (name, content) => {
      const temporary = resolve(root, 'data', `.${randomBytes(16).toString('hex')}.lab.tmp`);
      try {
        const handle = await open(temporary, 'wx', 0o600);
        try { await handle.writeFile(content); await handle.sync(); } finally { await handle.close(); }
        await rename(temporary, resolve(root, 'data', name));
      } finally { await unlink(temporary).catch(() => {}); }
    };
    await privateWrite('http-lab.env', `SCOPEHAVEN_TARGET_LAB_MEMBER_TOKEN=${lab.memberToken}\n`);
    await privateWrite('http-lab.targets.json', JSON.stringify({ schemaVersion: 1, targets: [makeLabProfile(lab.origin)] }, null, 2));
    await privateWrite('http-lab.authorization.json', JSON.stringify(makeLabAuthorization(lab.origin), null, 2));
    console.log(`Owned HTTP lab: ${lab.origin}`);
    console.log('Synthetic credentials, profile and authorization record saved in ignored data/http-lab.env, data/http-lab.targets.json and data/http-lab.authorization.json. No credential values are printed.');
  }
  for (const event of ['SIGINT', 'SIGTERM', 'disconnect']) process.on(event, async () => { await lab.close(); process.exit(0); });
}
