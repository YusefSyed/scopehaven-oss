import { createServer } from 'node:http';
import { readFile, open, rename, unlink } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, resolve } from 'node:path';
import { SUITE } from './suite.mjs';
import { compareRuns } from './runner.mjs';
import { createRegistry, loadProfiles } from './registry.mjs';
import { createStore } from './store.mjs';
import { renderReport } from './report.mjs';
import { json, body, record, localHostAllowed, idValid, singleHeader } from './http.mjs';
import { assertRuntime } from './runtime.mjs';
import { needsAuthorization, WINDOW_ENDED } from './authorization.mjs';
import { authorizeConfigured } from './authorization-file.mjs';
import { ownedTapConfig } from './http-model-identity.mjs';
import { createLocalAccess, renderLaunchPage } from './local-access.mjs';
import { summarizeGate } from '../integrations/regression-gate/gate.mjs';
import { importPromptfooJson, INPUT_CONTRACT, LIMITS as IMPORT_LIMITS } from '../integrations/evaluation-import/import.mjs';
import packageInfo from '../package.json' with { type: 'json' };

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const assets = { '/': ['index.html', 'text/html'], '/index.html': ['index.html', 'text/html'], '/workbench-host.js': ['workbench-host.js', 'text/javascript'], '/access.css': ['access.css', 'text/css'] };
for (const [name, type] of [['dashboard.mjs', 'text/javascript'], ['adapter.mjs', 'text/javascript'], ['dashboard.css', 'text/css']]) assets[`/dashboard/${name}`] = [`dashboard/${name}`, type];
for (const [name, type] of [['index.html', 'text/html'], ['styles.css', 'text/css'], ['intro.js', 'text/javascript'], ['particle-scene.js', 'text/javascript']]) assets[`/intro/${name}`] = [`intro/${name}`, type];
assets['/intro/'] = assets['/intro/index.html'];
const SHELL_PATHS = new Set(['/', '/index.html', '/intro/', '/intro/index.html']);
// Error responses are { error, code }. `error` is fixed copy without paths, keys or
// stack traces; `code` is stable for clients. A failed assessment says so; anything
// else keeps its status with generic copy.
const GENERIC_ERRORS = { 400: ['invalid-request', 'The request or target configuration is invalid.'], 401: ['access-required', 'Local workbench access is required.'], 403: ['forbidden', 'This operation is not permitted.'], 404: ['not-found', 'The requested evidence was not found.'], 409: ['conflict', 'The operation conflicts with current work or existing evidence.'], 413: ['too-large', 'The request or evidence exceeds its size limit.'], 415: ['unsupported-content-type', 'JSON content type required.'], 507: ['storage-quota-reached', 'Evidence storage quota reached. Existing evidence has been preserved.'] };
export function publicError(error) {
  const status = Object.hasOwn(GENERIC_ERRORS, error?.status) ? error.status : 500;
  if (status === 500 && error?.assessmentFailed) return { status, body: { error: 'The assessment could not complete, so no run was saved.', code: 'assessment-failed' } };
  const [code, copy] = GENERIC_ERRORS[status] || ['internal-error', 'The operation failed. Evidence may be unavailable or failed its integrity check.'];
  return { status, body: { error: copy, code } };
}
export async function startServer({ port = 4317, dataDir = resolve(root, 'data'), assess, profiles = [], env = process.env, accessToken, accessOptions = {}, storeOptions = {}, authorizationFile } = {}) {
  // A listen options object can override the host argument. Refuse it before
  // initializing access, targets or storage so this server stays loopback-only.
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error('Server port must be an integer from 0 to 65535; the listener always binds 127.0.0.1.');
  assertRuntime();
  const access = createLocalAccess({ ...accessOptions, ...(accessToken ? { token: accessToken } : {}) });
  const registry = createRegistry({ profiles, env });
  const assessTarget = assess || registry.run;
  const store = createStore(dataDir, storeOptions); await store.ready; let active = false, previewing = false;
  const server = createServer({ maxHeaderSize: 8192, connectionsCheckingInterval: 1000 }, async (req, res) => {
    res.setHeader('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'");
    res.setHeader('X-Content-Type-Options', 'nosniff'); res.setHeader('Referrer-Policy', 'no-referrer'); res.setHeader('Cache-Control', 'no-store');
    try {
      const address = server.address();
      if (!localHostAllowed(req, address)) return json(res, 403, { error: 'Invalid host. Use the displayed 127.0.0.1 address.', code: 'invalid-host' });
      const origin = `http://127.0.0.1:${address.port}`;
      // The private launch page is opened from disk, so browsers mark its link as a cross-site navigation.
      // Only a top-level GET of an HTML shell is let through: the capability stays in the URL fragment, which
      // is never sent, and every API, asset and POST request keeps the strict check.
      const shellNavigation = req.method === 'GET' && SHELL_PATHS.has(new URL(req.url, origin).pathname) && singleHeader(req, 'sec-fetch-mode') === 'navigate' && singleHeader(req, 'sec-fetch-dest') === 'document';
      if ((req.headers.origin && req.headers.origin !== origin) || (req.headers['sec-fetch-site'] === 'cross-site' && !shellNavigation)) return json(res, 403, { error: 'Cross-origin access denied.', code: 'cross-origin-denied' });
      if (!['GET', 'POST'].includes(req.method)) return json(res, 405, { error: 'Method not supported.', code: 'method-not-supported' });
      if (req.method === 'POST' && req.headers['x-scopehaven-request'] !== '1') return json(res, 403, { error: 'Explicit local request header required.', code: 'local-request-header-required' });
      const url = new URL(req.url, origin), path = url.pathname;
      if (req.method === 'GET' && Object.hasOwn(assets, path)) {
        if (path.startsWith('/intro/')) res.setHeader('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'none'; connect-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'");
        const [filename, type] = assets[path]; const data = await readFile(resolve(root, 'public', filename));
        res.writeHead(200, { 'Content-Type': `${type}; charset=utf-8` }); return res.end(data);
      }
      if (req.method === 'GET' && path === '/api/access-info') return json(res, 200, { authenticationRequired: true, method: 'per-launch local capability', expiresAt: access.expiresAt });
      if (path.startsWith('/api/') && !access.authorize(req)) { res.setHeader('Connection', 'close'); return json(res, 401, { error: 'Unlock this local workbench using its private launch page or access key.', code: 'access-required' }); }
      if (req.method === 'POST' && path === '/api/external-evaluations/preview') {
        // Only caller-supplied text is accepted. Never resolve a supplied path,
        // fetch a URL, persist the source, or promote it into native run storage.
        // One preview at a time: a body may be twice the 16 MiB input limit, so a second preview is refused before its
        // body is read, and memory stays at one preview's peak.
        if (previewing) { res.setHeader('Retry-After', '1'); return json(res, 429, { error: 'Another external evaluation preview is running. Try again after it finishes.', code: 'preview-in-progress' }); }
        previewing = true;
        try {
          const input = await body(req, 2 * IMPORT_LIMITS.maxBytes);
          if (!record(input) || Object.keys(input).some(key => !['format', 'content'].includes(key)) || typeof input.content !== 'string') return json(res, 400, { error: 'Provide an explicit versioned format and JSON text.', code: 'invalid-request' });
          const result = importPromptfooJson(input.content, input.format);
          return json(res, result.ok ? 200 : result.error.code === 'input_limit' ? 413 : 400, result.ok ? result : { ...result, error: result.error.message, code: result.error.code });
        } finally { previewing = false; }
      }
      if (req.method === 'GET' && path === '/api/bootstrap') {
        const history = await store.historyPage();
        return json(res, 200, { product: { name: 'Scopehaven', version: packageInfo.version, mode: 'Local application assessments', description: 'Test. Investigate. Repair. Verify.', hasConfiguredTargets: registry.hasProfiles }, capabilities: { pilotEvidence: { freshExecution: 'cli-only' }, externalPreview: { format: INPUT_CONTRACT, maxBytes: IMPORT_LIMITS.maxBytes, retained: false }, savedRunGate: true, scheduling: false }, suite: SUITE, targets: registry.list(), runs: history.runs, history: { nextCursor: history.nextCursor, total: history.total } });
      }
      if (req.method === 'GET' && path === '/api/history') return json(res, 200, await store.historyPage({ limit: url.searchParams.has('limit') ? Number(url.searchParams.get('limit')) : 50, before: url.searchParams.get('before') || undefined }));
      if (req.method === 'GET' && path === '/api/suite/export.json') {
        res.setHeader('Content-Disposition', 'attachment; filename="scopehaven-check-definitions.json"');
        const targetId = url.searchParams.get('targetId');
        const refund = registry.list().some(target => target.id === targetId && target.kind === 'owned-refund-contract');
        return json(res, 200, refund ? await registry.currentSuite(targetId) : registry.exportSuite(targetId));
      }
      if (req.method === 'POST' && path === '/api/runs') {
        const input = await body(req);
        if (!record(input) || Object.keys(input).some(k => k !== 'targetId') || !registry.has(input.targetId)) return json(res, 400, { error: 'Choose an existing configured local target.', code: 'invalid-target' });
        if (active) return json(res, 409, { error: 'Another assessment is running. Try again after it finishes.', code: 'assessment-in-progress' });
        active = true;
        try {
          // A configured target runs only under an authorization record that covers it now. The record is
          // read from authorizationFile (SCOPEHAVEN_AUTHORIZATION_FILE) at each run and checked before any request is
          // sent; a refusal is a 403 with the refusal's code. Built-in fixture targets need none and keep their shape.
          // The window is checked again before every request the run sends and when each observer call it makes starts,
          // and once more immediately before the run is saved: once it ends, no further request is sent and no further
          // observer call starts (one already running can finish its reads), and the run is refused (403,
          // authorization-window-ended), never saved or stamped.
          let authorization = null, granted = null;
          if (needsAuthorization(registry.list().find(t => t.id === input.targetId))) {
            try { granted = await authorizeConfigured(profiles.find(p => p.id === input.targetId), authorizationFile, { alsoContacts: [ownedTapConfig(env)?.upstream].filter(upstream => upstream !== undefined) }); authorization = granted.stamp; }
            catch (error) {
              const code = error?.name === 'AuthorizationError' ? error.code : 'authorization-invalid';
              return json(res, 403, { error: code === 'authorization-missing' ? 'This configured target needs an authorization record. Restart the workbench with SCOPEHAVEN_AUTHORIZATION_FILE naming one (docs/RULES-OF-ENGAGEMENT.md); nothing was sent.'
                : `The authorization record was refused (${error?.name === 'AuthorizationError' ? error.message : 'unreadable'}); nothing was sent.`, code });
            }
          }
          const windowEnded = () => json(res, 403, { error: 'The authorization record\'s window ended before the run was saved: nothing more was sent, and no run was saved.', code: WINDOW_ENDED });
          let run;
          try { run = await assessTarget(input.targetId, granted ? { beforeRequest: granted.window.check, remote: granted.remote } : undefined); }
          catch (error) {
            if (granted?.window.ended()) return windowEnded();
            // A remote target the connector refused (src/remote-target.mjs): its code, with fixed copy; no run is saved.
            if (error?.name === 'RemoteTargetError') return json(res, 403, { error: `The remote target was refused (${error.code}); no run was saved.`, code: error.code });
            throw Object.assign(error ?? new Error(), { assessmentFailed: true });
          }
          // The window once more, immediately before the run is saved and stamped.
          if (granted) { try { granted.window.check(); } catch { return windowEnded(); } }
          return json(res, 201, await store.save(authorization ? { ...run, authorization } : run));
        } finally { active = false; }
      }
      if (req.method === 'GET' && path === '/api/compare') {
        const baseline = await store.get(url.searchParams.get('baseline')), candidate = await store.get(url.searchParams.get('candidate'));
        return json(res, 200, compareRuns(baseline, candidate));
      }
      const match = /^\/api\/runs\/([^/]+)(?:\/(notes|export\.json|report\.html|gate))?$/.exec(path);
      if (match) {
        const [, id, action] = match;
        if (!idValid(id)) return json(res, 400, { error: 'Invalid run identifier.', code: 'invalid-run-id' });
        if (req.method === 'GET' && action === 'gate') {
          const candidate = await store.get(id), baselineId = url.searchParams.get('baseline');
          const baseline = baselineId ? await store.get(baselineId) : null;
          const expectedSuite = registry.has(candidate.targetId) ? await registry.currentSuite(candidate.targetId) : { checks: [], hash: '' };
          return json(res, 200, { ...summarizeGate({ candidate, baseline, expectedSuite }), evaluationMode: 'saved-evidence', assessmentExecuted: false, scheduled: false });
        }
        if (req.method === 'POST' && action === 'notes') {
          const input = await body(req);
          if (!record(input) || Object.keys(input).some(k => !['caseId', 'note'].includes(k))) return json(res, 400, { error: 'Only a case identifier and human note may be edited.', code: 'invalid-note' });
          return json(res, 200, await store.note(id, input.caseId, input.note));
        }
        if (req.method === 'GET' && (!action || action === 'export.json')) {
          const run = await store.get(id);
          if (action) res.setHeader('Content-Disposition', `attachment; filename="scopehaven-${id}.json"`);
          return json(res, 200, run);
        }
        if (req.method === 'GET' && action === 'report.html') {
          const run = await store.get(id);
          res.setHeader('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'");
          res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Content-Disposition': `attachment; filename="scopehaven-${id}.html"` }); return res.end(renderReport(run));
        }
      }
      return json(res, 404, { error: 'Not found.', code: 'not-found' });
    } catch (error) {
      if (!res.headersSent && !res.destroyed) { const failure = publicError(error); json(res, failure.status, failure.body); }
    }
  });
  // Keep raw headers intact for duplicate detection; localHostAllowed applies
  // the explicit 40-header limit, while the parser enforces the byte limit.
  server.requestTimeout = 10000; server.headersTimeout = 5000; server.maxHeadersCount = 0; server.maxConnections = 32; server.maxRequestsPerSocket = 100; server.keepAliveTimeout = 1000;
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, '127.0.0.1', resolve); });
  return { server, store, accessToken: access.token, accessExpiresAt: access.expiresAt, origin: `http://127.0.0.1:${server.address().port}`, close: () => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }) };
}
if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  const port = Number(process.env.SCOPEHAVEN_PORT || 4317);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('SCOPEHAVEN_PORT must be a valid port.');
  const profiles = await loadProfiles(process.env.SCOPEHAVEN_TARGETS_FILE);
  const app = await startServer({ port, profiles, ...(process.env.SCOPEHAVEN_AUTHORIZATION_FILE ? { authorizationFile: resolve(process.env.SCOPEHAVEN_AUTHORIZATION_FILE) } : {}) });
  const launchPath = resolve(root, 'data/local-access.html'), temporary = resolve(root, 'data', `.${randomUUID()}.launch.tmp`);
  try {
    const handle = await open(temporary, 'wx', 0o600);
    try { await handle.writeFile(renderLaunchPage(app.origin, app.accessToken)); await handle.sync(); } finally { await handle.close(); }
    await rename(temporary, launchPath);
  } catch (error) { await app.close(); throw error; }
  finally { await unlink(temporary).catch(() => {}); }
  console.log(`Scopehaven local prototype: ${app.origin}`);
  console.log(`Private launch page (keep local): ${launchPath}`);
  for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, async () => { await app.close(); process.exit(0); });
}
