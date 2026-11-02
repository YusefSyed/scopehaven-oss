// Operator-forwarded staging: a forwarder that answers or alters one route itself (a deny rule on
// /admin/*, credentials stripped on that route, an auth gate that answers everything) makes a boundary check on
// that route read pass with every login proven (integrations/forwarded/README.md). What catches
// it is a required allowed-use control on the same route, through the same forwarder, that passed: the forwarder
// that denies or strips the forbidden request denies or strips the allowed one too.
//
// So in a forwarded run a boundary pass counts toward a clean gate, and a clean assess exit, only when a required
// control with the same method on the same route passed in the same run. The row itself keeps its verdict (this
// module is outside the HTTP evaluator identity and never changes a row); the gate reports the unpaired passes as
// forwarded-pass-unpaired and assess exits 1. Local-app runs are unaffected.
//
// The same route: the same number of path segments, each the same literal, or a record position in both (two
// different records, such as the owner's note and another user's, are the same route). Read from each row's
// recorded method and route segments (keyed digests, comparable within one run), or from a profile's paths. A
// route of one record position, which is also how a path the route reader cannot split reads (one with a query,
// for example), pairs only with the identical path (its recorded requestPathHash).
// What no single run can show stays the operator's statement in the authorization record: the wrong upstream
// serving the same accounts, a response cache kept across runs, a gate that refuses only signed-out requests.
// A remote target reached directly has the same exposure: a CDN, WAF or gateway in front of it can answer
// a route itself. Its unpaired passes are remote-pass-unpaired.
import { pathSegments } from './http-rests-on.mjs';

export const FORWARDED_UNPAIRED = 'forwarded-pass-unpaired', REMOTE_UNPAIRED = 'remote-pass-unpaired';
// The gate reason for a run's context, or null for a context the rule does not apply to (a local app).
export const unpairedReasonOf = context => context === 'operator-forwarded' ? FORWARDED_UNPAIRED : context === 'operator-remote' ? REMOTE_UNPAIRED : null;
const sameRoute = (a, b) => Array.isArray(a) && Array.isArray(b) && a.length > 0 && a.length === b.length && a.every((segment, i) => {
  const other = b[i];
  if (segment === null || typeof segment !== 'object' || other === null || typeof other !== 'object') return false;
  const record = Object.hasOwn(segment, 'record'), otherRecord = Object.hasOwn(other, 'record');
  return record || otherRecord ? record && otherRecord : typeof segment.exact === 'string' && segment.exact === other.exact;
});
const evidenceOf = row => row?.trace?.[0]?.data ?? null;
const lone = segments => Array.isArray(segments) && segments.length === 1 && segments[0] !== null && typeof segments[0] === 'object' && Object.hasOwn(segments[0], 'record');
const pairs = (control, own, samePath) => control.method === own.method && sameRoute(control.route, own.route) && (!lone(own.route) || samePath);

// The boundary rows of a saved forwarded run that read pass with no passing same-route required control.
export function unpairedForwardedPasses(run) {
  if (!unpairedReasonOf(run?.targetContext) || !Array.isArray(run.results)) return [];
  const required = new Set(Array.isArray(run.requiredControlIds) ? run.requiredControlIds : []);
  const controls = run.results.filter(row => row?.severity === 'control' && required.has(row.id) && row.status === 'pass').map(evidenceOf).filter(Boolean);
  return run.results.filter(row => row?.severity !== 'control' && row?.status === 'pass').filter(row => {
    const own = evidenceOf(row);
    return !own || !controls.some(control => pairs({ method: control.method, route: control.routeSegments }, { method: own.method, route: own.routeSegments },
      typeof own.requestPathHash === 'string' && own.requestPathHash === control.requestPathHash));
  }).map(row => row.id);
}

// The same rule read from a forwarded profile before any run (check-config): its boundary checks with no required
// control of the same method on the same route (a lone record position, or a path the route reader cannot split,
// only with the identical path).
export function forwardedPairingGaps(profile) {
  if (!unpairedReasonOf(profile?.targetContext) || !Array.isArray(profile.checks)) return [];
  const required = new Set(Array.isArray(profile.requiredControlIds) ? profile.requiredControlIds : []);
  const route = check => { const segments = pathSegments(check.path); return Array.isArray(segments) ? segments.map(s => Object.hasOwn(s, 'record') ? { record: true } : { exact: s.exact }) : null; };
  const controls = profile.checks.filter(check => check.severity === 'control' && required.has(check.id)).map(check => ({ method: check.method, route: route(check), path: check.path }));
  return profile.checks.filter(check => check.severity !== 'control' && check.applicability?.applies !== false)
    .filter(check => !controls.some(control => pairs(control, { method: check.method, route: route(check) }, control.path === check.path))).map(check => check.id);
}
