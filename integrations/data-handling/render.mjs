// Renders docs/DATA-HANDLING.md from facts read out of the source, so the sheet cannot drift from the code.
//   node integrations/data-handling/render.mjs --write   (re)write docs/DATA-HANDLING.md
//   node integrations/data-handling/render.mjs --check   exit 1 when the committed sheet is stale
// Every fact is read from a named source file. A fact that can no longer be read, a network call site
// that is not in the reviewed list below, or a store method that could delete evidence fails the render.
import { execFileSync } from 'node:child_process';
import { lstat, readFile, writeFile } from 'node:fs/promises';
import { join, relative } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { MANIFEST_NAME, excluded } from '../../packaging/build-release.mjs';

export const ROOT = fileURLToPath(new URL('../..', import.meta.url));
export const SHEET = 'docs/DATA-HANDLING.md';

// The reviewed network call sites: every shipped code file that networkRules below matches, fixtures and vendored source
// included. A new site must be reviewed and added here.
export const SITES = Object.freeze({
  scopehaven: 'Launcher. Its doctor binds 127.0.0.1 on the port ./scopehaven start would use, to test that the port is free, and closes it. It connects to nothing, and never installs or downloads anything.',
  'design/dashboard/preview-server.mjs': 'Local dashboard preview server. Listens on 127.0.0.1 (default port 4392), serves an allowlist of preview files and refuses a foreign Host or Origin or a cross-site request. No outbound connections.',
  'design/dashboard/preview.mjs': 'Browser code of the dashboard preview. Fetches its preview data from a relative path on its own origin; the preview server\'s Content-Security-Policy limits connections to that origin.',
  'public/app.js': 'Workbench browser code. Fetches relative /api/ paths on the local server\'s own origin, and an export link only after checking it is that origin under /api/. src/server.mjs sets connect-src \'self\'.',
  'public/workbench-host.js': 'Workbench host browser code. Fetches /api/ paths on the local server\'s own origin only: route() refuses any other destination, and redirects are refused.',
  'integrations/conversations/fixtures/storefront.mjs': 'Test fixture: owned synthetic storefront with a deterministic assistant and no model. Listens on 127.0.0.1 and refuses a foreign Host or any Origin. No outbound connections.',
  'integrations/init/test/fixtures/two-tenant-app.mjs': 'Test fixture for init: owned two-tenant app. Listens on 127.0.0.1 at an OS-assigned port. No outbound connections.',
  'integrations/metamorphic/fixtures/owned-fixture-run.mjs': 'Test-only tenant-swap runner. Starts the built-in SupportDesk fixture on 127.0.0.1 and fetches only that fixture\'s origin; the model is scripted.',
  'integrations/observers/fixtures/egress-recorder-d349c7c.mjs': 'Frozen copy of an earlier egress recorder, for a compatibility test. Listens on 127.0.0.1 at the configured port, answers every request itself and never forwards.',
  'integrations/observers/fixtures/fake-mysql.mjs': 'Test-only scripted MySQL server. Listens on 127.0.0.1 at an OS-assigned port. No real database and no outbound connections.',
  'integrations/observers/fixtures/fake-postgres.mjs': 'Test-only scripted PostgreSQL server. Listens on 127.0.0.1 at an OS-assigned port. No real database and no outbound connections.',
  'integrations/observers/fixtures/free-port.mjs': 'Loopback port picker, imported by the class-template, core-practice, evidence-subject and temporal-contracts runners as well as tests. Probes by connecting to and binding ports on 127.0.0.1 and closes each probe; it sends nothing.',
  'integrations/observers/fixtures/provider-stub.mjs': 'Test-only provider stub. Serves a signed synthetic feed on 127.0.0.1 at an OS-assigned port, with keys generated per stub. No real provider and no outbound connections.',
  'integrations/observers/fixtures/refund-app.mjs': 'Test-only twin refund apps writing to a scripted fake PostgreSQL. Listen on 127.0.0.1 at an OS-assigned port and fetch only their own origin.',
  'integrations/packs-v2/fixtures/pack-app.mjs': 'Owned synthetic two-company app for the check packs\' run proofs. Listens on 127.0.0.1 at an OS-assigned port and refuses a foreign Host or any Origin. Its outbound requests go only to 127.0.0.1, at a port it picks at start.',
  'integrations/sequences/fixtures/mini-helpdesk.mjs': 'Owned synthetic helpdesk and fake model for observer and sequence tests. Both listen on 127.0.0.1 at OS-assigned ports. The helpdesk POSTs to the modelUrl and optional otlpUrl its caller passes and does not check that they are loopback.',
  'integrations/sequences/fixtures/ws-desk.mjs': 'Owned synthetic agent desk for websocket-step tests: a chat route and a websocket server on 127.0.0.1 at an OS-assigned port. It makes no outbound connection.',
  'integrations/sequences/fixtures/refund-desk.mjs': 'Owned synthetic refund desk and refund tools for lifecycle-sequence tests. Both listen on 127.0.0.1 at OS-assigned ports. The desk POSTs only to its upstream, which must be a literal http://127.0.0.1:PORT origin (checked at start).',
  'integrations/sequences/sweep/fixtures/relay-desk.mjs': 'Owned synthetic relay desk for the boundary sweep\'s tests: a backend and an agent app in one process, each on 127.0.0.1 at an OS-assigned port. The app POSTs to the upstream base URL its caller passes and does not check that it is loopback.',
  'integrations/temporal-contracts/fixtures/refund-app.mjs': 'Owned synthetic refund app for the temporal-contract runs. Listens on 127.0.0.1 at an OS-assigned port, refuses a foreign Host or any Origin, and POSTs refunds only to the local payment double at 127.0.0.1 on the port its caller passes.',
  'integrations/temporal-contracts/fixtures/refund-adversarial-app.mjs': 'Adversarial build of the synthetic refund app for temporal-contract tests. Listens on 127.0.0.1 at an OS-assigned port and POSTs refunds only to the local payment double at 127.0.0.1 on the port its caller passes.',
  'integrations/temporal-contracts/fixtures/review-v4-app.mjs': 'Review probes over the synthetic refund app. An optional proxy listens on 127.0.0.1 at an OS-assigned port and calls only that app; a gap refund POSTs only to the local payment double at 127.0.0.1.',
  'action.yml': 'GitHub composite action at the repository root, so a workflow elsewhere can use `YusefSyed/scopehaven-oss@<ref>` and Marketplace can list it. Its one step is `uses: $/integrations/github-action`, this repository\'s inner action at the running commit; it declares the same inputs and outputs, forwards them, and makes no network call of its own.',
  'integrations/github-action/action.yml': 'GitHub composite action, run on the runner of the repository that uses it. actions/setup-node provides Node.js 24.22.2 and downloads it if the runner lacks it; actions/upload-artifact uploads the export folder to the repository\'s workflow artifacts; github/codeql-action/upload-sarif uploads SARIF to code scanning only when upload-sarif is true (default false). All three are pinned to a commit.',
  'integrations/github-action/example-workflow.yml': 'Inert example, not installed as a workflow. Copied into a repository, it runs actions/checkout and actions/setup-node from GitHub, starts the owned lab on loopback and runs the local composite action.',
  'docs/demo/tools/record-frames.mjs': 'Demo recorder, run by hand to make the README GIF. Launches a local headless Chrome and talks only to its DevTools endpoint and the workbench, both on 127.0.0.1; loaded by nothing in the product or its tests.',
  'integrations/model-path/stacks/langgraph/app.py': 'LangGraph practice subject (Python), started by stacks.mjs. Listens on 127.0.0.1 at LG_PORT (default 4497). Its chat-model binding POSTs with httpx to LG_MODEL_BASE_URL/chat/completions and checks no host or port, so a non-loopback model origin is possible; stacks.mjs sets it from the caller\'s gateUrl (loopback in the reviewed runner). httpx does not follow redirects by default.',
  'src/server.mjs': 'Workbench server. Listens on 127.0.0.1 only.',
  'src/fixture.mjs': 'Built-in SupportDesk fixture. Listens on 127.0.0.1.',
  'src/runner.mjs': 'Reads fixture evidence; refuses any URL that is not http://127.0.0.1:PORT.',
  'src/http-connector.mjs': 'HTTP connector. A target is a literal http://127.0.0.1:PORT origin, or, declared operator-remote and only under an authorization record naming its exact origin, an https://host[:port] origin dialled over TLS (certificate verified for the host, TLS 1.2 or newer) at the one address resolved before the run; no redirects, proxy or connection reuse.',
  'src/remote-target.mjs': 'Remote target pin (operator-remote). Resolves the target host with the system resolver before the run and before each request, refuses a changed answer or a non-public address the authorization record does not name; opens no connection.',
  'src/confine.mjs': 'Confined launch (--confine). For its self-test it opens a canary listener on 127.0.0.1 (an OS-assigned port) and checks that a dial to [::1] at a sink port is refused (the canary bind there may fail, because the sink holds [::1]); its sandboxed probe children dial 127.0.0.1, [::1] and one interface address of this machine at those ports (nothing of ScopeHaven\'s listens at the interface address; the probe records whether the rule admits it). It dials 127.0.0.1 at the target origin to wait for readiness, reads the unified log (log stream), the process table (ps) and the listeners on the origin and sink ports (lsof). The application it starts runs under sandbox-exec with outbound connections refused except TCP/IPv4 to the declared sinks\' ports and a recorded allowlist.',
  'examples/http-lab.mjs': 'Owned HTTP lab app. Listens on 127.0.0.1.',
  'examples/app-log-notify-app.mjs': 'Owned example app for the app-log admission clean corpus. Listens on 127.0.0.1 and calls only the caller\'s egress recorder on 127.0.0.1.',
  'examples/observed-support-app.mjs': 'Owned example app for the onboarding profiles. Listens on 127.0.0.1.',
  'integrations/attest/countersign.mjs': 'Countersigning client, called only by `cli.mjs countersign`, which ScopeHaven runs with its key; a run, export or evidence pack never calls it. POSTs an RFC 3161 query holding only the SHA-256 of the countersignature and a random nonce to a time-stamping authority the key set names (https://freetsa.org/tsr in the published set), a non-loopback host. Refuses redirects. Sends no file, row or result.',
  'integrations/attest/test-tsa.mjs': 'Test-only RFC 3161 time-stamping authority for integrations/attest/countersign.test.mjs. Listens on 127.0.0.1 at an OS-assigned port, keeps nothing and makes no outbound connections.',
  'integrations/core-practice/app.mjs': 'Owned practice app for the core HTTP path (lifecycle, captures, settlement). Listens on 127.0.0.1 at an OS-assigned port, refuses non-loopback Host headers, and sends its webhooks only through the loopback egress recorder at 127.0.0.1 (proxy routing); nothing leaves the machine.',
  'integrations/access-change/desk.mjs': 'Owned synthetic desk. Listens on 127.0.0.1.',
  'integrations/data-handling/net-log.mjs': 'Zero-egress logger. Records connection attempts in the run it is loaded into; opens no connection.',
  'integrations/claim-check/cases.mjs': 'Claim-check cases against the owned desk on loopback.',
  'integrations/decision-effect/decision-log.mjs': 'Decision-log sink listens on 127.0.0.1 at an OS-assigned port. Exported engineServed and decisionWindow fetch a caller-supplied engine origin without enforcing loopback, so they can reach non-loopback hosts at the supplied port (default HTTP port 80); the shipped harness passes the loopback engine from engines.mjs. Redirects are not followed.',
  'integrations/decision-effect/desk.mjs': 'Synthetic refund desk listens on 127.0.0.1 at an OS-assigned port and asks only a loopback policy engine (it refuses any engine origin other than http://127.0.0.1). Redirects are not followed.',
  'integrations/decision-effect/engines.mjs': 'Starts policy engines bound to 127.0.0.1 at OS-assigned ports and logs to a loopback sink (non-loopback engine or sink origins are refused); OPA runs with telemetry and version checks disabled. Health checks do not follow redirects.',
  'integrations/claim-check/coverage-cases.mjs': 'Coverage-claim harness reads its owned 127.0.0.1 desk at an OS-assigned port. Exported reviewer/read helpers also accept caller-supplied HTTP origins without enforcing loopback, so they can reach non-loopback hosts at the supplied port (default HTTP port 80); redirects are not followed.',
  'integrations/claim-check/coverage-desk.mjs': 'Owned synthetic coverage-review desk. Listens on 127.0.0.1 at an OS-assigned port; serves authenticated ticket reads and records them in SQLite. No outbound connections.',
  'integrations/claim-check/desk.mjs': 'Owned synthetic refund desk. Listens on 127.0.0.1.',
  'integrations/conversations/conversation.mjs': 'Conversation connector. Origin must be a literal http://127.0.0.1:PORT.',
  'integrations/evaluation-import/promptfoo/egress-guard.mjs': 'Promptfoo egress guard, preloaded with --import. Opens no connection of its own; in its process it wraps Node DNS, net, tls, dgram and the raw network bindings to refuse and log non-loopback attempts (best effort: the OS sandbox profile is the barrier).',
  'integrations/evaluation-import/promptfoo/records-hook.mjs': 'Promptfoo records hook and assertion transport. POSTs only to SCOPEHAVEN_RECORDS_URL, which must be a literal http://127.0.0.1:PORT origin, and refuses redirects.',
  'integrations/evaluation-import/records-desk.mjs': 'Owned synthetic records desk. Listens on 127.0.0.1 at an OS-assigned port with a bearer check; with egressProxy (a literal http://127.0.0.1:PORT egress recorder) its outbound share and witness requests go only to that loopback sink, which never forwards.',
  'integrations/evaluation-import/verdict-service.mjs': 'Records verdict service. Listens on 127.0.0.1 with Host and bearer checks; sends per-window witness requests only to a declared literal http://127.0.0.1:PORT application origin and refuses redirects.',
  'integrations/evid-subject/corpus.mjs': 'Forgery corpus (test-only, not in TARGETS). Starts an owned tool service, the operator hold gate and the payments double, each on 127.0.0.1 at an OS-assigned or test-chosen port, and sends requests only to 127.0.0.1; destination names are routing labels, never resolved. No outbound connections.',
  'integrations/github-action/wait-for.mjs': 'CI readiness probe. Accepts only 127.0.0.1 or localhost, dialled as 127.0.0.1.',
  'integrations/init/probe.mjs': 'scopehaven init discovery (v0). Sends GET requests only to the literal 127.0.0.1 port of the base URL the operator gives (localhost is dialled as 127.0.0.1; any other host is refused), only after the operator confirmed and init sealed an authorization record naming that origin, each one checked against the record\'s window first. Follows no redirect, reads at most 64 KiB of each reply and keeps only its status, content type, Location path and, in memory, a parsed JSON body for the identity search; never stores a body. Sends the test identities\' credentials from the operator\'s 0600 env file only to that origin.',
  'integrations/guards/guarded-app.mjs': 'Owned guarded app. Listens on 127.0.0.1.',
  'integrations/kill-switch/agent-desk.mjs': 'Owned agent desk. Listens on 127.0.0.1.',
  'integrations/kill-switch/model-stub.mjs': 'Scripted model stand-in. Listens on 127.0.0.1.',
  'integrations/mcp-target/server.mjs': 'Owned synthetic MCP server. Listens on 127.0.0.1 at an OS-assigned port with Host/Origin and bearer checks; makes no outbound network calls.',
  'integrations/model-identity/stand-in.mjs': 'Always-attempt model stand-in. Listens on 127.0.0.1.',
  'integrations/model-identity/tap.mjs': 'Model tap. Listens on 127.0.0.1 and forwards to one operator-declared upstream: a literal loopback origin, or one of the hosted origins below.',
  'integrations/model-path/redirect-guard.mjs': 'Model redirect guard. Listens on 127.0.0.1 at an OS-assigned port and forwards only to a configured HTTP origin whose parsed host is 127.0.0.1 (supplied port, or 80 if omitted). Refuses every upstream 3xx with 502.',
  'integrations/model-path/stacks/ollama-model.mjs': 'Local derived-model administration. Connects only to http://127.0.0.1:11434 for tags, create, show and delete; refuses redirects. No model download request.',
  'integrations/model-path/stacks/run-stack.mjs': 'Practice-stack model-path runner. MP_UPSTREAM defaults to http://127.0.0.1:11434 and must be a canonical literal http://127.0.0.1:PORT origin; model status, tags and unload requests refuse redirects. Starts the loopback model path and practice apps.',
  'integrations/model-path/stacks/stacks.mjs': 'Practice-stack launcher. Uses apps on 127.0.0.1:4496-4498, Postgres on 127.0.0.1:4494 and a BotID override on 127.0.0.1:4459. Direct HTTP probes do not follow redirects. Caller-supplied model gateUrl has no host or port allowlist and can configure non-loopback model destinations in child apps; the reviewed runner supplies loopback. Other child-app egress is outside this module review.',
  'integrations/model-standin/server.mjs': 'Scripted OpenAI-shaped model stand-in (chat completions and Responses, JSON or SSE). Listens on 127.0.0.1 or ::1 only (any other host is refused) at the port the CLI gives; opens no connection; accepts any Authorization header and records only its presence; logs endpoint, step, tool names, roles and a digest of the last user text, never message text or a credential.',
  'integrations/policy-import/reset.mjs': 'Seed and reset. Runs the declared reset command (an argv list, no shell) in a minimal environment and hashes the declared seed sources; its optional seed reads are GETs to one declared plain-http loopback origin (127.0.0.1, localhost or [::1]; any other origin is refused at validation), with a credential read once from a SCOPEHAVEN_TARGET_ variable and never stored or printed.',
  'integrations/model-path/stand-in.mjs': 'Owned model and agent stand-ins. Listen on 127.0.0.1 at OS-assigned ports. The agent POSTs to caller-supplied HTTP modelBaseUrl without a host or port allowlist, so non-loopback hosts are possible (supplied port, or 80 if omitted); reviewed tests supply a loopback gate. It does not follow model redirects. The stub can emit a redirect to 127.0.0.1:9 without connecting there.',
  'integrations/multiturn/desk.mjs': 'Owned synthetic multi-turn ticket desk. Listens on 127.0.0.1 at an OS-assigned port; stores ticket changes and audit rows in SQLite. No outbound connections.',
  'integrations/observers/egress-recorder.mjs': 'Egress sink. Listens on 127.0.0.1 and [::1] (the same port on both, each bound exclusively; it does not start unless both bind) and by default never forwards; a destination that declares forward has its recorded sends forwarded (egress-forward.mjs) only to its declared upstream on 127.0.0.1. Keeps bodies as salted digests, plus the JSON (and, on opt-in, form-encoded) fields a destination declares for capture, and salted digests of a declared idempotency key. A destination that declares verified signature headers has its webhook signing secrets read from SCOPEHAVEN_TARGET_ variables once and kept only in memory; each send records whether its signature verified, never a secret, MAC or anything derived from one. A destination that declares readBack has its reader (read-back.mjs) read the system of record through the forwarder; its read credential and the identities\' write credentials are read from SCOPEHAVEN_TARGET_ variables once and kept only in memory, and item ids, authors, paths, values and credentials are compared only as digests salted per recorder and never written.',
  'integrations/observers/mcp.mjs': 'MCP recorder and proxy on loopback.',
  'integrations/observers/mysql-wire.mjs': 'MySQL snapshot client. Connects only to 127.0.0.1.',
  'integrations/observers/otel.mjs': 'OpenTelemetry receiver. Listens on 127.0.0.1 (inbound only).',
  'integrations/observers/payments-double.mjs': 'Stateful test-mode payments sink. Listens on 127.0.0.1 and [::1] at a required configured port (1024-65535; each bound exclusively, and it does not start unless both bind), answers requests locally, and refuses CONNECT tunnels. Provider hosts are classification inputs; it never forwards to a provider.',
  'integrations/observers/pg-wire.mjs': 'Postgres snapshot client. Connects only to 127.0.0.1.',
  'integrations/observers/pg-net-wire.mjs': 'pg_net on the wire (pgNetWire on a pg-wal observer). Starts one sidecar container with the docker CLI at /usr/local/bin/docker, joined to the network namespace of the one database container the profile names (never another), with every capability dropped except NET_RAW, a read-only root, no new privileges, 64 MB of memory and 8 processes. The sidecar only reads the frames that namespace sends and opens no connection. Through pg_net in that database it queues one witness request per mark to the host gateway (host.docker.internal as resolved in that namespace) at a fresh port where nothing listens. It reaches Postgres only through pg-wire.mjs at 127.0.0.1. It keeps addresses, Host values, request targets and DNS names only as digests salted per observer, and never stores a payload. The witness credential is read from a SCOPEHAVEN_TARGET_ variable and never stored.',
  'integrations/observers/smtp-sink.mjs': 'SMTP sink. Listens on 127.0.0.1 and [::1] (the same port on both, each bound exclusively; it does not start unless both bind) and never relays.',
  'integrations/observers/dns-stub.mjs': 'DNS stub (dns-stub/1). Listens on 127.0.0.1 and [::1] over UDP and TCP (the same port on each, four sockets bound exclusively; it does not start unless all four bind). It answers every query itself from the declared names (a loopback or NXDOMAIN answer) and never recurses or forwards; the query name is kept only as a salted SHA-256 digest beside its declared parent, and no datagram or connection is opened by the stub.',
  'integrations/observers/provider-feed.mjs': 'Provider-feed reader. Reads a provider stub\'s signed feed only from the literal 127.0.0.1 on the port the profile declares (never a name, never a request-supplied host, no redirects, bounded responses), or an operator-supplied export file; sends no request body and holds no credential. With a declared template vocabulary it stores only the operator label of a declared template id an entry names exactly; the profile\'s ids are never stored as such. With declared later outcomes it stores, per send, only its own event number and the provider\'s later word, never a message id or an address.',
  'integrations/observers/request-feed.mjs': 'Request-feed reader, built by an egress recorder that declares requestFeed. Reads a provider stub\'s or adapter\'s signed request feed only from the literal 127.0.0.1 on the port the profile declares (never a name, never a request-supplied host, no redirects, bounded responses, each request and the run-end read capped in time); sends no credential and holds only the feed\'s public key. Provider keys, object ids and tenants are compared as digests salted per recorder and never written.',
  'integrations/observers/egress-forward.mjs': 'Forwarding for an egress destination that opts in. Connects only to the literal 127.0.0.1 on the port the profile declares (never a name, never a request-supplied host, no redirects), sends the recorded request and reads the reply within declared time and size bounds. The upstream proof secret is read from a SCOPEHAVEN_TARGET_ variable and never stored; the run keeps only whether each reply\'s proof verified. It also carries an egress recorder\'s read-back reads: GET requests to the same declared upstream on 127.0.0.1 under the destination\'s read credential, to a path filled only from a write\'s own path segments with no query, bounded in time and size, counted only under forward proof /2.',
  'integrations/payments-pack/pack.mjs': 'Refunds and payments pack runner. Starts the payments double at the pack\'s declared loopback port and sends each check and witness request only to the literal 127.0.0.1 app origin the pack declares, after an authorization record covering that origin is checked. Keeps amounts, currencies, object ids and the agent\'s reply text (at most 500 characters); never a token, request body or raw payment method.',
  'integrations/payments-pack/demo/refund-agent-app.mjs': 'Owned synthetic refund agent demo. Listens on 127.0.0.1 at a required port and calls only the payments double on 127.0.0.1 with a test-mode key. No model, no real provider.',
  'integrations/payments-pack/demo/demo.mjs': 'Payments demo driver. Picks two free ports by listening on 127.0.0.1 at OS-assigned ports and closing them; no other network use.',
  'integrations/payments-stripe/read-back.mjs': 'Stripe read-back observer. Sends GET requests only to the loopback provider at the literal 127.0.0.1 base the operator declares (stage 1) or, in an operator\'s stage-2 run, to https://api.stripe.com and no other host (a constant in the file; certificate checked, no proxy, no redirect followed), with a read-only restricted test key (rk_test_) held in memory, which in stage 2 the operator\'s harness reads from the macOS Keychain. Every stage-2 read must name the declared sandbox account in test mode. Keeps object ids, amounts, currencies, statuses, created times, short declared metadata values and each reply\'s status and Request-Id; never the key, a header, a body or a payment method.',
  'integrations/payments-stripe/stripe-forwarder.mjs': 'Stripe test-mode forwarder (stage 2, an operator\'s stage-2 run only). Listens on 127.0.0.1 and forwards only POST /v1/customers, /v1/charges and /v1/refunds, form-encoded, to https://api.stripe.com and no other host (a constant in the file; certificate checked, no proxy, no redirect followed), with one of the two restricted test keys (rk_test_) the run started it with, the desk\'s (seeding and refunds) and the read key (its one probe); any other key is refused and never sent. It forwards only the Authorization, Content-Type, Idempotency-Key and a pinned Stripe-Version headers. Keeps per request its path, status, Request-Id, replay flag, hold time, the refund\'s charge id and salted digest groups of the idempotency key and the key; never a key, a header, a body or an amount.',
  'integrations/payments-stripe/stand-in.mjs': 'Stripe API stand-in (stage 1, test and demo use). Listens on 127.0.0.1 at an OS-assigned or chosen port and answers locally from its in-memory state; never forwards or connects out. Refuses live-mode and unregistered keys and never logs a key.',
  'integrations/regression-gate/launcher-acceptance.mjs': 'Launcher acceptance helper on loopback.',
  'integrations/revocation-clock/clock.mjs': 'Synthetic revocation-timing harness calls its owned 127.0.0.1 agent desk, hold gate and scripted model stub at OS-assigned ports. A desk model-origin override must remain literal http://127.0.0.1:PORT; redirects are not followed.',
  'integrations/sequences/gate.mjs': 'Hold gate. Listens on 127.0.0.1; its upstream must be literal loopback HTTP.',
  'integrations/sequences/transport.mjs': 'Sequence transport to the declared 127.0.0.1 origin: HTTP requests and websocket steps (no extension, 1 MiB per message, 8 MiB per step; message content is reduced to digests).',
});

// What counts as a network call site, by kind of file. Each rule reads the whole text, comments and strings included, so a
// script carried in a string counts; a file that only mentions one gets a row saying so. Text matching, not parsing: it
// misses injected or aliased fetch and some Python and shell shapes, and zero-egress.mjs is the run-time check.
// In JavaScript: a network module or HTTP client package loaded by name, the global fetch and its browser relatives, a
// network tool run as a child process, or a container started on another container's network (docker --network).
const MODULES = String.raw`(?:node:)?(?:https?|http2|net|tls|dgram|dns)(?:/promises)?|undici|node-fetch|cross-fetch|axios|got|ky|superagent|ws`;
const TOOLS = 'curl|wget|nc|ncat|netcat|socat|telnet|ssh|scp|sftp|rsync';
const RUNS_TOOL = new RegExp(String.raw`\b(?:exec|execSync|execFile|execFileSync|spawn|spawnSync|system|popen|Popen|run|call|check_call|check_output)\(\s*\[?\s*['"\x60](?:${TOOLS})['"\x60\s]`);
const JS = [new RegExp(String.raw`from\s+['"](?:${MODULES})['"]|\b(?:import|require|getBuiltinModule)\(\s*['"](?:${MODULES})['"]|\bfetch\(|\bnew\s+(?:WebSocket|EventSource|XMLHttpRequest)\(|\bsendBeacon\(|['"]--network['"]`), RUNS_TOOL];
// In Python: a network module or hosted-client package imported, on its own line or in a list.
const PY_MODULES = String.raw`socket|socketserver|ssl|http\.client|http\.server|urllib\.request|urllib3|requests|httpx|aiohttp|websockets?|smtplib|ftplib|imaplib|poplib|telnetlib|xmlrpc|openai|anthropic|langsmith|langchain\.chat_models|langchain_(?:openai|anthropic|tavily|mcp_adapters)`;
const PY = [new RegExp(String.raw`^[ \t]*(?:import[ \t]+(?:[\w.]+[ \t]*,[ \t]*)*|from[ \t]+)(?:${PY_MODULES})\b|^[ \t]*from[ \t]+(?:http[ \t]+import[ \t]+[^\n]*\b(?:client|server)\b|urllib[ \t]+import[ \t]+[^\n]*\brequest\b)|\b(?:__import__|import_module)\(\s*['"](?:${PY_MODULES})['"]`, 'm'), RUNS_TOOL];
// In shell: a network tool, git with a remote verb, a package install, or a /dev/tcp socket. The launcher carries a Node script, so JS rules apply too.
const SH = [new RegExp(String.raw`(?:^|[\s;&|(\x60])(?:(?:${TOOLS})\s|git\s+(?:-\S+\s+(?:\S+\s+)?)*(?:clone|fetch|pull|push|ls-remote)\b|(?:npm|npx|pnpm|yarn|pip3?|uv)\s+(?:install|add|ci|sync)\b)|/dev/(?:tcp|udp)/`, 'm'), ...JS];
// A workflow step taken from GitHub; a page or stylesheet that loads a remote resource; a query or policy that sends a request.
const WORKFLOW = [/^[ \t]*(?:-[ \t]+)?uses:[ \t]/m, ...SH];
const REMOTE = /<(?:script|link|img|iframe|video|audio|source|embed|object)\b[^>]*\b(?:src|href|data)=["']?(?:https?:)?\/\/|url\(\s*["']?(?:https?:)?\/\/|@import[^;\n]*(?:https?:)?\/\//;
const QUERY = [/\bhttp\.send\b|\bnet\.http_|\bpg_net\b|\bhttp_(?:get|post)\(/];
// Every shipped file is read as one of these kinds or declared here as data; any other file fails the render, so a new kind
// of code cannot ship outside the scan. A #! line makes any file code.
const CODE = [[/\.(?:[cm]?[jt]sx?)$/, JS], [/\.html?$/, [...JS, REMOTE]], [/\.css$/, [REMOTE]], [/\.py$/, PY], [/\.(?:ba|z)?sh(?:\.example)?$/, SH], [/\.ya?ml$/, WORKFLOW], [/\.(?:sql|rego)$/, QUERY]];
const DATA = /\.(?:md|txt|json|jsonl|pem|tsr|sarif|db|diff|toml|lock|tap|gif|png|sql|plist\.template)$|(?:^|\/)(?:LICENSE|NOTICE|CODEOWNERS|allowed_signers|\.node-version|\.nvmrc|\.gitattributes|\.editorconfig|\.env\.example)$/;
function networkRules(file, text) {
  const byName = CODE.find(([name]) => name.test(file))?.[1];
  if (byName) return byName;
  const bang = /^#!(?:.*\b(python|node)(?:\d[\d.]*)?\s*$)?/m.exec(text.split('\n', 1)[0]);
  if (bang) return bang[1] === 'python' ? PY : bang[1] === 'node' ? JS : SH;
  return DATA.test(file) ? [] : null;
}
const DELETING = /delete|remove|purge|expire|prune|unlink/i;

// What the release ships: inside a release copy, its manifest; in a checkout, the folder's files minus what the release builder
// leaves out (packaging/build-release.mjs excluded), new uncommitted files included so that they fail here before they ship.
export async function shippedFiles(root = ROOT) {
  const manifest = await readFile(join(root, MANIFEST_NAME), 'utf8').catch(() => null);
  if (manifest !== null) return JSON.parse(manifest).files.map(file => file.path).sort();
  let listed;
  try { listed = execFileSync('git', ['-C', root, 'ls-files', '-z', '--cached', '--others', '--exclude-standard', '--', '.'], { encoding: 'utf8', maxBuffer: 1 << 28, stdio: ['ignore', 'pipe', 'ignore'] }); }
  catch { throw new Error(`data-handling: cannot list the shipped files: ${root} has no ${MANIFEST_NAME} and is not a git checkout`); }
  const out = [];
  for (const file of listed.split('\0').filter(Boolean)) if (!excluded(file) && (await lstat(join(root, file)).catch(() => null))?.isFile()) out.push(file);
  return out.sort();
}

function need(match, what) {
  if (!match) throw new Error(`data-handling: cannot read ${what} from the source; update render.mjs and the sheet`);
  return match;
}

// Reads every fact. `read` and `modules` can be replaced in tests.
export async function readFacts({ root = ROOT, read = path => readFile(join(root, path), 'utf8'), modules } = {}) {
  const store = await read('src/store.mjs');
  const quotas = need(/const defaults = \{ maxRuns: (\d+), maxTotalBytes: (\d+) \* 1024 \* 1024, maxFileBytes: (\d+) \* 1024 \* 1024 \}/.exec(store), 'the store quotas (src/store.mjs defaults)');
  need(/mkdir\(path, \{ recursive: true, mode: 0o700 \}\)/.test(store) && /\(stat\.mode & 0o7777\) !== 0o700/.test(store), 'the evidence directory mode 0700 (src/store.mjs)');
  need(/O_EXCL \| constants\.O_NOFOLLOW, 0o600\)/.test(store) && /& ~0o600\) !== 0/.test(store), 'the evidence file mode 0600 (src/store.mjs)');
  const immutable = need(/'(Run already exists; immutable evidence cannot be overwritten\.)'/.exec(store), 'the immutable-run rule (src/store.mjs)')[1];
  const notesScope = need(/scope: '(run core only; editable notes excluded)'/.exec(store), 'the integrity scope of notes (src/store.mjs)')[1];
  const api = need(/\n  return \{ (ready, [a-zA-Z, ]+) \};\n\}/.exec(store), 'the store API (createStore return)')[1].split(', ');
  const deleting = api.filter(name => DELETING.test(name));
  if (deleting.length) throw new Error(`data-handling: the store now exposes ${deleting.join(', ')}; update the retention section`);

  const server = await read('src/server.mjs');
  need(/dataDir = resolve\(root, 'data'\)/.test(server), 'the default evidence directory data/ (src/server.mjs)');
  need(/server\.listen\(port, '127\.0\.0\.1'/.test(server), 'the server loopback bind (src/server.mjs)');
  const connector = await read('src/http-connector.mjs');
  need(connector.includes("/^http:\\/\\/127\\.0\\.0\\.1:([1-9][0-9]{0,4})\\/?$/"), 'the connector loopback origin rule (src/http-connector.mjs)');
  const contracts = await read('src/contracts.mjs');
  // A configured target reaches past loopback only in the two operator modes, each under an authorization record.
  need(/export const TARGET_CONTEXTS = Object\.freeze\(\['local-app', 'operator-forwarded', 'operator-remote'\]\)/.test(contracts), 'the three target contexts (src/contracts.mjs TARGET_CONTEXTS)');
  need(/\n  if \(profile\.targetContext === 'operator-remote' && !\(remoteGrant && remoteGrant\.origins\.includes\(/.test(connector) && /await pinRemoteTarget\(profile\.origin/.test(connector), 'the remote target rule: an origin the authorization record names (src/http-connector.mjs)');
  need(connector.includes("opts?.all ? done(null, [{ address: pin.address, family: pin.family }])"), 'the remote target\'s pinned address lookup (src/http-connector.mjs)');
  const authorization = await read('src/authorization.mjs');
  need(authorization.includes("const forwardedTarget = profile?.targetContext === 'operator-forwarded';\n  if (forwardedTarget && !Object.hasOwn(record, 'forwarded')) fail('authorization-forwarded'"), 'the forwarded target rule: a record naming the forwarder\'s destination (src/authorization.mjs)');
  const dbHosts = (contracts.match(/"host" must be the literal loopback address 127\.0\.0\.1/g) ?? []).length;
  need(dbHosts >= 2, 'the database observers\' loopback host rule (src/contracts.mjs)');
  const tap = await read('integrations/model-identity/tap.mjs');
  const hosted = JSON.parse(need(/export const HOSTED_ORIGINS = Object\.freeze\((\[[^\]]*\])\)/.exec(tap), 'the model tap hosted origins (integrations/model-identity/tap.mjs)')[1].replace(/'/g, '"'));
  const action = await read('integrations/github-action/action.yml');
  need(/uses: actions\/upload-artifact@[0-9a-f]{40}/.test(action), 'the Action\'s pinned evidence artifact upload (integrations/github-action/action.yml)');
  need(/upload-sarif:\n(?:    .*\n)*?    default: 'false'/.test(action), 'the Action\'s upload-sarif default (integrations/github-action/action.yml)');
  // Request bodies an egress sink records: digests by default, declared JSON fields only on opt-in.
  const bodyFields = await read('src/body-fields.mjs'), recorder = await read('integrations/observers/egress-recorder.mjs');
  const list = name => JSON.parse(need(new RegExp(`export const ${name} = Object\\.freeze\\((\\[[^\\]]*\\])\\)`).exec(bodyFields), `the ${name} list (src/body-fields.mjs)`)[1].replace(/'/g, '"'));
  const bound = name => Number(need(new RegExp(`${name}: (\\d+)`).exec(bodyFields), `the capture bound ${name} (src/body-fields.mjs)`)[1]);
  need(/const salt = randomBytes\(16\)/.test(recorder) && /createHash\('sha256'\)\.update\(salt\)/.test(recorder), 'the egress recorder\'s salted body digest (integrations/observers/egress-recorder.mjs)');
  need(/const capture = where\.host === cfg\.witness\?\.host \? null : byHost\.get\(where\.host\)\?\.capture \?\? null;/.test(recorder), 'capture only for a declared destination (integrations/observers/egress-recorder.mjs)');
  need(/const captureHere = capture && named\.name !== '\*' && !named\.ambiguous \? capture : null;/.test(recorder), 'capture only on a declared path (integrations/observers/egress-recorder.mjs)');
  const capture = { deniedParts: list('DENIED_KEY_PARTS'), deniedWords: list('DENIED_KEY_WORDS'), deniedEdges: list('DENIED_KEY_WORD_EDGES'), exceptions: list('DENIED_WORD_EXCEPTIONS'), pointers: bound('pointersPerDestination'), perRecorder: bound('pointersPerRecorder'), stringChars: bound('stringChars'), defaultMaxBytes: bound('defaultMaxBytes') };
  const pkg = JSON.parse(await read('package.json'));
  const dependencies = Object.keys({ ...(pkg.dependencies ?? {}), ...(pkg.optionalDependencies ?? {}), ...(pkg.peerDependencies ?? {}) });

  // Network call sites in every shipped code file, and where the hosted origins appear.
  const files = modules ?? await shippedFiles(root);
  const sites = [], hostedIn = [], unknown = [];
  for (const file of files) {
    const text = await read(file), rules = networkRules(file, text);
    if (!rules) { unknown.push(file); continue; }
    if (rules.some(rule => rule.test(text))) sites.push(file);
    if (rules.length && hosted.some(origin => text.includes(origin.replace('https://', '')))) hostedIn.push(file);
  }
  if (unknown.length) throw new Error(`data-handling: shipped file${unknown.length === 1 ? '' : 's'} of a kind the scan does not know: ${unknown.join(', ')}; add a rule to CODE or the kind to DATA`);
  const unreviewed = sites.filter(file => !Object.hasOwn(SITES, file));
  const gone = Object.keys(SITES).filter(file => !sites.includes(file));
  if (unreviewed.length) throw new Error(`data-handling: unreviewed network call site${unreviewed.length === 1 ? '' : 's'}: ${unreviewed.join(', ')}; review each and add it to SITES`);
  if (gone.length) throw new Error(`data-handling: reviewed ${gone.length === 1 ? 'site no longer makes' : 'sites no longer make'} network calls: ${gone.join(', ')}; remove ${gone.length === 1 ? 'it' : 'them'} from SITES`);
  return { quotas: { runs: Number(quotas[1]), totalMiB: Number(quotas[2]), fileMiB: Number(quotas[3]) }, immutable, notesScope, api, dbHosts, hosted, hostedIn, dependencies, sites, capture };
}

export function renderSheet(f) {
  const lines = [
    '# Data handling',
    '',
    'Generated by `integrations/data-handling/render.mjs` from the source. Do not edit it by hand: run `node integrations/data-handling/render.mjs --write`. The test suite fails when this sheet is stale. It describes what this repository\'s code does with data on the machine that runs it. It is not a certification or a compliance statement.',
    '',
    '## Where evidence is kept',
    '',
    '- Evidence is kept on the local disk of the machine that runs Scopehaven, by default in `data/` inside the `scopehaven` folder (`src/server.mjs`). `--out`, `--data` and `--data-dir` choose another directory.',
    '- In GitHub Actions, the Scopehaven action (`integrations/github-action/action.yml`) uploads the run\'s evidence as a workflow artifact (`actions/upload-artifact`, pinned to a commit). It uploads SARIF to code scanning only when `upload-sarif` is `true`; the default is `false`.',
    '- Evidence directories must be real, owner-owned directories with mode `0700`. A directory with broader permissions is rejected, not repaired (`src/store.mjs`).',
    '- Evidence files are written with mode `0600` and must stay no broader than that (`src/store.mjs`).',
    `- Quotas per evidence directory: at most ${f.quotas.runs} runs, ${f.quotas.totalMiB} MiB in total and ${f.quotas.fileMiB} MiB per file. Reaching a quota rejects the new write and keeps existing evidence.`,
    '',
    '## Append-only runs',
    '',
    `- A saved run is never overwritten: it is created exclusively, and a second write to the same run is refused ("${f.immutable}").`,
    `- Human notes are saved in a separate file and never change a computed result. The run checksum's scope reads "${f.notesScope}".`,
    '',
    '## Request bodies the egress sink records',
    '',
    '- By default an egress sink keeps every outbound request body only as a salted SHA-256 digest (`integrations/observers/egress-recorder.mjs`); the body itself is never stored.',
    `- Capture is opt-in per destination (\`capture.pointers\` in the profile): up to ${f.capture.pointers} JSON pointers per destination and ${f.capture.perRecorder} per sink, to scalar fields of that destination's JSON bodies (and, with \`capture.encodings\` ["json", "form"], its form-encoded POST bodies sent with no URL query, fragment or Cookie header) on its declared paths (a destination that declares capture must declare paths; a send on another path records \`path-undeclared\` and no values). Only those fields are stored, on the send events of the run record and its exports, with the declaration. The whole body is never captured, and the sink buffers at most the declared \`maxBytes\` (default ${f.capture.defaultMaxBytes}) of a body to parse it.`,
    `- A pointer is refused, even when declared, when any of its keys, folded with NFKC, still holds a character outside printable ASCII (a lookalike letter), or (lowercased, with everything outside a-z and 0-9 removed) contains ${f.capture.deniedParts.map(x => `\`${x}\``).join(', ')}; or when a word of the key (split at separators, camelCase humps and letter/digit boundaries) equals ${f.capture.deniedWords.map(x => `\`${x}\``).join(', ')}, or equals, starts with or ends with ${f.capture.deniedEdges.map(x => `\`${x}\``).join(', ')}, except the ordinary words ${f.capture.exceptions.map(x => `\`${x}\``).join(', ')} (\`src/body-fields.mjs\`). Refusing too much is accepted.`,
    `- A captured string over ${f.capture.stringChars} characters, or a value shaped like a secret or a personal identifier (a JWT, a provider key, an AWS access key id, a bearer, basic or token authorization value, a PEM block, a long hex or base64 run, a Luhn-valid run of 13 to 19 digits that may be a card number, with any one separator between digit groups, or a nine-digit NNN-NN-NNNN identifier with any one separator or none, including a Luhn-valid 13 to 19 digit integer; strings are checked after NFKC folding, and one holding a decimal digit outside 0-9 is redacted), is not stored; objects and arrays are never captured.`,
    '- Claim rules keep only how a reply read (success, refusal, ambiguous, unreadable or untriggered) and the index of the declared phrase or value that matched, never the reply text (`src/http-claims.mjs`). The declared claim rules themselves, phrases and values included, are stored in each check\'s sealed trace and exported with it, like the rest of the profile.',
    '',
    '## JSON predicates of HTTP contract checks',
    '',
    '- Each `json.equals`, `json.exists` and `json.notContains` predicate keeps a record in the mode the run chose (`SCOPEHAVEN_PREDICATE_RECORD`; predicate records in `src/contracts.mjs`). `digest`, the default, keeps the field\'s JSON pointer and, for `json.equals` and `json.notContains`, a SHA-256 of the configured value (and for `json.equals` of the value the response held there) keyed with 32 random bytes per run. The key is never written to the run, its exports or an evidence pack, so a short or guessable value (an amount, a boolean, a short id) cannot be found by trying candidates against a digest. An operator may set the key (`SCOPEHAVEN_PREDICATE_KEY`) to hand a named reviewer; whoever holds it can test candidate values against every digest of that run.',
    '- `value` mode is opt-in and keeps the configured value and the response\'s value at the pointer in clear. `outcome` mode keeps each predicate\'s outcome only.',
    '',
    '## App action logs',
    '',
    '- An app log (`appLogs` in the profile; `integrations/observers/app-log.mjs`) reads a local file the application writes. Each line is kept only as its mapped fields (the declared rule\'s operation, name and resource; a mail recipient\'s domain and a declared address or `*`; the actor as a declared principal, or `unlisted:` and a 16-character digest keyed with a secret the run does not keep; the outcome; the line\'s time; a named rule\'s resource read from the line when its rule says so) and a SHA-256 digest of the line, plus the constants a rule declares and, for a field a rule reads from the line, the declared selector value its word map names for the line\'s word (never the word itself, and nothing for an unlisted word), the correlation token of the value named by `fields.trace` (its 32 hex digits, only when the value is a well-formed correlation value), and for `fields.key` a 16-character digest keyed with a secret the run does not keep (never the key; a key over 1024 characters is kept only as unreadable). The raw line, the file path and any other field are never stored in a run.',
    '',
    '## Retention and deletion',
    '',
    `- The evidence store has no delete or expiry operation. Its whole API is: ${f.api.map(name => `\`${name}\``).join(', ')}.`,
    '- Runs stay until you delete them. To delete evidence, delete the private evidence directory (and any exported files you saved elsewhere).',
    '',
    '## What the tool connects to',
    '',
    `- No npm dependencies${f.dependencies.length ? `, except: ${f.dependencies.join(', ')}` : ''}, and no telemetry: none of the modules listed below sends usage or analytics data.`,
    '- The HTTP connector reaches a literal `http://127.0.0.1:PORT` origin unless the profile declares one of two operator modes, each run only under an authorization record that covers it: through a forwarder you run on 127.0.0.1 (`operator-forwarded`; the record states where the forwarder sends traffic, which ScopeHaven cannot check), or over direct HTTPS to the exact origin the record names, with its address pinned for the run (`operator-remote`). See [KNOWN-LIMITS.md](KNOWN-LIMITS.md#operator-forwarded-staging) for both.',
    `- Database observers connect only to the literal loopback address 127.0.0.1 (${f.dbHosts} rules in \`src/contracts.mjs\`).`,
    `- **No hosted model calls by default.** The built-in targets use fixtures and scripted models. The model tap's fixed hosted upstream choices are ${f.hosted.map(o => `\`${o}\``).join(' and ')}, whose host names appear in ${f.hostedIn.map(p => `\`${p}\``).join(' and ')}. The model tap forwards to one of them only when an operator passes it as \`--upstream\`; the application's own key passes through and is not written to the tap log.`,
    '- Some integration helpers accept caller-supplied origins without enforcing loopback and can reach non-loopback hosts. Their rows below distinguish those APIs from the owned fixture runners that pass loopback URLs.',
    '',
    `Every shipped code file that loads a network module or HTTP client, calls the global fetch, runs a network tool or starts a container on another container's network (${f.sites.length}), as reviewed. The files come from what the release ships (\`packaging/build-release.mjs\`), fixtures and vendored source included: JavaScript, HTML and CSS, Python, shell including the launcher, the GitHub Action's YAML, and SQL and Rego. A shipped file of any other kind must be declared as data or this sheet fails to render. Files the release leaves out (tests, \`packaging/osv-snapshot.mjs\`, the framework setup scripts) are not listed. A file is found by matching its text, not by parsing it, so a name built at run time, or a call made inside a library the file does not name, is not found here; the zero-egress check below is the run-time check.`,
    '',
    '| Module | What it reaches |',
    '| --- | --- |',
    ...f.sites.map(file => `| \`${file}\` | ${SITES[file]} |`),
    '',
    '## How this is checked',
    '',
    '- `integrations/data-handling/data-handling.test.mjs` re-renders this sheet and fails when it differs, when a new network call site appears without review, when a shipped file is of a kind the scan does not know, or when the store gains a method that could delete evidence.',
    '- `node integrations/data-handling/zero-egress.mjs --out /abs/new/dir` runs every available built-in target and the test suite with outbound network denied except loopback (macOS `sandbox-exec`; Linux `unshare`), and logs every connection attempt. Its result is a run record, not part of this sheet.',
    '- A target application you test can make its own outbound calls. This sheet covers Scopehaven\'s code, not the application under test.',
    '',
  ];
  return lines.join('\n');
}

export async function render(options) { return renderSheet(await readFacts(options)); }

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const mode = process.argv[2];
  const text = await render();
  if (mode === '--write') { await writeFile(join(ROOT, SHEET), text); console.log(`wrote ${SHEET}`); }
  else if (mode === '--check') {
    const current = await readFile(join(ROOT, SHEET), 'utf8').catch(() => null);
    if (current !== text) { console.log(`${SHEET} is stale: run node integrations/data-handling/render.mjs --write`); process.exitCode = 1; }
    else console.log(`${SHEET} is current`);
  } else { console.log('Usage: render.mjs --write | --check'); process.exitCode = 2; }
}
