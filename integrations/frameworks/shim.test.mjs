// The shipped Python shim (adapters/shim.py): channel and ledger under threads,
// the fault hook's three kinds (fault.mjs), and the state helpers object-path adapters answer snapshots with. fixtures/shim_checks.py runs each
// property's allowed and forbidden case once; each test reads its own result. No network, no model.
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

// A Python 3 at a fixed path (as the ledger tests find one); without one these tests are skipped, not passed.
const PYTHON = ['/Library/Frameworks/Python.framework/Versions/3.13/bin/python3', '/opt/homebrew/bin/python3', '/usr/bin/python3'].find(path => existsSync(path));
const CHECKS = fileURLToPath(new URL('./fixtures/shim_checks.py', import.meta.url));
const results = PYTHON ? new Promise((resolve, reject) => execFile(PYTHON, ['-I', '-B', CHECKS], { timeout: 60000 }, (error, stdout, stderr) => (error ? reject(new Error(`${error.message}\n${stderr}`)) : resolve(JSON.parse(stdout))))) : null;
results?.catch(() => {}); // each test awaits it and fails on its own if the checks did not run
const skip = { skip: !PYTHON && 'no Python 3 at a fixed path' };
const holds = async name => { const r = (await results)[name]; assert.ok(r?.ok, `${name}: ${JSON.stringify(r?.detail)}`); };

test('shim channel: lines written from several threads at once arrive whole, never interleaved', skip, () => holds('channel-lines'));
test('shim ledger: the sequence number is taken when a record is written, so a call that starts first and ends last still arrives in order', skip, () => holds('ledger-order'));
test('shim fault hook: two concurrent first calls to the planned tool fault once, and the fault is that tool\'s first record', skip, () => holds('fault-once'));
test('shim reset after commit: the body returns, its record is marked and keeps the result, and the agent gets a connection reset; a first call that raises is not marked and spends the fault', skip, () => holds('fault-reset'));
test('shim duplicate delivery: the body runs twice with the same arguments, both records are written together, and the agent gets the first result or, with seen second, the duplicate\'s; no duplicate after a first call that raises', skip, () => holds('fault-duplicate'));
test('shim reset and duplicate: two concurrent first calls to the planned tool, and the fault applies to one of them only', skip, () => holds('fault-kinds-once'));
test('shim reset and duplicate edges: a cancelled duplicate is recorded as cancelled and goes on with no result given; an async reset commits and resets; an async first call that raises is not delivered again', skip, () => holds('fault-edges'));
test('shim ledger: a call still running is counted until its record is written, and a result that cannot be captured still leaves its record', skip, () => holds('unfinished'));
test('shim ledger: a call cancelled or interrupted after its side effect leaves one cancelled record, and the cancellation goes on', skip, () => holds('cancelled'));
test('shim models: a pydantic model is read by its declared fields, never its own model_dump; private, excluded, undeclared and missing fields, a non-pydantic model_dump and an undeclared slot are refused', skip, () => holds('models'));
test('shim containers: a list, tuple or dict subclass is read as its items only when it holds nothing else; an attribute, a dataclass field or a slot on it is refused, in a whole read and a key subset', skip, () => holds('containers'));
test('shim read_path: a path through None reads None; a missing key, attribute or root is an error, never None', skip, () => holds('read-path'));
test('shim plain_data: plain values, tuples and dataclasses are read; a set, an object, a non-string key, NaN, an integer past 2**53 or a dataclass attribute outside its fields is refused', skip, () => holds('plain-data'));
test('shim select_entries: only the declared keys travel, typed; every other entry is in the remainder digest whatever the order', skip, () => holds('select-entries'));
