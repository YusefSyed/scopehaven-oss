// Inference hook: inference that drafts more of the profile from the app's own declarations.
//
// Today: with --openapi, init calls the existing importer (integrations/policy-import/openapi.mjs importOpenApi) and
// drafter (draft.mjs draftChecks), binding the document's anonymous role to the anonymous actor and every authenticated
// requirement to identity A. The draft is written next to the profile, unconfirmed: confirming it is a named person's
// step (./scopehaven policy confirm ...), never init's.
//
// LANE-D-HOOK: init loads each module below if it exists and calls its draftForInit({ profile, openapi, root, session })
// export, which returns { checks, notDrafted, warnings } (and optionally draft, binding, confirm) as a proposal. session is
// the absolute path given with --session (a HAR or a JSON-lines request log), or undefined. A missing module is reported
// as "not available yet" and nothing blocks.
import { readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { basename, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { importOpenApi } from '../policy-import/openapi.mjs';
import { draftChecks, BINDING_SCHEMA } from '../policy-import/draft.mjs';

export const LANE_D_MODULES = Object.freeze([
  'policy-import/init-hook.mjs',
  'session-import/init-hook.mjs',
  'model-standin/init-hook.mjs',
]);
const integrations = fileURLToPath(new URL('../', import.meta.url));

export async function openApiDraft(file, profile) {
  const content = await readFile(file);
  const matrix = importOpenApi({ id: basename(file), content }, { application: profile.applicationId });
  const actors = {};
  for (const role of new Set(matrix.cells.map(c => c.role))) actors[role] = role === 'anonymous' ? 'anonymous' : 'a';
  const binding = { schema: BINDING_SCHEMA, targetId: profile.id, actors };
  return { matrix, binding, draft: draftChecks(matrix, binding) };
}

export async function laneDDrafts({ profile, openapi, session, root = integrations }) {
  const results = [];
  for (const rel of LANE_D_MODULES) {
    const path = join(root, rel);
    if (!existsSync(path)) { results.push({ module: rel, available: false }); continue; }
    try {
      const mod = await import(pathToFileURL(path).href);
      if (typeof mod.draftForInit !== 'function') { results.push({ module: rel, available: false, note: 'no draftForInit export' }); continue; }
      const out = await mod.draftForInit({ profile: structuredClone(profile), openapi, root: integrations, session });
      // Kept for the written proposal: the drafted checks and what the hook says about them, plus its draft and binding when
      // it returns them (a person confirms from those). Anything else it returns, such as an imported session, is not kept.
      results.push({ module: rel, available: true, checks: Array.isArray(out?.checks) ? out.checks : [], notDrafted: out?.notDrafted ?? [], warnings: out?.warnings ?? [],
        ...(out?.draft !== undefined ? { draft: out.draft } : {}), ...(out?.binding !== undefined ? { binding: out.binding } : {}), ...(typeof out?.confirm === 'string' ? { confirm: out.confirm } : {}) });
    // The full message is kept in memory: the caller checks it for credentials before printing a shortened form.
    } catch (error) { results.push({ module: rel, available: true, error: String(error?.message ?? error) }); }
  }
  return results;
}
