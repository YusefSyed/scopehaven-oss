#!/bin/bash
# One scheduled re-run, for launchd (com.scopehaven.drift.plist.template), cron or
# the scheduled workflow. It gates a built-in synthetic target against the last successful run kept
# in a private directory, writes the drift summary there (latest-drift.md), and keeps this run as the
# next baseline unless it regressed or could not be compared. Nothing is sent anywhere: no mail, chat
# or webhook. Exit code: drift.mjs's (0 no change or improved, 1 regression or needs review, 2 error).
# Usage: run-local.sh [demo-repaired | demo-vulnerable]
#   data directory: $SCOPEHAVEN_DRIFT_DIR, or ~/Library/Application Support/Scopehaven/drift
set -uo pipefail
umask 077
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
target=${1:-demo-repaired}
case "$target" in demo-repaired|demo-vulnerable) ;; *) echo "run-local.sh runs a built-in target: demo-repaired or demo-vulnerable" >&2; exit 2 ;; esac
node_bin=${SCOPEHAVEN_NODE:-$(command -v node || true)}
[ -n "$node_bin" ] || { echo "run-local.sh needs node (or SCOPEHAVEN_NODE)" >&2; exit 2; }
data=${SCOPEHAVEN_DRIFT_DIR:-"$HOME/Library/Application Support/Scopehaven/drift"}
# Refuse a symlinked directory before touching its mode, so chmod never follows a link elsewhere.
[ ! -L "$data" ] || { echo "the drift directory must not be a symlink" >&2; exit 2; }
mkdir -p -m 700 "$data" && chmod 700 "$data" || exit 2
work="$data/run-$(date -u +%Y%m%dT%H%M%SZ)-$$"
mkdir -m 700 "$work" || exit 2
baseline_args=()
if [ -f "$data/last-run.json" ]; then
  baseline_id=$("$node_bin" "$root/integrations/github-action/prepare.mjs" seed-baseline --run "$data/last-run.json" --gate-dir "$work/gate") || { echo "the stored baseline could not be read" >&2; exit 2; }
  baseline_args=(--baseline "$baseline_id")
fi
"$root/scopehaven" gate --target "$target" --out "$work/gate" ${baseline_args[@]+"${baseline_args[@]}"} > "$work/gate-summary.json"
"$node_bin" "$root/integrations/schedule/drift.mjs" --summary "$work/gate-summary.json" --markdown "$work/drift.md"
code=$?
cp "$work/drift.md" "$data/latest-drift.md"
if [ "$code" -eq 0 ]; then
  run_id=$("$node_bin" "$root/integrations/github-action/prepare.mjs" run-id --from "$work/gate-summary.json") || exit 2
  "$root/scopehaven" export --run "$run_id" --format json --out "$work/run.json" --data "$work/gate" --unsigned > /dev/null || exit 2
  mv -f "$work/run.json" "$data/last-run.json"
fi
exit "$code"
