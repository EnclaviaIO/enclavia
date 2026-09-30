#!/usr/bin/env bash
# Run every TLC model under spec/models/ and assert its expected outcome.
#
# Each models/<name>.cfg carries a line
#     \* EXPECT: pass
# or
#     \* EXPECT: violation <InvariantName>
# A positive model must finish with no error; a negative model must stop on
# exactly the named invariant (regression evidence that the model is strong
# enough to see the attack). Exit status is non-zero if any model disagrees.
#
# Usage:  spec/check.sh [--may] [name-glob]
#   --may      also run the May 2026 core spec (may-2026/MCSynchronizer).
#   name-glob  only run models whose name matches (e.g. 'Neg_*').
#
# Environment:
#   TLC        command that runs TLC (default: `tlc` on PATH, otherwise
#              `nix shell nixpkgs#tlaplus --command tlc`)
#   WORKERS    TLC workers per model (default 4)
#   JOBS       models run in parallel (default 1)
#   LOGDIR     where to keep TLC output (default: a temporary directory)
set -uo pipefail
cd "$(dirname "$0")"

run_may=0
glob='*'
for a in "$@"; do
  case "$a" in
    --may) run_may=1 ;;
    *) glob="$a" ;;
  esac
done

if [ -z "${TLC:-}" ]; then
  if command -v tlc >/dev/null 2>&1; then TLC=tlc
  else TLC="nix shell nixpkgs#tlaplus --command tlc"; fi
fi
WORKERS=${WORKERS:-4}
JOBS=${JOBS:-1}
LOGDIR=${LOGDIR:-$(mktemp -d)}
mkdir -p "$LOGDIR"
export TLC WORKERS LOGDIR

# run_one <dir> <module> <cfg> <name> <expect>
# Each run gets a private copy of the modules, so parallel runs never share
# TLC's working files.
run_one() {
  local dir=$1 mod=$2 cfg=$3 name=$4 expect=$5
  local log="$LOGDIR/$name.log" work
  work=$(mktemp -d)
  cp "$dir"/*.tla "$work"/ && cp "$dir/$cfg" "$work/run.cfg"
  # A private java.io.tmpdir too: TLC unpacks its standard modules there, and
  # concurrent JVMs sharing one directory read each other's half-written files.
  (cd "$work" && JAVA_TOOL_OPTIONS="-Djava.io.tmpdir=$work ${JAVA_TOOL_OPTIONS:-}" $TLC -workers "$WORKERS" -deadlock -cleanup \
      -metadir "$work/states" -config run.cfg "$mod" >"$log" 2>&1)
  rm -rf "$work"
  local got states
  if grep -q "Model checking completed. No error has been found." "$log"; then
    got=pass
  elif grep -q "^Error: Invariant .* is violated" "$log"; then
    got="violation $(sed -n 's/^Error: Invariant \(.*\) is violated.*/\1/p' "$log" | head -1)"
  else
    got="error (see $log)"
  fi
  states=$(sed -n 's/.* states generated, \([0-9]*\) distinct states found.*/\1/p' "$log" | tail -1)
  depth=$(sed -n 's/The depth of the complete state graph search is \([0-9]*\).*/\1/p' "$log" | tail -1)
  steps=$(grep -c '^State [0-9]*:' "$log")
  local detail
  if [ "$got" = pass ]; then detail="${states:-?} distinct states, depth ${depth:-?}"
  else detail="counterexample of $steps states"; fi
  if [ "$got" = "$expect" ]; then
    printf 'OK    %-44s %-38s %s\n' "$name" "$got" "$detail"
  else
    printf 'FAIL  %-40s expected [%s] got [%s]\n' "$name" "$expect" "$got"
    return 1
  fi
}
export -f run_one

jobs_file=$(mktemp)
for cfg in models/$glob.cfg; do
  [ -e "$cfg" ] || continue
  name=$(basename "$cfg" .cfg)
  expect=$(sed -n 's/^\\\* EXPECT: //p' "$cfg" | head -1)
  printf '%s\t%s\t%s\t%s\t%s\n' "." MCAntiRollback.tla "$cfg" "$name" "$expect" >>"$jobs_file"
done
if [ "$run_may" = 1 ]; then
  printf '%s\t%s\t%s\t%s\t%s\n' may-2026 MCSynchronizer.tla MCSynchronizer.cfg May_MCSynchronizer pass >>"$jobs_file"
fi

status=0
if [ "$JOBS" -gt 1 ]; then
  tr '\t\n' '\0\0' <"$jobs_file" | xargs -0 -n5 -P "$JOBS" bash -c 'run_one "$@"' _ || status=1
else
  while IFS=$'\t' read -r dir mod cfg name expect; do
    run_one "$dir" "$mod" "$cfg" "$name" "$expect" || status=1
  done <"$jobs_file"
fi
rm -f "$jobs_file"
echo "logs: $LOGDIR"
exit $status
