#!/usr/bin/env bash
# Prove each lemma of nbd.spthy, one at a time, and check every result.
# Exits non-zero unless all are verified.
#
# Run from the repository root:  formal/check.sh
# Each lemma runs alone, with the heuristic that lets it terminate, under a
# time cap (CAP seconds, default 1800). Results go to formal/results.txt.
# RTS passes Haskell runtime options, for example RTS="-N2 -M16g" to bound
# each proof's threads and heap. JOBS (default 1) proves that many lemmas at
# once; use it only on a machine, or in a container, with room for them all
# (see README.md). JOBS above 1 needs bash 4.3 or later.
set -uo pipefail

cd "$(dirname "$0")"
THEORY=nbd.spthy
CAP=${CAP:-1800}
JOBS=${JOBS:-1}
ORACLE="--heuristic=o --oraclename=oracle.py"
RTSOPTS=${RTS:+"+RTS $RTS -RTS"}

# label | lemma | extra tamarin-prover arguments
LEMMAS=(
  "main|executable_grant|"
  "main|executable_approval|"
  "main|executable_approved_device|--heuristic=C"
  "main|key_agreement|"
  "main|grant_authentication|"
  "main|approval_authenticity|"
  "main|no_silent_addition|"
  "main|reset_acceptance_needs_hold|"
  "main|key_leaks_only_via_holders_or_grants|--heuristic=i"
  "main|first_contact_substitution|"
  "main|inviters_executable_vouched_grant|"
  "main|inviters_executable_captured_grant|"
  "main|inviters_executable_held_grant|"
  "main|inviters_executable_later_invite_grant|"
  "main|inviters_grant_targets_justified|$ORACLE"
  "main|inviters_reenrolled_never_invite_authorized|"
  "main|inviters_root_is_ancestor|"
  "main|inviters_standing_scoped|"
  "main|inviters_grant_scope|"
  "NOLIVEGUARD|revoked_signer_bypass|-D=NOLIVEGUARD"
  "UNSCOPED|cross_space_vouch_attack|-D=UNSCOPED"
  "REINVITE|reinvite_carries_vouch|-D=REINVITE"
  "RETRO|retro_vouch_attack|-D=RETRO"
  "PREINVITERS|key_leaks_only_via_holders_or_grants|-D=PREINVITERS"
  "PREINVITERS|adversary_grant_targets_justified|-D=PREINVITERS $ORACLE"
  "PREINVITERS|first_contact_substitution|-D=PREINVITERS"
)

# Stop a command after $1 seconds (macOS has no timeout(1)).
cap() { /usr/bin/perl -e 'alarm shift; exec @ARGV or die' "$@"; }

: > results.txt

# Prove one entry and print its result line.
prove() {
  IFS='|' read -r label lemma extra <<< "$1"
  start=$(date +%s)
  # shellcheck disable=SC2086
  line=$(cap "$CAP" tamarin-prover $RTSOPTS --prove="$lemma" $extra "$THEORY" 2>&1 | grep -E "^\s+$lemma \(" | head -1 | sed -E 's/^ +//')
  secs=$(( $(date +%s) - start ))
  if [[ "$line" == *": verified"* ]]; then
    printf "ok    %-12s %-40s %s [%ss]\n" "$label" "$lemma" "${line#*: }" "$secs"
  else
    printf "FAIL  %-12s %-40s %s [%ss]\n" "$label" "$lemma" "${line:-timed out or no result}" "$secs"
  fi
}

if (( JOBS <= 1 )); then
  for entry in "${LEMMAS[@]}"; do
    prove "$entry" | tee -a results.txt
  done
else
  # Run up to JOBS entries at once, then write results in the list's order.
  tmp=$(mktemp -d)
  for i in "${!LEMMAS[@]}"; do
    while (( $(jobs -rp | wc -l) >= JOBS )); do wait -n; done
    { prove "${LEMMAS[$i]}" > "$tmp/$i"; cat "$tmp/$i"; } &
  done
  wait
  for i in "${!LEMMAS[@]}"; do cat "$tmp/$i" >> results.txt; done
  rm -r "$tmp"
fi
! grep -q "^FAIL" results.txt
