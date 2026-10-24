#!/usr/bin/env bash
# Prove each lemma of peep.spthy, one at a time, and check every result.
# Exits non-zero unless all are verified.
#
# Run from the repository root:  formal/check.sh
# Each lemma runs alone, with the heuristic that lets it terminate, under a
# time cap (CAP seconds, default 1800). Results go to formal/results.txt.
set -uo pipefail

cd "$(dirname "$0")"
THEORY=peep.spthy
CAP=${CAP:-1800}
ORACLE="--heuristic=o --oraclename=oracle.py"

# label | lemma | extra tamarin-prover arguments
LEMMAS=(
  "main|executable_grant|"
  "main|executable_approval|"
  "main|executable_approved_device|"
  "main|key_agreement|"
  "main|grant_authentication|"
  "main|approval_authenticity|"
  "main|no_silent_addition|"
  "main|reset_acceptance_needs_hold|"
  "main|key_leaks_only_via_holders_or_grants|"
  "main|adversary_grant_targets_justified|$ORACLE"
  "main|first_contact_substitution|"
  "NOLIVEGUARD|revoked_signer_bypass|-D=NOLIVEGUARD"
)

# Stop a command after $1 seconds (macOS has no timeout(1)).
cap() { /usr/bin/perl -e 'alarm shift; exec @ARGV or die' "$@"; }

: > results.txt
status=0
for entry in "${LEMMAS[@]}"; do
  IFS='|' read -r label lemma extra <<< "$entry"
  start=$(date +%s)
  # shellcheck disable=SC2086
  line=$(cap "$CAP" tamarin-prover --prove="$lemma" $extra "$THEORY" 2>&1 | grep -E "^\s+$lemma \(" | head -1 | sed -E 's/^ +//')
  secs=$(( $(date +%s) - start ))
  if [[ "$line" == *": verified"* ]]; then
    printf "ok    %-12s %-40s %s [%ss]\n" "$label" "$lemma" "${line#*: }" "$secs" | tee -a results.txt
  else
    printf "FAIL  %-12s %-40s %s [%ss]\n" "$label" "$lemma" "${line:-timed out or no result}" "$secs" | tee -a results.txt
    status=1
  fi
done
exit $status
