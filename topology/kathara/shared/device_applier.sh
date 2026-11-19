#!/bin/sh
# device_applier.sh - runs INSIDE each device container (firewall / WAF / proxy).
#
# Polls this device's control-plane inbox for one-shot removal jobs written by
# the remover (DropFolderTransport), runs each locally, records the result, and
# moves the job to done.
#
# Layout (per device):
#   /shared/<DEVICE>/inbox/   jobs to run   (job_*.sh)
#   /shared/<DEVICE>/done/    finished jobs + .result files
#
# Usage (in the container .startup):  DEVICE=EdgeFirewall sh device_applier.sh &
#
# The jobs themselves are idempotent (delete-absent-marker = no-op), so a job
# that runs twice is harmless.

: "${DEVICE:?set DEVICE to this container's name}"
ROOT="/shared/${DEVICE}"
INBOX="${ROOT}/inbox"
DONE="${ROOT}/done"
mkdir -p "$INBOX" "$DONE"

while true; do
  for job in "$INBOX"/job_*.sh; do
    [ -e "$job" ] || continue
    name="$(basename "$job")"
    if sh "$job" >"${DONE}/${name}.log" 2>&1; then
      echo "ok"   >"${DONE}/${name}.result"
    else
      echo "fail" >"${DONE}/${name}.result"
    fi
    mv "$job" "${DONE}/${name}"
  done
  sleep 5
done