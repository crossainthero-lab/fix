#!/usr/bin/env bash
# Helper-side: wait (bounded) for the friend's PC to report in, then print the SSH command.
# usage: gate/watch.sh CODE [timeout-seconds]   (default 1800). Exit 0 = ready, 1 = failed, 2 = timed out.
set -u
code="${1:?usage: watch.sh CODE [timeout-seconds]}"; limit="${2:-1800}"
gate="${RESCUE_GATE:-$(cat "$(dirname "$0")/../src/gate_url.txt")}"
end=$(( $(date +%s) + limit ))
while [ "$(date +%s)" -lt "$end" ]; do
  out=$(curl -fsS -m 15 "$gate/report/$code" 2>/dev/null) && {
    python3 -I - "$out" <<'PY'
import json, sys
r = json.loads(sys.argv[1])
if r.get("ok"):
    print(f"READY  computer={r.get('computer')}  user={r.get('user')}  tailscale={r.get('ip')}  ({r.get('dnsName','')})")
    print(f"\n  ssh {r.get('user')}@{r.get('ip')}\n")
    print(f"  first connect: the host key fingerprint must be {r.get('hostKey','(not reported)')}")
    sys.exit(0)
print(f"REPORTED PROBLEM: {r.get('message')}  (computer={r.get('computer')}, user={r.get('user')}, at {r.get('at')})")
sys.exit(1)
PY
    exit $?
  }
  sleep 5
done
echo "No report within ${limit}s (the PC has not finished, or has not run the command yet)."; exit 2
