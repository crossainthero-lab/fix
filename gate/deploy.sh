#!/usr/bin/env bash
# Deploy rescue-gate into a dedicated Cloudflare account. Usage: CLOUDFLARE_ACCOUNT_ID=<id> ./deploy.sh
set -euo pipefail
cd "$(dirname "$0")"
: "${CLOUDFLARE_ACCOUNT_ID:?set CLOUDFLARE_ACCOUNT_ID}"
ns=$(npx --no-install wrangler kv namespace list 2>/dev/null | python3 -I -c "import json,sys;print(next((n['id'] for n in json.load(sys.stdin) if n['title']=='rescue-gate-RESCUE'),''))")
if [ -z "$ns" ]; then
  npx --no-install wrangler kv namespace create rescue-gate-RESCUE >/dev/null 2>&1 || true
  ns=$(npx --no-install wrangler kv namespace list 2>/dev/null | python3 -I -c "import json,sys;print(next(n['id'] for n in json.load(sys.stdin) if n['title']=='rescue-gate-RESCUE'))")
fi
printf '\n[[kv_namespaces]]\nbinding = "RESCUE"\nid = "%s"\n' "$ns" > .kv.toml
cat wrangler.toml .kv.toml > .deploy.toml
npx --no-install wrangler deploy -c .deploy.toml
echo "KV namespace id: $ns"
