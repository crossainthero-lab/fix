#!/usr/bin/env bash
# Builds docs/ (the GitHub Pages site) from src/. Run before every commit.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p docs
key=$(cat src/helper_key.pub)
case "$key" in "ssh-ed25519 "*" rescue-support") ;; *) echo "bad helper key file" >&2; exit 1;; esac
# the key blob is public; the comment must stay "rescue-support" (no email/host names)
sed "s|@@HELPER_PUBLIC_KEY@@|${key}|; s|@@GATE_URL@@|$(cat src/gate_url.txt)|" src/rescue.ps1 > docs/rescue.ps1
cp src/diag.ps1 docs/diag.ps1
sum=$(sha256sum docs/rescue.ps1 | cut -d' ' -f1)
sed "s|@@RESCUE_SHA256@@|${sum}|" src/r.template | sed 's/$/\r/' > docs/r
cp src/index.html docs/index.html
touch docs/.nojekyll
( cd docs && sha256sum r rescue.ps1 diag.ps1 > SHA256SUMS )
# every published file must be pure ASCII and free of key material
for f in docs/r docs/rescue.ps1 docs/diag.ps1 docs/index.html; do
  LC_ALL=C grep -nP '[^\x00-\x7F]' "$f" && { echo "non-ASCII in $f" >&2; exit 1; } || true
  grep -nE 'tskey-[A-Za-z0-9]{6,}|PRIVATE KEY' "$f" && { echo "secret-like text in $f" >&2; exit 1; } || true
done
echo "rescue.ps1 sha256: $sum"
