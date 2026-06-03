#!/usr/bin/env bash
#
# Run the DAST battery against one target, all in a single sbt session.
#
#   ./scripts/scan.sh <target-url> [identity-spec.json]
#
# Configuration (ANTHROPIC_API_KEY, DAST_AUTHORIZED_HOSTS, DAST_OAST_BASE_URL,
# DAST_MAX_HOPS, ...) is read from .env by DastConfig -- no export needed. The
# target host MUST be in DAST_AUTHORIZED_HOSTS for active probing; otherwise the
# run is observe-only (capture + security headers). XSS/IDOR planning need
# ANTHROPIC_API_KEY; absent it, those steps fail closed and are skipped while the
# deterministic checks still run.
#
# Stages:
#   ScannerMain <url>              per-URL battery (headers + analyzer-driven
#                                  XSS/SQLi/open-redirect/SSRF probes)
#   SiteScannerMain <url>          crawl in-scope URLs + scan each
# With a spec (two identities named attacker/victim):
#   AccessScannerMain <spec>       HTTP two-identity access-control / IDOR
#   SpaIdorScannerMain <url> <spec> browser two-identity IDOR (SPA targets)
#
# (IdorScannerMain <url> <spec> is the HTTP multi-hop IDOR variant -- add it
# below if you want it alongside the browser one.)
#
# Examples:
#   ./scripts/scan.sh https://target.example/app
#   ./scripts/scan.sh https://target.example/app spec.json
set -euo pipefail
cd "$(dirname "$0")/.."

URL="${1:-}"
SPEC="${2:-}"

if [[ -z "$URL" ]]; then
  echo "usage: $0 <target-url> [identity-spec.json]" >&2
  exit 2
fi
if [[ -n "$SPEC" && ! -f "$SPEC" ]]; then
  echo "spec file not found: $SPEC" >&2
  exit 2
fi
if [[ ! -f .env ]]; then
  echo "warning: no .env in $(pwd) -- run will be observe-only unless config is in the environment" >&2
fi

cmds=(
  "runMain dast.scan.ScannerMain $URL"
  "runMain dast.scan.SiteScannerMain $URL"
)
if [[ -n "$SPEC" ]]; then
  cmds+=("runMain dast.scan.AccessScannerMain $SPEC")
  cmds+=("runMain dast.scan.SpaIdorScannerMain $URL $SPEC")
fi

echo "==> scanning $URL${SPEC:+ (spec: $SPEC)} -- ${#cmds[@]} stage(s), one sbt session"
sbt -batch "${cmds[@]}"
echo "==> scan complete"
