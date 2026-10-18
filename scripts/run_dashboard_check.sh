#!/usr/bin/env bash
# Generates reports from the demo fixtures, then checks the dashboard against them in jsdom.
set -euo pipefail
cd "$(dirname "$0")/.."
export DASH_DIR="$(mktemp -d)"
sentinel scan examples/vulnerable-demo --registry-fixture examples/vulnerable-demo/registry-fixture.json --output-dir "$DASH_DIR/vuln" >/dev/null || true
sentinel scan examples/clean-demo --registry-fixture examples/clean-demo/registry-fixture.json --output-dir "$DASH_DIR/clean" >/dev/null || true
sentinel scan examples/clean-demo --registry-fixture examples/clean-demo/registry-error-fixture.json --output-dir "$DASH_DIR/error" >/dev/null 2>&1 || true
mkdir -p "$DASH_DIR/evil-src"
echo '{"dependencies": {"<img-src=x-onerror=window.__pwned=1>": "1.0.0", "a-b": "<script>window.__pwned=2</script>"}}' > "$DASH_DIR/evil-src/package.json"
sentinel scan "$DASH_DIR/evil-src" --output-dir "$DASH_DIR/evil" >/dev/null 2>&1 || true
TOOLS="$(mktemp -d)"
(cd "$TOOLS" && npm init -y >/dev/null && npm install jsdom --silent)
NODE_PATH="$TOOLS/node_modules" node scripts/dashboard_check.js
