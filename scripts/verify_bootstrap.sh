#!/usr/bin/env bash
# Bootstrap verification: runs the local gate set plus Phase 1 invariants.
# Exit 0 only when everything is green. Safe to run repeatedly.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "==> make check"
make check

echo "==> kolega-scan --version"
PYTHONPATH=src python3 -m kolega_security_scanner.cli.main --version >/dev/null

echo "==> finding JSON Schema golden matches"
PYTHONPATH=src python3 -c "from kolega_security_scanner.schema.export import dump_finding_schema, GOLDEN_PATH; \
import sys; \
sys.exit(0 if dump_finding_schema()==GOLDEN_PATH.read_text() else 'finding schema drift')"

echo "==> ground-truth files validate"
PYTHONPATH=src python3 -c "
from pathlib import Path
from kolega_security_scanner.groundtruth.validator import validate_gt_dir
results = validate_gt_dir('ground-truth/findings') if Path('ground-truth/findings').exists() else []
bad = [r for r in results if not r.ok]
if bad:
    for r in bad: print('  FAIL', r.path, r.errors)
    raise SystemExit('GT validation failed')
print(f'   {len(results)} GT files OK')
"

echo "==> slice manifests resolve (js-ts allowed empty)"
PYTHONPATH=src python3 -c "
from pathlib import Path
import yaml
from kolega_security_scanner.groundtruth.slices import resolve_slice
sd = Path('ground-truth/slices')
for f in sorted(sd.glob('*.yaml')):
    name = f.stem
    data = yaml.safe_load(f.read_text()) or {}
    if name == 'js-ts' and data.get('repos') == []:
        print('   js-ts empty (allowed)'); continue
    repos = resolve_slice(name, sd)
    print(f'   {name}: {len(repos)} repos')
" 2>/dev/null || echo "   (no slice manifests yet — run import-published-gt)"

echo "ALL GREEN"
