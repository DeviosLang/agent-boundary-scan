#!/usr/bin/env sh
# abs demo: build a hostile repository, scan it, show all three output formats.
# No network, no credentials, nothing destructive.
set -e
here=$(cd "$(dirname "$0")/.." && pwd)
cd "$here"

tmp=$(mktemp -d)
echo "== building fixture =="
python3 corpus/gen.py "$tmp/mal" malicious
python3 corpus/gen.py "$tmp/ok" clean

echo
echo "== text =="
python3 -m abs_scan "$tmp/mal" | head -12

echo
echo "== json (first 2 findings) =="
python3 -m abs_scan "$tmp/mal" --format json | python3 -c "import json,sys; d=json.load(sys.stdin); print(json.dumps(d[:2], indent=2))"

echo
echo "== sarif =="
python3 -m abs_scan "$tmp/mal" --format sarif | python3 -c "import json,sys; d=json.load(sys.stdin); r=d['runs'][0]; print('results:', len(r['results']), '| rules:', len(r['tool']['driver']['rules']))"

echo
echo "== CI gate =="
python3 -m abs_scan "$tmp/mal" --fail-on high >/dev/null && echo "malicious: PASS (unexpected)" || echo "malicious: FAIL -> exit 1 (correct)"
python3 -m abs_scan "$tmp/ok"  --fail-on high >/dev/null && echo "clean:     PASS -> exit 0 (correct)" || echo "clean: FAIL (unexpected)"

rm -rf "$tmp"
echo
echo "done."
