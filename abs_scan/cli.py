from __future__ import annotations
import argparse, json, sys
from pathlib import Path
from .rules import RULES, SEV_ORDER

BANNER = "agent-boundary-scan {} - AI coding agent boundary risks\n"


def scan(root: Path):
    root = Path(root).resolve()
    out = []
    for r in RULES:
        try:
            if r.__code__.co_argcount > 1:
                out.extend(r(root, ))
            else:
                out.extend(r(root))
        except Exception as e:  # a rule must never kill the run
            out.append(dict(id="ERR", title=f"rule {r.__name__} failed: {e}",
                            severity="info", path=str(root), evidence="", refs=[], fix=""))
    seen, uniq = set(), []
    for f in out:
        k = (f["id"], f["path"], f["evidence"])
        if k in seen:
            continue
        seen.add(k)
        uniq.append(f)
    uniq.sort(key=lambda f: (SEV_ORDER.get(f["severity"], 9), f["id"]))
    return uniq


def sarif(root, findings):
    rules = {}
    for f in findings:
        rules[f["id"]] = {"id": f["id"], "name": f["id"], "shortDescription": {"text": f["title"]},
                          "help": {"text": f"{f['fix']} refs={','.join(f['refs'])}"}}
    return {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "agent-boundary-scan", "rules": list(rules.values())}},
        "results": [{"ruleId": f["id"], "level": {"critical": "error", "high": "error",
                                                  "medium": "warning", "low": "note",
                                                  "info": "note"}.get(f["severity"], "note"),
                     "message": {"text": f["title"]},
                     "locations": [{"physicalLocation": {"artifactLocation": {"uri": f["path"]}}}]}
                    for f in findings]}]}


def main(argv=None):
    ap = argparse.ArgumentParser(prog="abs", description="scan a repo for AI-agent boundary risks")
    ap.add_argument("path", nargs="?", default=".")
    ap.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    ap.add_argument("--min", default="low", choices=list(SEV_ORDER))
    ap.add_argument("--fail-on", default="none", choices=["none"] + list(SEV_ORDER))
    a = ap.parse_args(argv)
    fs = [f for f in scan(Path(a.path)) if SEV_ORDER.get(f["severity"], 9) <= SEV_ORDER[a.min]]
    if a.format == "json":
        print(json.dumps(fs, indent=2))
    elif a.format == "sarif":
        print(json.dumps(sarif(a.path, fs), indent=2))
    else:
        print(BANNER.format(__import__("abs_scan").__version__), end="")
        if not fs:
            print("no agent-boundary risks found")
        for f in fs:
            print(f"[{f['severity']:<8}] {f['id']:<8} {f['path']}\n           {f['title']}")
            if f["evidence"]:
                print(f"           evidence: {f['evidence'][:120]}")
    if a.fail_on != "none" and any(SEV_ORDER.get(f["severity"], 9) <= SEV_ORDER[a.fail_on] for f in fs):
        sys.exit(1)
