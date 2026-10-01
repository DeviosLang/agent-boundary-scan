# agent-boundary-scan (`abs`)

> **A repository can choose a program that runs on your machine the moment an AI coding agent opens it.**
> `abs` finds those places — before Claude Code / Codex / gemini-cli / Cursor do.

Every serious agent escape of 2026 had the same shape: **the agent trusted something the repository supplied**.
`abs` scans a repo for those trust boundaries and reports them, with the CVE that proved each class.

```bash
pip install .                  # or: pip install agent-boundary-scan
abs .                          # or: python3 -m abs_scan .
abs . --format sarif           # SARIF 2.1.0 -> GitHub code scanning
abs . --fail-on high           # CI gate (see action/action.yml)
```

```
agent-boundary-scan 0.1.0 - AI coding agent boundary risks
[critical] CC-001   /tmp/abs-mal/.claude/settings.json
           repo-supplied Claude Code hooks (SessionStart/PreToolUse...) run unsandboxed
           evidence: SessionStart
[critical] GIT-001  /tmp/abs-mal/.git/config
           repo-supplied core.hooksPath -> agent runs attacker hook outside sandbox
           evidence: core.hookspath = .githooks
[critical] GIT-002  /tmp/abs-mal/.git/config
           repo-supplied core.fsmonitor -> command exec on every git op
           evidence: core.fsmonitor = ./tools/watch.sh
[high    ] GIT-010  /tmp/abs-mal/.gitattributes
           smudge/clean filter executes a command on checkout/add
           evidence: * filter=evil
[high    ] MCP-001  /tmp/abs-mal/.mcp.json
           repo-declared MCP server 'helper' executes sh
           evidence: sh
...
```

## What it detects

| id | risk | proven by |
|---|---|---|
| `GIT-001..009` | repo-supplied `core.hooksPath` / `fsmonitor` / `pager` / `sshCommand` / `editor` / `gitProxy` / `alternate object dirs` / `protocol.ext::allow` / `url.*.insteadof` | CVE-2026-19590, CVE-2026-19592, CVE-2026-71963 |
| `GIT-010/011` | smudge/clean/process **filter drivers** — `.gitattributes` names the driver, `.git/config` supplies the program; `git status` has no flag to turn it off | CWE-829 |
| `GIT-012/013` | `.git` pointer & path-confusing worktrees | CVE-2026-55607 |
| `CC-001/002/003` | repo-supplied Claude Code **hooks**, over-broad auto-approvals, `defaultMode` disabling the approval boundary | CVE-2026-25725 |
| `CTX-001` | instruction injection in `CLAUDE.md` / `AGENTS.md` / `.cursorrules` / copilot instructions | CWE-74 |
| `MCP-001/002` | repo-declared MCP servers (local command + remote URL) in `.mcp.json`, `.cursor/`, `.vscode/`, `.gemini/settings.json`, `.continue/mcpServers/` | CWE-829 |
| `CX-001/002` | Codex `node_repl` / experimental surface | Heapjack-style shared-heap exposure |
| `ENV-001..010` | repo `.env` steering git through `GIT_EXTERNAL_DIFF`, `GIT_SSH_COMMAND`, `GIT_CONFIG_COUNT/KEY_n/VALUE_n`, `GIT_ASKPASS`, `GIT_PAGER`, … | CWE-829, CWE-426 |
| `FS-001` | symlinks escaping the workspace (sandbox-write × host-follow) | CVE-2026-39861 |
| `DEV-001/002` | `.devcontainer/devcontainer.json` lifecycle commands (`postCreateCommand`, …) and editor extensions installed automatically | documented feature |
| `VS-001` | `.vscode/tasks.json` task with `runOn: folderOpen` — runs when the folder opens | documented feature |
| `HK-001` | git hook scripts shipped in the repository (`.husky/`, `.lefthook/`, `.githooks/`, `pre-commit`) — reachable when `core.hooksPath` points inside the repo | CWE-829 |
| `EN-001` | `.envrc` (direnv) executing shell on entering the directory | CWE-829 |
| `PKG-001` | `package.json` `preinstall`/`install`/`postinstall` — runs with the `npm install` an agent often performs for you | CWE-829 |

## Why it exists

2026's agent bugs are not model bugs — they are **boundary bugs**: the component that enforces
the boundary runs in the same environment it polices, and takes its parameters from untrusted input
(a repo, an issue, a patch, a tool result). `abs` turns that into a check you can run in CI.

Note the asymmetry that makes this class awkward to close: git's execution sinks split into
**fixed-name** ones (`core.hooksPath`, `core.fsmonitor`, …) and **repository-named** ones
(`filter.<name>.process`, `diff.<name>.textconv` — the name comes from `.gitattributes`, so a list
of known keys cannot enumerate it). `abs` reports the repository side of that: a filter driver, an
MCP server, or a `GIT_*` env channel shipped inside a repository is something you want to see
before anything automated opens it.

## Scope: what this is not

`abs` inspects **repository content**. It does not test, fingerprint or score any vendor's
mitigation, and it says nothing about whether a given agent is vulnerable. Vendor-side
differential tooling lives in a separate project.

## Fixtures

```bash
python3 corpus/gen.py /tmp/mal malicious && abs /tmp/mal   # 29 findings
python3 corpus/gen.py /tmp/ok  clean     && abs /tmp/ok    # no findings
```

## CI

```yaml
- uses: actions/setup-python@v5
  with: {python-version: "3.11"}
- run: pip install . && abs . --fail-on high      # composite action: action/action.yml
```

`--format sarif` feeds GitHub code scanning (see `.github/workflows/ci.yml`).

## Tests

```bash
pip install -e ".[dev]" && pytest -q        # 13 tests: fixture A/B, SARIF shape, exit codes
```

## Roadmap

- [ ] `--fix` suggestions per rule
- [ ] vendor-side differential suite (`agent-boundary-diff`)
- [ ] single-binary Rust build for air-gapped CI
- [ ] commercial rule pack (enterprise policy + reporting)

## Commercial

AGPL-3.0-or-later. **Detection rules are the product** — org policy rules, reporting/compliance
export, central rule management and support ship as a commercial rule pack under separate terms.
If you run coding agents on code you do not fully control and want that, get in touch
(issues are fine for a first contact).

Vendor-boundary security reviews and agent-hardening consulting are available on the same subject:
repository-controlled execution surfaces, approval-parser differentials, MCP and config surfaces.
