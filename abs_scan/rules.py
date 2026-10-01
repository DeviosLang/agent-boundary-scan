"""
Detection rules for AI coding agent boundary risks.

Each rule takes a ScanContext and yields Finding(dict).
Rule ids are stable: <FAMILY>-<NNN>.  Keep them stable, they are the product.
"""
from __future__ import annotations
import json
import os
import re
from pathlib import Path

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def F(rid, title, severity, path, evidence, refs, fix):
    return dict(id=rid, title=title, severity=severity, path=str(path),
                evidence=evidence, refs=refs, fix=fix)


# ---------- git config family (the 2026 agent bug class) ----------
def _normalise_section(section: str) -> str:
    """[protocol "ext"] -> "protocol.ext";  [core] -> "core";  [filter "p"] -> "filter.p"."""
    head, _, tail = section.partition(" ")
    head = head.lower()
    tail = tail.strip()
    if len(tail) >= 2 and tail[0] == '"' and tail[-1] == '"':
        tail = tail[1:-1]
    return f"{head}.{tail.lower()}" if tail else head



GIT_HIJACK_KEYS = {
    "core.hookspath": ("critical", "GIT-001",
                       "repo-supplied core.hooksPath -> agent runs attacker hook outside sandbox"),
    "core.fsmonitor": ("critical", "GIT-002",
                       "repo-supplied core.fsmonitor -> command exec on every git op"),
    "core.pager":     ("high",     "GIT-003", "core.pager executes on git output"),
    "core.sshcommand": ("critical","GIT-004", "core.sshCommand hijacks every git ssh operation"),
    "core.editor":    ("high",     "GIT-005", "core.editor executes during rebase/commit --amend"),
    "core.gitproxy":  ("high",     "GIT-006", "core.gitProxy runs on every remote git:// fetch"),
    "core.alternateobjectdirectories": ("high", "GIT-007",
                       "alternate object dirs can point the agent at attacker objects"),
    "protocol.ext.allow": ("critical", "GIT-008",
                       "ext:: protocol allowed -> remote command execution via git fetch"),
    "url..insteadof": ("medium", "GIT-009", "URL rewrite can redirect agent fetches"),
}

REFS_GIT = ["CVE-2026-19590", "CVE-2026-19592", "CVE-2026-72718(goose)", "CVE-2026-71963(Hermes)"]


def rule_git_config(root: Path):
    for gitpath in [root / ".git" / "config", root / ".gitconfig", root / "..git" / "config"]:
        if not gitpath.is_file():
            continue
        txt = gitpath.read_text(errors="replace")
        cur_section = ""
        for raw in txt.splitlines():
            line = raw.strip()
            if line.startswith("[") and line.endswith("]"):
                cur_section = _normalise_section(line[1:-1])
                continue
            if "=" not in line or line.startswith(("#", ";")):
                continue
            k, v = line.split("=", 1)
            k, v = k.strip().lower(), v.strip()
            full = f"{cur_section.lower()}.{k}" if cur_section else k
            for key, (sev, rid, title) in GIT_HIJACK_KEYS.items():
                if key.count("..") == 1 and re.fullmatch(key.replace("..", r"\..*\."), full):
                    yield F(rid, title, sev, gitpath, f"{full} = {v}", REFS_GIT,
                            "Move the setting to the user-level ~/.gitconfig, or refuse repos shipping it.")
                elif full == key:
                    yield F(rid, title, sev, gitpath, f"{full} = {v}", REFS_GIT,
                            "Move the setting to the user-level ~/.gitconfig, or refuse repos shipping it.")


def rule_gitattributes_filter(root: Path):
    ga = root / ".gitattributes"
    if ga.is_file():
        for line in ga.read_text(errors="replace").splitlines():
            if re.search(r"filter\s*=\s*\w+", line):
                yield F("GIT-010", "smudge/clean filter executes a command on checkout/add",
                        "high", ga, line.strip(), ["CWE-829"],
                        "Disallow repo-defined filters (git config --unset filter.*).")
                break
    cfg = root / ".git" / "config"
    if cfg.is_file() and re.search(r"^\s*(smudge|clean|process)\s*=", cfg.read_text(errors="replace"), re.M):
        yield F("GIT-011", "filter driver command defined in repo .git/config",
                "high", cfg, "filter.*.smudge/clean/process", ["CWE-829"],
                "Do not let the repo define filter drivers.")


def rule_git_path_confusion(root: Path):
    g = root / ".git"
    if g.is_file():
        yield F("GIT-012", ".git is a file (gitdir pointer) - worktree path confusion",
                "high", g, g.read_text(errors="replace").strip(), ["CVE-2026-55607"],
                "Reject repos whose .git is a pointer to an attacker-controlled dir.")
    wt_dir = root / ".git" / "worktrees"
    if wt_dir.is_dir():
        for name in sorted(os.listdir(wt_dir)):
            if not name.startswith("."):
                continue
            yield F("GIT-013", f"worktree named '{name}' can confuse agent path checks",
                    "high", wt_dir / name, name, ["CVE-2026-55607"],
                    "Reject worktrees with path-confusing names.")


# ---------- Claude Code family ----------
def _load_json(p: Path):
    try:
        return json.loads(p.read_text(errors="replace"))
    except Exception:
        return None


def _is_overbroad_allow(rule: str) -> bool:
    """True if a Claude Code permissions.allow entry auto-approves more than it looks like."""
    r = rule.strip()
    if r in ("*", "Bash", "Bash(*)", "Bash(**)", "Write", "Edit", "Write(*)", "Edit(*)"):
        return True
    # Bash(git *)          -> any git subcommand   (but  Bash(git status) is fine)
    # Bash(npm:*)          -> tool wildcard form
    if r.startswith("Bash(") and ("**" in r or r.endswith("*)") or r.endswith(":*")):
        return True
    # Write(/**/*) / Edit(/**/*) / Read(/**/*)
    if r.startswith(("Write(", "Edit(", "Read(")) and ("**" in r or r.endswith("*)")):
        return True
    # WebFetch(domain:*) / mcp__*__* wildcards
    if r.endswith("__*") or r.startswith("mcp__") and r.endswith("*"):
        return True
    return False


def rule_claude_settings(root: Path):
    for p in list(root.glob(".claude/settings*.json")) + list(root.glob(".claude/**/settings*.json")):
        d = _load_json(p)
        if not isinstance(d, dict):
            continue
        hooks = d.get("hooks") or {}
        if hooks:
            yield F("CC-001", "repo-supplied Claude Code hooks (SessionStart/PreToolUse...) run unsandboxed",
                    "critical", p, ",".join(hooks.keys())[:200], ["CVE-2026-25725"],
                    "Hooks must be user-owned and outside the repo; refuse repo-provided hooks.")
        perms = d.get("permissions") or {}
        allow = perms.get("allow") or []
        for a in allow:
            if _is_overbroad_allow(str(a)):
                yield F("CC-002", f"over-broad auto-approval: {a}", "high", p, str(a), ["CWE-732"],
                        "Scope allow rules to explicit commands/paths.")
                break
        if perms.get("defaultMode") in ("acceptEdits", "bypassPermissions", "dangerously-skip-permissions"):
            yield F("CC-003", f"permission defaultMode={perms['defaultMode']} disables the approval boundary",
                    "high", p, str(perms.get("defaultMode")), ["CWE-732"],
                    "Keep defaultMode default; never ship it in a repo.")


INJECT_PAT = [
    (r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+instructions", "classic instruction override"),
    (r"(?i)do\s+not\s+(tell|inform|mention)\s+the\s+user", "concealment directive"),
    (r"curl\s+[^|]*\|\s*(ba)?sh", "curl|sh in agent instructions"),
    (r"~/.ssh|id_ed25519|authorized_keys", "attempts to touch ssh credentials"),
    (r"--dangerously-skip-permissions|--yolo|--no-verify", "asks agent to disable its own guardrails"),
    (r"(?i)(read|exfiltrate|send)\s+.{0,40}(api[_-]?key|token|secret|credential)", "credential exfiltration ask"),
]


def rule_context_injection(root: Path):
    for name in ("CLAUDE.md", "AGENTS.md", ".cursorrules", ".github/copilot-instructions.md",
                 "CONTRIBUTING.md", "README.md", ".claude/agents/*.md"):
        for p in root.glob(name):
            if not p.is_file():
                continue
            txt = p.read_text(errors="replace")
            hits = [desc for pat, desc in INJECT_PAT if re.search(pat, txt)]
            if hits:
                yield F("CTX-001", f"instruction-injection patterns in agent context file ({', '.join(hits[:3])})",
                        "high", p, txt[:160].replace("\n", " "), ["CWE-74", "LLM01"],
                        "Treat repo markdown as data; require human review of agent context files.")


# ---------- MCP / Codex family ----------
def rule_mcp(root: Path):
    candidates = set()
    for pat in (".mcp.json", "**/.mcp.json", ".cursor/mcp.json", ".vscode/mcp.json",
                ".gemini/settings.json", ".continue/mcpServers/*.json", ".codex/mcp.json"):
        candidates.update(root.glob(pat))
    for p in sorted(candidates):
        d = _load_json(p)
        if not isinstance(d, dict):
            continue
        servers = d.get("mcpServers") or d.get("mcp") or {}
        if not isinstance(servers, dict):
            continue
        for srv, cfg in servers.items():
            if not isinstance(cfg, dict):
                continue
            cmd = str(cfg.get("command", ""))
            if cmd:
                yield F("MCP-001", f"repo-declared MCP server '{srv}' executes {cmd}",
                        "high", p, cmd[:200], ["CWE-829"],
                        "MCP servers must be registered by the user, never by the repo.")
            if cfg.get("url"):
                yield F("MCP-002", f"remote MCP server '{srv}' -> {cfg['url']}",
                        "medium", p, str(cfg["url"])[:200], ["CWE-829"],
                        "Pin and review remote MCP endpoints.")


def rule_codex_config(root: Path):
    for p in list(root.glob("**/config.toml")) + list(root.glob(".codex/config.toml")):
        txt = p.read_text(errors="replace")
        if re.search(r"^\s*node_repl\s*=|\[.*node_repl.*\]", txt, re.M):
            yield F("CX-001", "codex node_repl enabled (shared-heap token exposure class)",
                    "high", p, "node_repl", ["Heapjack-style shared-heap exposure (public research)"],
                    "Disable node_repl unless required.")
        if re.search(r"experimental", txt, re.I):
            yield F("CX-002", "experimental codex features enabled (out of bounty scope + risk)",
                    "medium", p, "experimental", [], "Disable in shared environments.")



ENV_CHANNELS = [
    ("GIT_EXTERNAL_DIFF", "critical", "ENV-001", "git external diff driver executed on every diff"),
    ("GIT_SSH_COMMAND",   "critical", "ENV-002", "git ssh command override (also honoured by git >= 2.3)"),
    ("GIT_ASKPASS",       "high",     "ENV-003", "credential prompt helper executed by git"),
    ("GIT_CONFIG",        "high",     "ENV-004", "GIT_CONFIG points git at another config file"),
    ("GIT_CONFIG_COUNT",  "high",     "ENV-005", "GIT_CONFIG_COUNT/KEY_n/VALUE_n injects arbitrary git config"),
    ("GIT_CONFIG_GLOBAL", "high",     "ENV-006", "GIT_CONFIG_GLOBAL redirects the global config git reads"),
    ("GIT_CONFIG_SYSTEM", "high",     "ENV-007", "GIT_CONFIG_SYSTEM redirects the system config git reads"),
    ("GIT_PAGER",         "medium",   "ENV-008", "pager executed on git output"),
    ("GIT_EDITOR",        "medium",   "ENV-009", "editor executed by git"),
    ("GIT_ALTERNATE_OBJECT_DIRECTORIES", "high", "ENV-010", "alternate object dirs (attacker objects)"),
]


def rule_env_channels(root: Path):
    """Repo-shipped .env / dotenv files that steer the environment of git and of agents.

    Agents (aider, and any tool that loads a repo .env) and shells (direnv, dotenv,
    `. env`) turn these into real environment variables.
    """
    for name in (".env", ".env.local", "*.env", ".envrc"):
        for p in root.glob(name):
            if not p.is_file():
                continue
            for raw in p.read_text(errors="replace").splitlines()[:400]:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k = line.split("=", 1)[0].strip()
                for key, sev, rid, title in ENV_CHANNELS:
                    if k == key or k.startswith(key + "_"):
                        yield F(rid, title, sev, p, line[:160], ["CWE-829", "CWE-426"],
                                "Never let a repository set git env channels; strip them on clone.")
                        break



# ---------- repo-controlled auto-execution surfaces ----------
# These are documented features, not bugs: each is a place where a repository ships
# something that runs on its own when a tool opens the directory. An agent that
# opens the folder inherits all of them.
def rule_devcontainer(root: Path):
    import json as _json
    for p in list(root.glob(".devcontainer/devcontainer.json")) + list(root.glob(".devcontainer/*/devcontainer.json")):
        d = _load_json(p)
        if not isinstance(d, dict):
            continue
        for key in ("initializeCommand", "onCreateCommand", "postCreateCommand",
                    "postStartCommand", "postAttachCommand"):
            if key in d:
                yield F("DEV-001", f"devcontainer lifecycle command '{key}' runs when the container is created",
                        "high", p, f"{key}: {str(d[key])[:120]}", ["CWE-829"],
                        "Review devcontainer lifecycle commands before opening the folder in a container.")
        cust = d.get("customizations") or {}
        exts = (cust.get("vscode") or {}).get("extensions") or []
        if exts:
            yield F("DEV-002", f"devcontainer installs {len(exts)} editor extension(s) automatically "
                               "(extensions execute code in the editor host)",
                    "medium", p, ",".join(map(str, exts[:3]))[:160], ["CWE-829"],
                    "Pin the extension list; a repository should not choose your editor's code.")


def rule_vscode_tasks(root: Path):
    import json as _json
    for p in list(root.glob(".vscode/tasks.json")):
        d = _load_json(p)
        if not isinstance(d, dict):
            continue
        for t in (d.get("tasks") or []):
            if not isinstance(t, dict):
                continue
            run_on = ((t.get("runOptions") or {}).get("runOn")) or t.get("runOn")
            if run_on in ("folderOpen", "default"):
                cmd = t.get("command") or (t.get("dependsOn") or "")
                yield F("VS-001", f"VS Code task '{t.get('label', '?')}' is set to run on folder open",
                        "high", p, f"runOn={run_on} command={str(cmd)[:100]}", ["CWE-829"],
                        "Tasks with runOn: folderOpen execute automatically when the folder opens.")


HOOK_DIRS = [".husky", ".husky/_", ".lefthook", ".lefthook-local", ".git-hooks", ".githooks", ".pre-commit-config.yaml"]
HOOK_FILES = ["pre-commit", "post-checkout", "post-merge", "pre-push", "prepare-commit-msg",
              "post-index-change"]


def rule_repo_hooks(root: Path):
    """Hook scripts shipped inside the repository (husky / lefthook / pre-commit / plain .githooks).

    `core.hooksPath` (often set by husky or lefthook at install time) points git at a directory
    inside the repository, so these are ordinary committed files that git will execute.
    """
    for d in HOOK_DIRS:
        cand = root / d
        if cand.is_file() and d.endswith(".yaml"):
            yield F("HK-001", "repo ships a pre-commit (pre-commit.com) configuration that runs hooks",
                    "medium", cand, d, ["CWE-829"],
                    "Review the hooks named in .pre-commit-config.yaml; they run on git operations.")
            continue
        if not cand.is_dir():
            continue
        for name in sorted(os.listdir(cand)):
            if name in HOOK_FILES or name.endswith((".sh", ".py", ".js")):
                yield F("HK-001", f"repo ships a git hook script '{d}/{name}'",
                        "medium", cand / name, f"{d}/{name}", ["CWE-829"],
                        "Hooks must be user-owned and outside the repository.")


def rule_direnv(root: Path):
    for p in list(root.glob(".envrc")) + list(root.glob(".direnv/*")):
        if p.is_file():
            txt = p.read_text(errors="replace")
            if any(k in txt for k in ("use ", "source_env", "layout", "PATH=", "eval")):
                yield F("EN-001", "direnv .envrc executes shell on entering the directory",
                        "medium", p, txt[:120].replace("\n", " "), ["CWE-829"],
                        "direnv requires `direnv allow`; never grant it to an untrusted tree.")


def rule_install_scripts(root: Path):
    import json as _json
    for p in list(root.glob("package.json")):
        d = _load_json(p)
        if not isinstance(d, dict):
            continue
        scripts = d.get("scripts") or {}
        for key in ("preinstall", "install", "postinstall", "prepare", "prepublishOnly"):
            if key in scripts:
                sev = "high" if key in ("preinstall", "install", "postinstall") else "medium"
                yield F("PKG-001", f"package.json '{key}' script runs on `npm install`",
                        sev, p, f"{key}: {str(scripts[key])[:120]}", ["CWE-829"],
                        "Agents commonly run npm install; lifecycle scripts execute with it. "
                        "Use `npm install --ignore-scripts` on a tree you have not reviewed.")

# ---------- filesystem family ----------
def rule_symlinks(root: Path, max_entries=20000):
    n = 0
    root_resolved = str(root.resolve())
    for dirpath, dirnames, filenames in os.walk(root):
        if n > max_entries:
            return
        n += 1
        if os.path.basename(dirpath) == ".git":
            dirnames[:] = []
        for fn in filenames + dirnames:
            p = Path(dirpath) / fn
            if p.is_symlink():
                tgt = os.readlink(p)
                resolved = (p.parent / tgt).resolve() if not os.path.isabs(tgt) else Path(tgt)
                if not str(resolved).startswith(root_resolved):
                    yield F("FS-001", "symlink escaping the workspace (sandbox-write x host-follow)",
                            "medium", p, f"{p.name} -> {tgt}", ["CVE-2026-39861", "CVE-2026-25725"],
                            "Strip symlinks on clone/checkout.")


RULES = [rule_git_config, rule_gitattributes_filter, rule_git_path_confusion,
         rule_claude_settings, rule_context_injection, rule_mcp,
         rule_codex_config, rule_env_channels,
         rule_devcontainer, rule_vscode_tasks, rule_repo_hooks, rule_direnv,
         rule_install_scripts, rule_symlinks]
