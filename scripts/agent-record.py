#!/usr/bin/env python
"""Create one agent change record under agent-records/.

Naming contract (see AGENT.md):

    <agent-slug>__<model-slug>__<YYYYMMDD-HHMMSS>__<uniq4>.md

Why a script instead of hand-written names: several agents iterate this repo at
the same time. Two of them finishing within the same second would collide on a
hand-picked name, and a collision silently overwrites one agent's history.
The timestamp gives ordering, the random suffix gives uniqueness, and an
existence check re-rolls the suffix instead of clobbering.

    python scripts/agent-record.py \
        --agent claude-code --model opus-4-5 \
        --summary "fix --task placement" --files findinfo.py SKILL.md

    python scripts/agent-record.py --list          # recent records, newest last
    python scripts/agent-record.py --check         # validate naming contract
    python scripts/agent-record.py --agent X --model Y --dry-run
"""
from __future__ import annotations

import argparse
import re
import secrets
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RECORDS = ROOT / "agent-records"
NAME_RE = re.compile(
    r"^(?P<agent>.+?)__(?P<model>.+?)__(?P<stamp>\d{8}-\d{6})__(?P<uniq>[0-9a-z]{4})\.md$")

KINDS = ("功能", "修复", "重构", "文档", "部署", "测试", "其它")


def slug(text: str, limit: int = 40) -> str:
    """Lowercase, keep [a-z0-9-], collapse separators.

    Model/agent ids arrive in many shapes ('Opus 4.5',
    'mythos-gw-6946973803[1m]', 'gpt-6'). Brackets, slashes and spaces are
    illegal on Windows or confusing in a filename, so they all collapse to '-'.

    CJK names must NOT collapse to 'unknown': two different Chinese-named
    agents would then share a prefix and the record becomes unattributable.
    When ASCII slugging leaves nothing usable, fall back to a short hash of
    the ORIGINAL text, which stays stable and distinct per name.
    """
    import hashlib
    raw = (text or "").strip()
    s = raw.lower()
    s = re.sub(r"[^a-z0-9]+", "-", s)
    s = re.sub(r"-{2,}", "-", s).strip("-")
    if not s:
        # non-ASCII (e.g. 中文) or punctuation-only: stable short hash
        return "x" + hashlib.sha1(raw.encode("utf-8", "replace")).hexdigest()[:10]
    return s[:limit]


def make_path(agent: str, model: str, when: datetime | None = None) -> Path:
    """Build a path that does not exist yet; re-roll uniq4 on collision."""
    RECORDS.mkdir(parents=True, exist_ok=True)
    stamp = (when or datetime.now()).strftime("%Y%m%d-%H%M%S")
    a, m = slug(agent), slug(model)
    for _ in range(64):
        uniq = secrets.token_hex(2)          # 4 hex chars
        p = RECORDS / ("%s__%s__%s__%s.md" % (a, m, stamp, uniq))
        if not p.exists():
            return p
    raise SystemExit("could not allocate a unique record name after 64 tries")


def render(agent: str, model: str, summary: str, files: list[str], kind: str,
           body: str, session: str) -> str:
    now = datetime.now().astimezone().strftime("%Y-%m-%dT%H:%M:%S%z")
    files_txt = "\n".join("- `" + f + "`" for f in files) if files else "- （未列出）"
    extra = ("\n" + body.strip() + "\n") if body.strip() else ""
    return (
        "# " + (summary or "变更记录") + "\n\n"
        "- **Agent**: " + agent + "\n"
        "- **模型**: " + model + "\n"
        "- **时间**: " + now + "\n"
        "- **会话标识**: " + session + "\n"
        "- **性质**: " + kind + "\n\n"
        "## 改了什么\n\n"
        "涉及文件：\n\n" + files_txt + "\n" + extra + "\n"
        "## 行为变化（对调用方 / 下游 agent 的影响）\n\n"
        "（命令、参数、输出字段、退出码、数据模型 — 只写**发生了变化**的部分）\n\n"
        "## 验证方式\n\n"
        "（跑了什么：`python -m tests` 几个用例、哪些手工实测、结果如何）\n\n"
        "## 未完成 / 风险 / 遗留\n\n"
        "（明确写出没验证到的部分，别让下一个 agent 误以为已覆盖）\n\n"
        "## 与其他 agent 的冲突点\n\n"
        "（是否发现别人的并行改动、是否避开、是否需要人工裁决）\n"
    )


def list_records(limit: int = 10) -> int:
    if not RECORDS.is_dir():
        print("no agent-records/ yet")
        return 0
    paths = sorted(RECORDS.glob("*.md"))
    if not paths:
        print("no records yet")
        return 0
    for p in paths[-limit:]:
        m = NAME_RE.match(p.name)
        if m:
            print("%s  agent=%-18s model=%-24s %s" % (
                m.group("stamp"), m.group("agent"), m.group("model"), p.name))
        else:
            print("%-46s (violates the AGENT.md naming contract)" % p.name)
    return 0


def check() -> int:
    """Validate every existing record against the naming contract."""
    bad = []
    for p in sorted(RECORDS.glob("*.md")):
        if not NAME_RE.match(p.name):
            bad.append(p.name)
    if bad:
        print("records violating <agent>__<model>__<stamp>__<uniq4>.md:")
        for b in bad:
            print("  " + b)
        return 1
    print("ok: all records match the naming contract")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        description="Create an agent change record (see AGENT.md)")
    ap.add_argument("--agent", help="agent name, e.g. claude-code")
    ap.add_argument("--model", help="model name, e.g. opus-4-5")
    ap.add_argument("--summary", default="", help="one-line title of the change")
    ap.add_argument("--files", nargs="*", default=[], help="files touched")
    ap.add_argument("--kind", default="其它", choices=KINDS)
    ap.add_argument("--body", default="", help="extra markdown for '改了什么'")
    ap.add_argument("--session", default="", help="session/run id (default: uniq suffix)")
    ap.add_argument("--dry-run", action="store_true", help="print the path, write nothing")
    ap.add_argument("--list", action="store_true", help="list recent records")
    ap.add_argument("--check", action="store_true", help="validate naming contract")
    a = ap.parse_args(argv)

    if a.list:
        return list_records()
    if a.check:
        return check()
    if not a.agent or not a.model:
        ap.error("--agent and --model are required (they are part of the filename)")

    p = make_path(a.agent, a.model)
    if a.dry_run:
        print(str(p))
        return 0
    p.write_text(render(a.agent, a.model, a.summary, a.files, a.kind, a.body,
                        a.session or p.stem.rsplit("__", 1)[-1]),
                 encoding="utf-8", newline="\n")
    print(str(p))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
