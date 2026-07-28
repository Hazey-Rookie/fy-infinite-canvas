"""Maintain Codex project documentation without third-party dependencies.

The command deliberately treats active records as immutable inputs during a
preview. Only ``archive --apply`` moves records after their front matter proves
that implementation and verification are complete.
"""

from __future__ import annotations

import argparse
import datetime as dt
import re
import shutil
from pathlib import Path
from typing import Dict, Iterable, List, Tuple


ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / ".codex" / "project-docs"
GENERATED = DOCS / "generated"
RECORD_KINDS = {
    "requirements": {
        "active": DOCS / "requirements" / "active",
        "archive": DOCS / "requirements" / "archive",
        "required": {"id", "title", "status", "verified", "implementation_ref"},
        "eligible": {"implemented", "accepted", "released", "已实现", "已验收", "已发布"},
    },
    "work": {
        "active": DOCS / "work" / "active",
        "archive": DOCS / "work" / "archive",
        "required": {"id", "title", "status", "verified", "implementation_ref"},
        "eligible": {"completed", "implemented", "已完成", "已实现"},
    },
}


def parse_frontmatter(path: Path) -> Dict[str, object]:
    """Parse the intentionally small scalar front matter contract."""
    lines = path.read_text(encoding="utf-8-sig").splitlines()
    if not lines or lines[0].strip() != "---":
        return {}
    values: Dict[str, object] = {}
    for line in lines[1:]:
        if line.strip() == "---":
            break
        if not line.strip() or line.lstrip().startswith("#") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if value.lower() == "true":
            parsed: object = True
        elif value.lower() == "false":
            parsed = False
        else:
            parsed = value
        values[key.strip()] = parsed
    return values


def active_records(kind: str, root: Path = ROOT) -> Iterable[Tuple[Path, Dict[str, object]]]:
    directory = root / ".codex" / "project-docs" / kind / "active"
    if not directory.exists():
        return []
    return (
        (path, parse_frontmatter(path))
        for path in sorted(directory.glob("*.md"))
        if path.name.lower() != "readme.md"
    )


def record_errors(kind: str, path: Path, metadata: Dict[str, object]) -> List[str]:
    config = RECORD_KINDS[kind]
    errors = [f"{path}: missing front matter"] if not metadata else []
    for field in sorted(config["required"] - metadata.keys()):
        errors.append(f"{path}: missing field {field}")
    if metadata and not isinstance(metadata.get("verified"), bool):
        errors.append(f"{path}: verified must be true or false")
    if metadata.get("status") in config["eligible"]:
        if metadata.get("verified") is not True:
            errors.append(f"{path}: eligible status requires verified: true")
        if not str(metadata.get("implementation_ref", "")).strip():
            errors.append(f"{path}: eligible status requires implementation_ref")
    return errors


def check(root: Path = ROOT) -> List[str]:
    required_paths = [
        root / "AGENTS.md",
        root / ".codex" / "project-docs" / "INDEX.md",
        root / ".codex" / "project-docs" / "DOCUMENTATION_SYSTEM.md",
        root / ".codex" / "project-docs" / "foundation" / "CURRENT_STATE.md",
        root / ".codex" / "project-docs" / "generated" / "API_ROUTES.md",
        root / ".codex" / "project-docs" / "generated" / "ENVIRONMENT_VARIABLES.md",
        root / ".codex" / "project-docs" / "generated" / "FILE_INVENTORY.md",
    ]
    errors = [f"missing required documentation: {path.relative_to(root)}" for path in required_paths if not path.exists()]
    ids: Dict[str, Path] = {}
    for kind in RECORD_KINDS:
        for path, metadata in active_records(kind, root):
            errors.extend(record_errors(kind, path, metadata))
            record_id = str(metadata.get("id", "")).strip()
            if record_id:
                if record_id in ids:
                    errors.append(f"duplicate record id {record_id}: {ids[record_id]} and {path}")
                ids[record_id] = path
    return errors


def completion_date(metadata: Dict[str, object], today: dt.date) -> dt.date:
    raw = str(metadata.get("completed_at", "")).strip()
    try:
        return dt.date.fromisoformat(raw[:10])
    except ValueError:
        return today


def archive_candidates(root: Path = ROOT, today: dt.date | None = None) -> List[Tuple[str, Path, Path]]:
    today = today or dt.date.today()
    candidates: List[Tuple[str, Path, Path]] = []
    for kind, config in RECORD_KINDS.items():
        for path, metadata in active_records(kind, root):
            if metadata.get("status") not in config["eligible"]:
                continue
            date = completion_date(metadata, today)
            quarter = (date.month - 1) // 3 + 1
            destination = root / ".codex" / "project-docs" / kind / "archive" / str(date.year) / f"Q{quarter}" / path.name
            candidates.append((kind, path, destination))
    return candidates


def archive(root: Path = ROOT, apply: bool = False, today: dt.date | None = None) -> List[str]:
    messages: List[str] = []
    for kind, source, destination in archive_candidates(root, today):
        if destination.exists():
            raise RuntimeError(f"archive destination already exists: {destination}")
        action = "archive" if apply else "would archive"
        messages.append(f"{action} {source.relative_to(root)} -> {destination.relative_to(root)}")
        if apply:
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(source), str(destination))
    if apply and messages and (root / "main.py").exists():
        generate(root)
    return messages


def generate(root: Path = ROOT) -> None:
    generated = root / ".codex" / "project-docs" / "generated"
    generated.mkdir(parents=True, exist_ok=True)
    route_pattern = re.compile(r"@app\.(get|post|put|patch|delete|websocket)\(\s*['\"]([^'\"]+)")
    routes = []
    for source_name in ("main.py", "fy_auth.py"):
        source = root / source_name
        for number, line in enumerate(source.read_text(encoding="utf-8").splitlines(), 1):
            match = route_pattern.search(line)
            if match:
                routes.append((source_name, number, match.group(1).upper(), match.group(2)))
    routes.sort(key=lambda item: (item[3], item[2], item[0], item[1]))
    route_lines = ["# API 路由清单", "", "> 此文件由 `tools/docs_maintenance.py generate` 生成。", "", "| 方法 | 路径 | 来源 |", "| --- | --- | --- |"]
    route_lines.extend(f"| `{method}` | `{path}` | `{source}:{line}` |" for source, line, method, path in routes)
    (generated / "API_ROUTES.md").write_text("\n".join(route_lines) + "\n", encoding="utf-8")

    env_names = set()
    env_pattern = re.compile(r"os\.getenv\(\s*['\"]([A-Z][A-Z0-9_]*)['\"]")
    for source_name in ("main.py", "fy_auth.py"):
        env_names.update(env_pattern.findall((root / source_name).read_text(encoding="utf-8")))
    example = root / ".env.example"
    if example.exists():
        env_names.update(re.findall(r"^([A-Z][A-Z0-9_]*)=", example.read_text(encoding="utf-8"), re.MULTILINE))
    env_lines = ["# 环境变量清单", "", "> 此文件由 `tools/docs_maintenance.py generate` 生成，只列字段名，不列值。", "", "| 变量 | 代码读取 |", "| --- | --- |"]
    env_lines.extend(f"| `{name}` | `main.py` / `fy_auth.py` / `.env.example` |" for name in sorted(env_names))
    (generated / "ENVIRONMENT_VARIABLES.md").write_text("\n".join(env_lines) + "\n", encoding="utf-8")

    skip = {".git", ".venv", "node_modules", "__pycache__", ".pytest_cache", "assets", "output", ".local-private", "data"}
    files = []
    for path in root.rglob("*"):
        if not path.is_file() or any(part in skip for part in path.parts):
            continue
        try:
            relative = path.relative_to(root)
            lines = len(path.read_text(encoding="utf-8").splitlines()) if path.suffix.lower() in {".py", ".js", ".css", ".html", ".md", ".json", ".yml", ".yaml", ".txt"} else "-"
            files.append((str(relative).replace("\\", "/"), path.stat().st_size, lines))
        except (OSError, UnicodeDecodeError):
            continue
    files.sort(key=lambda item: (-item[2] if isinstance(item[2], int) else 0, item[0]))
    inventory = ["# 文件规模清单", "", "> 此文件由 `tools/docs_maintenance.py generate` 生成；运行数据和依赖目录已排除。", "", "| 文件 | 字节 | 行数 |", "| --- | ---: | ---: |"]
    inventory.extend(f"| `{name}` | {size} | {lines} |" for name, size, lines in files)
    (generated / "FILE_INVENTORY.md").write_text("\n".join(inventory) + "\n", encoding="utf-8")

    archive_lines = ["# 需求与实施归档索引", "", "> 此文件由 `tools/docs_maintenance.py generate` 生成。", "", "| 类型 | 编号 | 标题 | 状态 | 路径 |", "| --- | --- | --- | --- | --- |"]
    for kind, config in RECORD_KINDS.items():
        archive_root = root / ".codex" / "project-docs" / kind / "archive"
        if not archive_root.exists():
            continue
        for path in sorted(archive_root.rglob("*.md")):
            metadata = parse_frontmatter(path)
            if not metadata:
                continue
            archive_lines.append(f"| {kind} | `{metadata.get('id', '')}` | {metadata.get('title', '')} | `{metadata.get('status', '')}` | `{path.relative_to(root).as_posix()}` |")
    (generated / "ARCHIVE_INDEX.md").write_text("\n".join(archive_lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Maintain FY Canvas Codex documentation")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("check")
    subparsers.add_parser("generate")
    archive_parser = subparsers.add_parser("archive")
    archive_parser.add_argument("--apply", action="store_true", help="move eligible records")
    args = parser.parse_args()
    if args.command == "check":
        errors = check()
        for error in errors:
            print(f"ERROR: {error}")
        print("documentation check passed" if not errors else f"documentation check failed: {len(errors)} error(s)")
        return 0 if not errors else 1
    if args.command == "generate":
        generate()
        print("generated documentation refreshed")
        return 0
    for message in archive(apply=args.apply):
        print(message)
    if not args.apply:
        print("preview only; rerun with --apply to move records")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
