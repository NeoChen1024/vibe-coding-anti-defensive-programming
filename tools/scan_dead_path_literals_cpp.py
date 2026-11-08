"""C++ 失效仓库路径字面量扫描器（dead_path_literal_cpp 棘轮规则，scan_dead_path_literals 的 C++ 对应版）。

要解决的问题与 Python 版相同：删掉文件后，C++ 源码 / 测试里写死它路径的字符串不会编译报错，
运行时才读不到文件，或让测试夹具静默失效。

口径：
- 扫描仓库内全部 C++（生产、测试、工具），跳过注释；支持普通、带前缀（u8/L/u/U）与原始字符串 R"(...)"。
- 候选：字符串里含 `/`、首段是仓库顶层目录（Python 版的 REPO_TOP_DIRS 加上本仓库实际存在的顶层目录）、
  带文件扩展名。不计入：运行时产物目录（与 Python 版共用 RUNTIME_PREFIXES）、含空白/通配/格式占位
  （含 printf 的 %）的字符串、绝对路径与 URL、构建产物扩展名（.o/.a/.so/.dll/...）。
- 条目键是 (源文件, 那条失效路径)，count 是出现次数；基线只减不增，刷新时有新增一律拒绝（同 Python 版）。

用法：
    python -m tools.scan_dead_path_literals_cpp [--json] [--fail-on-new]
        [--refresh [--allow-growth]] [--quiet-when-clean]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional, Sequence, Set

from tools.boundary_baseline import (
    BoundaryBaselineError,
    compare_counts,
    default_baseline_path,
    entries_to_counts,
    load_baseline,
    render_comparison,
    total_count,
    write_baseline,
)
from tools.cpp_scan.frontend import CPP_SUFFIXES, iter_files, skip_dir
from tools.scan_dead_path_literals import LOCAL_GENERATED_PATHS, REPO_TOP_DIRS, RUNTIME_PREFIXES

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
RULE = "dead_path_literal_cpp"
BASELINE_NOTE = "C++ 失效仓库路径字面量棘轮基线：删文件必须同步删掉引用它的字符串；条目只减不增，刷新走 --refresh。"

#: 注释、原始字符串、普通字符串（含编码前缀）、字符字面量，按出现顺序互斥匹配。
_TOKEN_RE = re.compile(
    r'//[^\n]*|/\*.*?\*/'
    r'|(?:u8|[LuU])?R"(?P<delim>[^()\\\s]{0,16})\((?P<raw>.*?)\)(?P=delim)"'
    r'|(?:u8|[LuU])?"(?P<plain>(?:\\.|[^"\\\n])*)"'
    r"|'(?:\\.|[^'\\\n])*'",
    re.S,
)
_EXTENSION = re.compile(r"\.([A-Za-z0-9]{1,6})$")
_BUILD_PRODUCTS = frozenset({"o", "obj", "a", "so", "dll", "lib", "dylib", "exe", "pdb", "pch", "gch"})
_NOT_A_PLAIN_PATH = re.compile(r"[\s,*?{}$\\<>|%]")


def repo_top_dirs(repo_root: str) -> Set[str]:
    existing = {
        name for name in os.listdir(repo_root)
        if os.path.isdir(os.path.join(repo_root, name)) and not skip_dir(name)
    }
    return set(REPO_TOP_DIRS) | existing


def is_repo_path_literal(value: str, top_dirs: Set[str]) -> bool:
    if "/" not in value or value.startswith(("/", "http", "~", "./", "../")):
        return False
    if _NOT_A_PLAIN_PATH.search(value):
        return False
    if value.startswith(RUNTIME_PREFIXES) or value in LOCAL_GENERATED_PATHS:
        return False
    extension = _EXTENSION.search(value)
    if extension is None or extension.group(1).lower() in _BUILD_PRODUCTS:
        return False
    return value.split("/", 1)[0] in top_dirs


def string_literals(text: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for match in _TOKEN_RE.finditer(text):
        value = match.group("raw") if match.group("raw") is not None else match.group("plain")
        if value is not None:
            rows.append({"value": value, "line": text.count("\n", 0, match.start()) + 1})
    return rows


def scan(repo_root: str = REPO_ROOT) -> Dict[str, Any]:
    top_dirs = repo_top_dirs(repo_root)
    files = iter_files(repo_root, CPP_SUFFIXES)
    entries: List[Dict[str, Any]] = []
    for rel_path in files:
        with open(os.path.join(repo_root, rel_path), encoding="utf-8", errors="replace") as handle:
            literals = string_literals(handle.read())
        by_literal: Dict[str, List[int]] = {}
        for item in literals:
            value = str(item["value"])
            if is_repo_path_literal(value, top_dirs) and not os.path.exists(os.path.join(repo_root, value)):
                by_literal.setdefault(value, []).append(int(item["line"]))
        for literal in sorted(by_literal):
            lines = sorted(by_literal[literal])
            entries.append({"path": rel_path, "kind": literal, "count": len(lines), "lines": lines})
    return {"rule": RULE, "scan_roots": ["."], "file_count": len(files), "entries": entries,
            "total": sum(int(entry["count"]) for entry in entries)}


def render_text(result: Dict[str, Any]) -> str:
    entries = list(result.get("entries") or [])
    by_file: Dict[str, int] = {}
    for entry in entries:
        by_file[str(entry["path"])] = by_file.get(str(entry["path"]), 0) + int(entry["count"])
    lines = [f"[{RULE}] 扫描 {result['file_count']} 个 C++ 文件，失效路径字面量 {result['total']} 处，涉及 {len(by_file)} 个文件"]
    for path in sorted(by_file, key=lambda item: (-by_file[item], item))[:15]:
        samples = [str(entry["kind"]) for entry in entries if str(entry["path"]) == path][:3]
        lines.append(f"  {by_file[path]:3d}  {path}  ({', '.join(samples)})")
    return "\n".join(lines)


def _parse_args(argv: Optional[Sequence[str]]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="C++ 失效仓库路径字面量棘轮扫描器")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--fail-on-new", action="store_true", help="相对基线有新增/增加/失效条目即退出码 1；基线异常退出码 2")
    parser.add_argument("--refresh", action="store_true", help="按当前扫描结果重写基线（有新增条目时拒绝）")
    parser.add_argument("--allow-growth", action="store_true")
    parser.add_argument("--quiet-when-clean", action="store_true")
    parser.add_argument("--repo-root", default=REPO_ROOT, help=argparse.SUPPRESS)
    return parser.parse_args(list(argv) if argv is not None else None)


def _error(message: str) -> None:
    print(f"[dead-path-literal-cpp] {message}", file=sys.stderr, flush=True)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    result = scan(os.path.abspath(args.repo_root))
    current = entries_to_counts(list(result["entries"]))
    baseline_path = default_baseline_path(args.repo_root, RULE)
    if args.refresh:
        try:
            previous = load_baseline(baseline_path, expected_rule=RULE)
        except BoundaryBaselineError as exc:
            _error(str(exc))
            return 2
        if previous is not None and not args.allow_growth:
            comparison = compare_counts(current, previous)
            if comparison.new or comparison.increased:
                detail = sorted(comparison.new) + sorted(comparison.increased)
                _error("刷新被拒绝：有新增的失效路径字面量，请先改掉引用而不是刷基线；"
                       "确属测试夹具等人工核对过的情况再加 --allow-growth。\n  "
                       + "\n  ".join(f"{path} -> {literal}" for path, literal in detail))
                return 1
        write_baseline(baseline_path, rule=RULE, scan_roots=["."], note=BASELINE_NOTE, counts=current)
        print(f"[{RULE}] 基线已写入 {os.path.relpath(baseline_path, args.repo_root)}：{len(current)} 条目 / {total_count(current)} 处")
        return 0
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    if not args.fail_on_new:
        print(render_text(result), flush=True)
        return 0
    try:
        baseline = load_baseline(baseline_path, expected_rule=RULE)
    except BoundaryBaselineError as exc:
        _error(str(exc))
        return 2
    comparison = compare_counts(current, baseline)
    if comparison.baseline_missing:
        _error(f"基线缺失：{baseline_path}；请先查看扫描结果并受控执行 --refresh")
        return 2
    if comparison.clean and args.quiet_when_clean:
        return 0
    for line in render_comparison(RULE, comparison):
        print(line, flush=True)
    return 1 if comparison.has_debt else 0


if __name__ == "__main__":
    raise SystemExit(main())
