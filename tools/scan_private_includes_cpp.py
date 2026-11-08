"""C++ 私有头文件跨模块包含扫描器（private_include_cpp 棘轮规则，scan_private_imports 的 C++ 对应版）。

Python 版禁止 `from 别的模块 import _私有名`；C++ 里同一件事是把别人的内部头文件 #include 过来。
拆分必须给共享部分起公开名字（放进 include/ 或去掉私有标记），而不是直接伸手进别人的实现目录。

口径（只扫生产 C++，按 #include 实际解析到的仓库内头文件判断，解析顺序同编译器：
引号形式先找包含者所在目录，再按 -iquote / -I / -isystem；编译参数取自 compile_commands.json 或默认参数）：
- private_header：头文件路径某一级目录是 detail/details/internal/impl/private，
  或文件名以 _p / _impl / _internal / _detail / _priv / -inl / _inl 结尾；属主是它所在组件
  （路径里最后一个 include/ 或 src/ 的上一级，如 libfoo/include/foo/detail/x.h 属于 libfoo/）；
  包含者不在属主目录之下即违规。
- foreign_src_header：头文件位于某组件的 src/ 下（属主是 src/ 的上一级组件目录，如 libfoo/），
  包含者不属于该组件——跨组件就该走对方的 include/ 公开头。仓库根的 src/ 属主是整个仓库，不会触发。
third_party/、build/ 等跳过目录里的头文件与仓库外头文件不计。每个文件按 kind 计数；基线只减不增。

用法：
    python -m tools.scan_private_includes_cpp [--json] [--fail-on-new] [--refresh [--allow-growth]]
        [--quiet-when-clean] [--compile-commands DIR] [--prod-dirs a,b]
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import defaultdict
from typing import Any, Dict, List, Optional, Sequence, Tuple

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
from tools.cpp_scan.frontend import (
    HEADER_SUFFIXES,
    INCLUDE_RE,
    ParseConfig,
    discover,
    include_search_dirs,
    rel,
    resolve_include,
    skip_dir,
)

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
RULE = "private_include_cpp"
KINDS = ("private_header", "foreign_src_header")
PRIVATE_DIRS = frozenset({"detail", "details", "internal", "impl", "private"})
PRIVATE_STEM_SUFFIXES = ("_p", "_impl", "_internal", "_detail", "_priv", "-inl", "_inl")
BASELINE_NOTE = "C++ 禁跨模块包含私有/实现头文件棘轮基线：拆文件必须给共享部分起公开名字；条目只减不增，刷新走 --refresh。"


def _component(dirs: List[str]) -> str:
    """目录片段里最后一个 include/ 或 src/ 的上一级就是组件根（libfoo/include/foo/detail → libfoo）；
    两者都没有时退回这些目录本身。"""
    for index in range(len(dirs) - 1, -1, -1):
        if dirs[index] in ("include", "src"):
            return "/".join(dirs[:index])
    return "/".join(dirs)


def ownership(header_rel: str) -> Optional[Tuple[str, str]]:
    """头文件若是某组件私有的，返回 (kind, 属主组件目录)；属主为空串表示整个仓库。"""
    parts = header_rel.split("/")
    dirs = parts[:-1]
    for index, segment in enumerate(dirs):
        if segment in PRIVATE_DIRS:
            return "private_header", _component(dirs[:index])
    if os.path.splitext(parts[-1])[0].endswith(PRIVATE_STEM_SUFFIXES):
        return "private_header", _component(dirs)
    if "src" in dirs:
        return "foreign_src_header", _component(dirs)
    return None


def _inside(path: str, owner: str) -> bool:
    return owner == "" or path.startswith(owner + "/")


def scan_file(repo_root: str, rel_path: str, dirs: Dict[str, List[str]]) -> List[Dict[str, Any]]:
    includer = os.path.join(repo_root, rel_path)
    with open(includer, encoding="utf-8", errors="replace") as handle:
        text = handle.read()
    hits: List[Dict[str, Any]] = []
    for match in INCLUDE_RE.finditer(text):
        resolved = resolve_include(includer, match.group(2), match.group(1) == '"', dirs)
        if resolved is None or not resolved.startswith(repo_root + os.sep) or not resolved.endswith(HEADER_SUFFIXES):
            continue
        header_rel = rel(repo_root, resolved)
        if any(skip_dir(part) for part in header_rel.split("/")[:-1]):
            continue
        owned = ownership(header_rel)
        if owned is not None and not _inside(rel_path, owned[1]):
            hits.append({"kind": owned[0], "line": text.count("\n", 0, match.start()) + 1, "symbol": header_rel})
    return hits


def scan(repo_root: str = REPO_ROOT, prod_dirs: Sequence[str] = (), compile_db_dir: Optional[str] = None) -> Dict[str, Any]:
    repo_root = os.path.normpath(os.path.abspath(repo_root))
    roles = discover(repo_root, prod_dirs)
    headers = [p for paths in roles.values() for p in paths if p.endswith(HEADER_SUFFIXES)]
    config = ParseConfig(repo_root, headers, compile_db_dir)
    grouped: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    for rel_path in roles["prod"]:
        dirs = include_search_dirs(config.args_for(os.path.join(repo_root, rel_path)))
        for hit in scan_file(repo_root, rel_path, dirs):
            grouped[(rel_path, str(hit["kind"]))].append(hit)
    entries = [
        {"path": path, "kind": kind, "count": len(hits), "lines": sorted(int(h["line"]) for h in hits),
         "symbols": sorted({str(h["symbol"]) for h in hits})}
        for (path, kind), hits in sorted(grouped.items())
    ]
    return {"rule": RULE, "scan_roots": list(prod_dirs) or ["."], "compile_db": config.describe(),
            "file_count": len(roles["prod"]), "entries": entries,
            "total": sum(int(entry["count"]) for entry in entries)}


def render_text(result: Dict[str, Any]) -> str:
    entries = list(result.get("entries") or [])
    lines = [f"[{RULE}] 扫描 {result['file_count']} 个 C++ 文件，跨模块包含私有头文件 {result['total']} 处，涉及 {len(entries)} 个条目"]
    for entry in sorted(entries, key=lambda item: (-int(item["count"]), str(item["path"])))[:15]:
        lines.append(f"  {entry['count']:3d}  {entry['path']}  [{entry['kind']}]  ({', '.join(entry['symbols'][:3])})")
    return "\n".join(lines)


def _parse_args(argv: Optional[Sequence[str]]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="C++ 私有头文件跨模块包含棘轮扫描器")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--fail-on-new", action="store_true", help="相对基线有新增/增加/失效条目即退出码 1；基线异常退出码 2")
    parser.add_argument("--refresh", action="store_true", help="按当前扫描结果重写基线（默认拒绝总命中数增长）")
    parser.add_argument("--allow-growth", action="store_true")
    parser.add_argument("--quiet-when-clean", action="store_true")
    parser.add_argument("--compile-commands", default=None, help="compile_commands.json 所在目录（默认自动探测）")
    parser.add_argument("--prod-dirs", default="", help="逗号分隔的生产代码目录（默认自动探测）")
    parser.add_argument("--repo-root", default=REPO_ROOT, help=argparse.SUPPRESS)
    return parser.parse_args(list(argv) if argv is not None else None)


def _error(message: str) -> None:
    print(f"[private-include-cpp] {message}", file=sys.stderr, flush=True)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    prod_dirs = tuple(x.strip() for x in args.prod_dirs.split(",") if x.strip())
    result = scan(args.repo_root, prod_dirs, args.compile_commands)
    current = entries_to_counts(list(result["entries"]))
    baseline_path = default_baseline_path(args.repo_root, RULE)
    if args.refresh:
        try:
            previous = load_baseline(baseline_path, expected_rule=RULE)
        except BoundaryBaselineError as exc:
            _error(str(exc))
            return 2
        if previous is not None and total_count(current) > total_count(previous) and not args.allow_growth:
            _error(f"刷新被拒绝：总命中数 {total_count(previous)} -> {total_count(current)} 增长；请先消除新增债务，或人工核对后加 --allow-growth")
            return 1
        write_baseline(baseline_path, rule=RULE, scan_roots=list(result["scan_roots"]), note=BASELINE_NOTE,
                       counts=current)
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
