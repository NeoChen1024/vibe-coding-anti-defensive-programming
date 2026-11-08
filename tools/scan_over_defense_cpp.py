"""C++ 反过度防御棘轮扫描器（over_defense_cpp 规则）。

与 Python 版 scan_over_defense 同口径、同基线机制（tools/boundary_baseline.py），只收误报率低的结构性信号：

- null_check_on_reference：对引用/具名对象取址后判空（`&ref == nullptr`、`if (&obj)`），结果恒定。
- null_check_on_this：`this == nullptr` / `!this`。
- null_check_after_new：`new T` / `make_unique` / `make_shared` 的结果紧接着判空（失败只会抛 bad_alloc）。
- delete_null_guard：`if (p) delete p;` / `if (p) free(p);`（可带 `p = nullptr;`），对空指针 delete/free 本就是空操作。
- param_overwritten：按值参数在被读取前就被整体赋值覆盖（引用参数写出、`*p = ...` 不算）。
- enum_switch_dead_default：枚举 switch 已覆盖全部枚举值仍保留 `default:`。
- silent_broad_catch：`catch (...)` / `catch (std::exception&)` 且处理体为空。
- zero_ref_func / test_only_func：全仓唯一定义、名字不短于 4、非虚/非特殊成员/非导出/非 extern "C"/
  非宏生成/非 include/ 公开声明的函数，生产与工具代码都没有按名字引用（仅测试引用则为后者）；
  Python、Cython、SWIG、导出表等跨语言文件里出现同名标识符即豁免。

解析：优先使用 compile_commands.json（仓库根、build/、out/，或 --compile-commands 指定），
没有时退回 -std=c++20 + 常见 include 目录。缺头文件会让依赖类型的信号漏报，
所以扫描会报告解析出错的文件数；门禁环境建议提供编译数据库，并加 --strict-parse 阻断。

用法：
    python -m tools.scan_over_defense_cpp [--json] [--fail-on-new] [--refresh [--allow-growth]]
        [--quiet-when-clean] [--strict-parse] [--compile-commands DIR] [--prod-dirs a,b] [--jobs N]
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import defaultdict
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

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
from tools.cpp_scan.engine import scan as scan_cpp

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
RULE = "over_defense_cpp"
KINDS = (
    "null_check_on_reference",
    "null_check_on_this",
    "null_check_after_new",
    "delete_null_guard",
    "param_overwritten",
    "enum_switch_dead_default",
    "silent_broad_catch",
    "zero_ref_func",
    "test_only_func",
)
BASELINE_NOTE = (
    "C++ 反过度防御棘轮基线（取址/this 判空、new 后判空、delete 前判空、参数进门覆盖、枚举死 default、"
    "静默宽泛 catch、零引用与只被测试引用的函数）：条目只减不增，刷新走 --refresh。"
)


def _entries(hits: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    grouped: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    for hit in hits:
        grouped[(hit["file"], hit["kind"])].append(hit)
    return [
        {
            "path": path,
            "kind": kind,
            "count": len(items),
            "lines": sorted(item["line"] for item in items),
            "symbols": sorted({item["symbol"] for item in items}),
        }
        for (path, kind), items in sorted(grouped.items())
    ]


def scan(repo_root: str = REPO_ROOT, prod_dirs: Sequence[str] = (), compile_db_dir: Optional[str] = None,
         jobs: Optional[int] = None) -> Dict[str, Any]:
    raw = scan_cpp(repo_root, prod_dirs, compile_db_dir, jobs)
    entries = _entries(hit for hit in raw["hits"] if hit["kind"] in KINDS)
    kind_totals = {kind: 0 for kind in KINDS}
    for entry in entries:
        kind_totals[entry["kind"]] += entry["count"]
    return {
        "rule": RULE,
        "scan_roots": raw["prod_roots"],
        "compile_db": raw["compile_db"],
        "file_count": raw["file_count"],
        "reference_file_count": raw["reference_file_count"],
        "fatal": raw["fatal"],
        "parse_errors": raw["parse_errors"],
        "kind_totals": kind_totals,
        "entries": entries,
        "total": sum(kind_totals.values()),
    }


def render_text(result: Dict[str, Any]) -> str:
    entries = list(result["entries"])
    db = ", ".join(result["compile_db"]) if result["compile_db"] else "无（退回默认参数）"
    lines = [
        f"[{RULE}] 扫描 {result['file_count']} 个 C++ 文件（编译数据库：{db}），"
        f"反过度防御信号 {result['total']} 处，涉及 {len(entries)} 个条目",
    ]
    if result["parse_errors"]:
        lines.append(f"  注意：{len(result['parse_errors'])} 个文件解析有错误（多为找不到头文件），依赖类型的信号可能漏报")
    for kind, count in result["kind_totals"].items():
        lines.append(f"  {kind:28s} {count:4d}")
    for entry in sorted(entries, key=lambda item: (-int(item["count"]), str(item["path"]), str(item["kind"])))[:15]:
        lines.append(f"  {entry['count']:3d}  {entry['path']}  [{entry['kind']}]  ({', '.join(entry['symbols'][:5])})")
    return "\n".join(lines)


def _parse_args(argv: Optional[Sequence[str]]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="C++ 反过度防御棘轮扫描器")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--fail-on-new", action="store_true", help="相对基线有新增/增加/失效条目即退出码 1；基线异常退出码 2")
    parser.add_argument("--refresh", action="store_true", help="按当前扫描结果重写基线（默认拒绝总命中数增长）")
    parser.add_argument("--allow-growth", action="store_true")
    parser.add_argument("--quiet-when-clean", action="store_true")
    parser.add_argument("--strict-parse", action="store_true", help="任一文件解析出错（如缺头文件）即退出码 2")
    parser.add_argument("--compile-commands", default=None, help="compile_commands.json 所在目录（默认自动探测）")
    parser.add_argument("--prod-dirs", default="", help="逗号分隔的生产代码目录（默认自动探测）")
    parser.add_argument("--jobs", type=int, default=None, help="并行解析进程数（默认 CPU 核数）")
    parser.add_argument("--repo-root", default=REPO_ROOT, help=argparse.SUPPRESS)
    return parser.parse_args(list(argv) if argv is not None else None)


def _error(message: str) -> None:
    print(f"[over-defense-cpp] {message}", file=sys.stderr, flush=True)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    prod_dirs = tuple(x.strip() for x in args.prod_dirs.split(",") if x.strip())
    result = scan(args.repo_root, prod_dirs, args.compile_commands, args.jobs)
    if result["fatal"]:
        _error(f"libclang 无法加载 {len(result['fatal'])} 个文件，门禁已阻断：{result['fatal'][0]}")
        return 2
    if result["parse_errors"] and args.strict_parse:
        first = result["parse_errors"][0]
        _error(f"{len(result['parse_errors'])} 个文件解析有错误（--strict-parse），例如 {first['file']}：{first['first'][:1]}")
        return 2
    current = entries_to_counts(result["entries"])
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
        write_baseline(baseline_path, rule=RULE, scan_roots=result["scan_roots"], note=BASELINE_NOTE, counts=current)
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
    if result["parse_errors"]:
        _error(f"注意：{len(result['parse_errors'])} 个文件解析有错误，依赖类型的信号可能漏报；门禁环境建议提供 compile_commands.json")
    for line in render_comparison(RULE, comparison):
        print(line, flush=True)
    return 1 if comparison.has_debt else 0


if __name__ == "__main__":
    raise SystemExit(main())
