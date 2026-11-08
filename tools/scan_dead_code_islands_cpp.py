#!/usr/bin/env python3
"""C++ 死代码孤岛防回潮扫描器（scan_dead_code_islands.py 的 C++ 对应版）。

候选：C++ 调用图（tools/callgraph/callgraph_extract_cpp.py 同一套建图）里零进零出的孤岛函数。
再用“真实使用证据”过滤误报，剩下的才是疑似死代码：

- 豁免证据（两种模式都用）：虚函数/覆写（经基类指针派发）、构造析构等特殊成员与 main、
  导出属性 / extern "C"、宏生成、include/ 公开头文件声明（对外 API）。
- 跨语言证据（两种模式都用）：仓库里的 Python、Cython、SWIG、导出表出现同名标识符（ctypes 按名字调用）。
- quick：同名标识符在生产 / 测试 / 工具 C++ 里出现（token 数减声明数 > 0）。按名字算，同名重载会互相掩护。
- precise：改用 clangd 的编译器级 textDocument/references，不再按名字匹配，所以同名重载、
  同名局部变量都不会掩护死函数。要求 clangd + compile_commands.json（见 tools/cpp_scan/clangd.py）。
- 所在文件（含借宿主源文件解析后）仍有解析错误的孤岛不判死，列为 unverified：缺边会制造假孤岛。

基线：.checkup/dead_code_islands_cpp_baseline.json；口径、退出码与 Python 版一致：
新增疑似死代码退出码 1（--warn-only 只提示），工具错误退出码 2。
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional, Sequence

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for path in (REPO_ROOT, os.path.join(REPO_ROOT, "tools", "callgraph")):
    if path not in sys.path:
        sys.path.insert(0, path)

import callgraph_extract_cpp as _extract  # 与调用图提取器同一套解析与建图
from tools.cpp_scan import crossref

RULE_NOTE = "C++ 死代码疑似项基线。候选来自 C++ 调用图孤岛,再经过真实使用证据过滤。"


def baseline_path(repo_root: str) -> str:
    return os.path.join(repo_root, ".checkup", "dead_code_islands_cpp_baseline.json")


def _quick_evidence(facts, candidates: List[str], graph) -> Dict[str, List[str]]:
    refs = crossref.net_refs(facts.of_role("prod", "test", "tool"))
    evidence: Dict[str, List[str]] = {}
    for key in candidates:
        name = graph.record_by_key[key]["name"]
        if refs[name]:
            evidence[key] = [f"name_reference:{name}x{refs[name]}"]
    return evidence


def _precise_evidence(repo_root: str, candidates: List[str], graph, compile_db_dir: Optional[str]) -> Dict[str, List[str]]:
    from tools.cpp_scan.clangd import ClangdSession, name_column

    evidence: Dict[str, List[str]] = {}
    with ClangdSession(repo_root, compile_db_dir) as session:
        session.wait_for_index(sorted({graph.record_by_key[key]["file"] for key in candidates}))
        for key in candidates:
            record = graph.record_by_key[key]
            column = name_column(os.path.join(repo_root, record["file"]), record["line"], record["name"])
            if column is None:
                continue
            outside = [
                f"{path}:{line}" for path, line, _col in session.references(record["file"], record["line"], column)
                if not (path == record["file"] and record["line"] <= line <= record["end"])
            ]
            if outside:
                evidence[key] = [f"clangd_reference:{site}" for site in outside[:5]]
    return evidence


def analyze(repo_root: str, mode: str, compile_db_dir: Optional[str], jobs: Optional[int]) -> Dict[str, Any]:
    facts, graph = _extract.build(repo_root, compile_db_dir, jobs, extra_roles=("test",))
    candidates = graph.islands()
    xlang = crossref.cross_language_words(facts.repo_root)
    broken = {fact["path"] for fact in facts.facts if fact["fatal"] or fact["error_count"]}
    unverified = sorted(key for key in candidates if graph.record_by_key[key]["file"] in broken)
    evidence: Dict[str, List[str]] = {}
    remaining = []
    for key in candidates:
        record = graph.record_by_key[key]
        if key in unverified:
            continue
        if record["exempt"] is not None or record["virtual"]:
            evidence[key] = [f"exempt:{record['exempt'] or 'virtual'}"]
        elif record["name"] in xlang:
            evidence[key] = [f"cross_language:{record['name']}"]
        else:
            remaining.append(key)
    if mode == "quick":
        evidence.update(_quick_evidence(facts, remaining, graph))
    else:
        evidence.update(_precise_evidence(facts.repo_root, remaining, graph, compile_db_dir))
    suspect_dead = sorted(set(candidates) - set(evidence) - set(unverified))
    return {
        "mode": mode,
        "candidate_count": len(candidates),
        "live_count": len(evidence),
        "suspect_dead": suspect_dead,
        "unverified": unverified,
        "evidence": evidence,
        "parse_errors": facts.parse_report()["parse_errors"],
    }


def _load_baseline(path: str) -> Optional[set]:
    if not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    return {str(item) for item in (data.get("islands") or [])}


def _write_baseline(path: str, islands: Sequence[str], mode: str) -> None:
    payload = {
        "note": RULE_NOTE + f"本基线按 {mode} 口径生成；受控更新："
                            f"python tools/scan_dead_code_islands_cpp.py --mode {mode} --refresh。",
        "schema_version": 2,
        "mode": mode,
        "count": len(islands),
        "islands": sorted(islands),
    }
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=1)
        handle.write("\n")


def _print_summary(result: Dict[str, Any]) -> None:
    print(
        "[dead-code-islands-cpp] "
        f"precision={result['mode']} candidates={result['candidate_count']} "
        f"explained={result['live_count']} suspect_dead={len(result['suspect_dead'])}"
        f" unverified={len(result['unverified'])}",
        flush=True,
    )
    if result["parse_errors"]:
        print(f"[dead-code-islands-cpp] 注意：{len(result['parse_errors'])} 个文件解析有错误，缺边可能制造假孤岛。",
              flush=True)
    if result["mode"] == "quick":
        print("[dead-code-islands-cpp] quick 模式按名字找引用;同名重载会互相掩护,精确确认用 --mode precise(clangd)。",
              flush=True)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="C++ 死代码孤岛防回潮扫描器")
    parser.add_argument("--mode", choices=("quick", "precise"), default="quick",
                        help="quick=按名字找引用;precise=clangd 编译器级引用")
    parser.add_argument("--warn-only", action="store_true", help="发现新增疑似死代码时只提示不阻断")
    parser.add_argument("--refresh", action="store_true", help="把基线重写为当前疑似死代码集")
    parser.add_argument("--quiet-when-clean", action="store_true", help="无新增孤岛时完全不输出")
    parser.add_argument("--json", action="store_true", help="输出完整结果（含每个候选的使用证据）")
    parser.add_argument("--compile-commands", default=None, help="compile_commands.json 所在目录（默认自动探测）")
    parser.add_argument("--jobs", type=int, default=None, help="并行解析进程数（默认 CPU 核数）")
    parser.add_argument("--repo-root", default=REPO_ROOT, help=argparse.SUPPRESS)
    args = parser.parse_args(list(argv) if argv is not None else None)
    repo_root = os.path.abspath(args.repo_root)
    from tools.cpp_scan.clangd import ClangdUnavailable

    try:
        result = analyze(repo_root, args.mode, args.compile_commands, args.jobs)
    except ClangdUnavailable as exc:
        print(f"[dead-code-islands-cpp] 精确模式不可用：{exc.message}", flush=True)
        for hint in exc.hints:
            print(f"  - {hint}", flush=True)
        return 2
    except RuntimeError as exc:
        print(f"[dead-code-islands-cpp] 扫描失败：{exc}", flush=True)
        return 2
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=1))
        return 0
    current = list(result["suspect_dead"])
    path = baseline_path(repo_root)
    rel = os.path.relpath(path, repo_root)
    if args.refresh:
        _print_summary(result)
        _write_baseline(path, current, args.mode)
        print(f"[dead-code-islands-cpp] 基线已刷新：{len(current)} 个疑似死代码 -> {rel}", flush=True)
        return 0
    baseline = _load_baseline(path)
    if baseline is None:
        print("[dead-code-islands-cpp] 未建立基线（先跑 `python tools/scan_dead_code_islands_cpp.py --refresh`）；本次跳过对比。",
              flush=True)
        return 0
    new_islands = sorted(set(current) - baseline)
    gone_islands = sorted(baseline - set(current))
    if args.quiet_when_clean and not new_islands:
        return 0
    _print_summary(result)
    if new_islands:
        print(f"⚠️ [dead-code-islands-cpp] 检出 {len(new_islands)} 个新增疑似死代码：", flush=True)
        for qual in new_islands:
            print(f"    + {qual}", flush=True)
        print("  处理：确认是真死代码就删；若是当前设计接受的未用入口，"
              f"跑 `python tools/scan_dead_code_islands_cpp.py --mode {args.mode} --refresh` 受控刷新基线。", flush=True)
    else:
        print(f"[dead-code-islands-cpp] 无新增疑似死代码（基线 {len(baseline)} 个）。", flush=True)
    if gone_islands:
        print(f"[dead-code-islands-cpp] {len(gone_islands)} 个基线疑似项已消失（已清理/已接线）；"
              f"可 --mode {args.mode} --refresh 收敛基线。", flush=True)
    return 1 if new_islands and not args.warn_only else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
