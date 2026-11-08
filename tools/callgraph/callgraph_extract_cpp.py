#!/usr/bin/env python3
"""C++ 函数级调用图（callgraph_extract.py 的 C++ 对应版）。

用 libclang 解析生产与工具目录下的 C++（与 Python 版一样不含 tests/），按编译器的名字查找结果画边：
直接调用、构造、取地址/回调登记是确信边；虚函数存在覆写、模板依赖名调用画 ambiguous 边；
函数指针与 std::function 回调记入 dynamic_unresolved。边的种类与消解口径见 tools/cpp_scan/callgraph.py。

产物（结构与 Python 版相同，symbol_locator 与 scan_dead_code_islands_cpp 直接读取）：
functions.json / edges.json / dynamic_unresolved.json / cycles.json / islands.json /
articulation_points.json / high_fan_in.json / summary.json。
functions.json 额外带 lang="cpp"、usr（clang 符号 ID），被 pybind11 等绑定导出的函数带 exported_as。
Python 版的敏感值数据流（dataflow_nodes / risk_dataflow）是业务项目专用规则，C++ 版不产出。

产物目录默认 <repo>/.checkup/callgraph_cpp/，可用 CHECKUP_CALLGRAPH_CPP 覆盖。
精确度取决于编译参数：请提供 compile_commands.json（见 tools/cpp_scan/frontend.py）。
"""
from __future__ import annotations

import argparse
import os
import sys
from typing import Any, Dict, List, Optional

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
for path in (HERE, REPO_ROOT):
    if path not in sys.path:
        sys.path.insert(0, path)

import callgraph_graph_metrics as _metrics  # 与 Python 提取器共用的图指标与产物写出
from tools.cpp_scan.callgraph import EXTRA_FIELDS, CallGraph
from tools.cpp_scan.engine import Facts, collect_facts

GRAPH_ROLES = ("prod", "tool")


def output_dir(repo_root: str) -> str:
    return os.path.abspath(os.environ.get("CHECKUP_CALLGRAPH_CPP") or os.path.join(repo_root, ".checkup", "callgraph_cpp"))


def build(repo_root: str, compile_db_dir: Optional[str], jobs: Optional[int], extra_roles: tuple) -> tuple:
    """解析并建图；extra_roles 让调用方顺带解析别的角色（死代码扫描要 tests 的引用）。返回 (Facts, CallGraph)。"""
    facts = collect_facts(repo_root, GRAPH_ROLES + tuple(extra_roles), (), compile_db_dir, jobs)
    if facts.parse_report()["fatal"]:
        failed = facts.parse_report()["fatal"]
        raise RuntimeError(f"libclang 无法加载 {len(failed)} 个文件，不能产出可信调用图：{failed[0]}")
    return facts, CallGraph(facts.of_role(*GRAPH_ROLES))


def write_outputs(out_dir: str, facts: Facts, graph: CallGraph) -> Dict[str, Any]:
    os.makedirs(out_dir, exist_ok=True)
    functions = graph.functions()
    edges = graph.edges
    dynamic = graph.dynamic_unresolved()
    fans = _metrics.fan_counts(edges)
    metrics = _metrics.graph_metrics(out_dir, list(functions.keys()), edges)
    high_fan_in = _metrics.high_fan_in(functions, fans[0])
    parse_errors: List[str] = [
        f"{item['file']}: {item['count']} 个解析错误，例如 {'; '.join(item['first'][:2])}"
        for item in facts.parse_report()["parse_errors"]
    ]
    summary = {
        "total_functions": len(functions),
        "total_edges": len(edges),
        "confident_edges": sum(1 for edge in edges if not edge["ambiguous"]),
        "ambiguous_edges": sum(1 for edge in edges if edge["ambiguous"]),
        "virtual_edges": sum(1 for edge in edges if edge["kind"] == "virtual"),
        "dynamic_unresolved_sites": len(dynamic),
        "high_fan_in_count": len(high_fan_in),
        "graph_metrics": metrics,
        "compile_db": facts.config.describe(),
        "parse_errors": parse_errors,
    }
    _metrics.write_json(out_dir, "functions.json", _metrics.functions_payload(functions, fans, EXTRA_FIELDS))
    _metrics.write_json(out_dir, "edges.json", edges)
    _metrics.write_json(out_dir, "dynamic_unresolved.json", dynamic)
    _metrics.write_json(out_dir, "high_fan_in.json", high_fan_in)
    _metrics.write_json(out_dir, "summary.json", summary)
    return summary


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="C++ 函数级调用图提取器（libclang）")
    parser.add_argument("--repo-root", default=REPO_ROOT, help="待扫描仓库根目录（默认当前仓库根）")
    parser.add_argument("--compile-commands", default=None, help="compile_commands.json 所在目录（默认自动探测）")
    parser.add_argument("--jobs", type=int, default=None, help="并行解析进程数（默认 CPU 核数）")
    args = parser.parse_args(argv)
    repo_root = os.path.abspath(args.repo_root)
    out_dir = output_dir(repo_root)
    facts, graph = build(repo_root, args.compile_commands, args.jobs, ())
    summary = write_outputs(out_dir, facts, graph)
    print("=== C++ 函数级调用图提取完成 ===")
    print(f"函数数: {summary['total_functions']}  边: {summary['total_edges']} "
          f"(确信 {summary['confident_edges']} / 模糊 {summary['ambiguous_edges']}，其中虚函数派发 {summary['virtual_edges']})")
    print(f"动态未消解: {summary['dynamic_unresolved_sites']}  编译数据库: {summary['compile_db'] or '无（退回默认参数）'}")
    print(f"图指标: {summary['graph_metrics']}")
    if summary["parse_errors"]:
        print(f"注意：{len(summary['parse_errors'])} 个文件解析有错误，相关调用可能缺边：{summary['parse_errors'][0]}")
    print("产物目录: " + out_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
