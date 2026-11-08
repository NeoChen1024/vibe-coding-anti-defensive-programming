#!/usr/bin/env python3
"""C++ 全量反过度防御深度探针（scan_over_defense_deep.py 的 C++ 对应版）。

只读：用 libclang 解析 C++ 源码，结果写到 --out/hits.json（结构与 Python 版相同：
{"errors": [...], "hits": {kind: [记录...]}}），不改仓库。信号清单见 tools/cpp_scan/detectors.py
与 tools/cpp_scan/crossref.py 的模块文档；混合仓库可把两个 hits.json 一起交给审查。
"""

import argparse
import json
import os
import sys
from collections import defaultdict

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from tools.cpp_scan.engine import scan


def main():
    ap = argparse.ArgumentParser(description="C++ 全量反过度防御深度探针")
    ap.add_argument("--root", default=".", help="待扫描仓库根目录")
    ap.add_argument("--out", required=True, help="扫描结果输出目录（生成 hits.json）")
    ap.add_argument("--prod-dirs", default="", help="逗号分隔的生产代码目录（默认自动探测）")
    ap.add_argument("--compile-commands", default=None, help="compile_commands.json 所在目录（默认自动探测）")
    ap.add_argument("--jobs", type=int, default=None, help="并行解析进程数（默认 CPU 核数）")
    args = ap.parse_args()
    prod_dirs = tuple(x.strip() for x in args.prod_dirs.split(",") if x.strip())
    result = scan(os.path.abspath(args.root), prod_dirs, args.compile_commands, args.jobs)
    hits = defaultdict(list)
    for hit in result["hits"]:
        record = {key: value for key, value in hit.items() if key != "kind"}
        hits[hit["kind"]].append(record)
    errors = [f"{item['file']}: {item['error']}" for item in result["fatal"]]
    errors += [f"{item['file']}: {item['count']} 个解析错误，例如 {'; '.join(item['first'][:2])}"
               for item in result["parse_errors"]]
    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, "hits.json"), "w", encoding="utf-8") as f:
        json.dump({"prod_roots": result["prod_roots"], "compile_db": result["compile_db"], "errors": errors,
                   "hits": hits}, f, ensure_ascii=False, indent=1)
    summary = {k: len(v) for k, v in sorted(hits.items())}
    print(json.dumps({"files": result["file_count"], "compile_db": result["compile_db"],
                      "parse_errors": len(errors), "summary": summary}, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
