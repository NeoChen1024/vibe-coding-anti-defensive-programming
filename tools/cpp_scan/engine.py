"""C++ 扫描调度：发现文件 → 并行 libclang 解析 → 跨文件引用分析 → 汇总命中。"""

from __future__ import annotations

import os
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
from typing import Any, Dict, List, Optional, Sequence

from tools.cpp_scan import crossref
from tools.cpp_scan.detectors import analyze_task
from tools.cpp_scan.frontend import HEADER_SUFFIXES, ParseConfig, discover, load_clang


def _run_tasks(tasks: List[tuple], jobs: int) -> List[Dict[str, Any]]:
    if jobs <= 1 or len(tasks) <= 1:
        return [analyze_task(task) for task in tasks]
    with ProcessPoolExecutor(max_workers=jobs) as pool:
        return list(pool.map(analyze_task, tasks, chunksize=2))


def scan(
    repo_root: str,
    prod_dirs: Sequence[str] = (),
    compile_db_dir: Optional[str] = None,
    jobs: Optional[int] = None,
) -> Dict[str, Any]:
    load_clang()
    repo_root = os.path.normpath(os.path.abspath(repo_root))
    roles = discover(repo_root, prod_dirs)
    headers = [p for paths in roles.values() for p in paths if p.endswith(HEADER_SUFFIXES)]
    config = ParseConfig(repo_root, headers, compile_db_dir)
    tasks = [(repo_root, path, role, config.args_for(os.path.join(repo_root, path)))
             for role in ("prod", "test") for path in roles[role]]
    facts = _run_tasks(tasks, jobs or os.cpu_count() or 1)
    prod_facts = [f for f in facts if f["role"] == "prod"]
    test_facts = [f for f in facts if f["role"] == "test"]
    tool_counts: Counter = Counter()
    for path in roles["tool"]:
        with open(os.path.join(repo_root, path), encoding="utf-8", errors="replace") as handle:
            tool_counts.update(crossref.c_identifier_counts(handle.read()))
    xlang = crossref.cross_language_words(repo_root)
    hits: List[Dict[str, Any]] = [hit for fact in prod_facts for hit in fact["hits"]]
    hits.extend(crossref.reference_hits(prod_facts, test_facts, tool_counts, xlang))
    return {
        "prod_roots": list(prod_dirs) or ["."],
        "compile_db": config.describe(),
        "file_count": len(roles["prod"]),
        "reference_file_count": len(roles["test"]) + len(roles["tool"]),
        "fatal": [{"file": f["path"], "error": f["fatal"]} for f in facts if f["fatal"]],
        "parse_errors": [
            {"file": f["path"], "count": f["error_count"], "first": f["errors"]}
            for f in facts if not f["fatal"] and f["error_count"]
        ],
        "hits": hits,
    }
