"""C++ 扫描调度：发现文件 → 并行 libclang 解析 → 跨文件引用分析 → 汇总命中。

collect_facts 是所有 C++ 工具共用的唯一解析入口（反过度防御、调用图、死代码孤岛），
每个文件只解析一次，产出纯数据事实（见 detectors.analyze_task）。
"""

from __future__ import annotations

import os
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
from typing import Any, Dict, List, NamedTuple, Optional, Sequence

from tools.cpp_scan import crossref
from tools.cpp_scan.detectors import analyze_task
from tools.cpp_scan.frontend import (
    HEADER_SUFFIXES,
    INCLUDE_RE,
    ParseConfig,
    discover,
    include_search_dirs,
    load_clang,
    rel,
    resolve_include,
)


class Facts(NamedTuple):
    repo_root: str
    roles: Dict[str, List[str]]
    config: ParseConfig
    facts: List[Dict[str, Any]]

    def of_role(self, *roles: str) -> List[Dict[str, Any]]:
        return [fact for fact in self.facts if fact["role"] in roles]

    def parse_report(self) -> Dict[str, Any]:
        return {
            "fatal": [{"file": f["path"], "error": f["fatal"]} for f in self.facts if f["fatal"]],
            "parse_errors": [
                {"file": f["path"], "count": f["error_count"], "first": f["errors"]}
                for f in self.facts if not f["fatal"] and f["error_count"]
            ],
        }


def _run_tasks(tasks: List[tuple], jobs: int) -> List[Dict[str, Any]]:
    if jobs <= 1 or len(tasks) <= 1:
        return [analyze_task(task) for task in tasks]
    with ProcessPoolExecutor(max_workers=jobs) as pool:
        return list(pool.map(analyze_task, tasks, chunksize=2))


def header_hosts(repo_root: str, roles: Dict[str, List[str]], config: ParseConfig) -> Dict[str, str]:
    """头文件 -> 一个（直接或经其他头文件间接）包含它的源文件；优先有编译命令的源文件。"""
    files = sorted((p for paths in roles.values() for p in paths),
                   key=lambda p: (os.path.normpath(os.path.join(repo_root, p)) not in config.per_file, p))
    included_by: Dict[str, str] = {}
    for path in files:
        abs_path = os.path.join(repo_root, path)
        dirs = include_search_dirs(config.args_for(abs_path))
        with open(abs_path, encoding="utf-8", errors="replace") as handle:
            text = handle.read()
        for match in INCLUDE_RE.finditer(text):
            resolved = resolve_include(abs_path, match.group(2), match.group(1) == '"', dirs)
            if resolved is not None and resolved.startswith(repo_root + os.sep) and resolved.endswith(HEADER_SUFFIXES):
                included_by.setdefault(rel(repo_root, resolved), path)
    hosts: Dict[str, str] = {}
    for header in included_by:
        current, seen = included_by[header], {header}
        while current.endswith(HEADER_SUFFIXES) and current in included_by and current not in seen:
            seen.add(current)
            current = included_by[current]
        if not current.endswith(HEADER_SUFFIXES):
            hosts[header] = current
    return hosts


def collect_facts(
    repo_root: str,
    parse_roles: Sequence[str],
    prod_dirs: Sequence[str],
    compile_db_dir: Optional[str],
    jobs: Optional[int],
) -> Facts:
    load_clang()
    repo_root = os.path.normpath(os.path.abspath(repo_root))
    roles = discover(repo_root, prod_dirs)
    headers = [p for paths in roles.values() for p in paths if p.endswith(HEADER_SUFFIXES)]
    config = ParseConfig(repo_root, headers, compile_db_dir)
    hosts = header_hosts(repo_root, roles, config)

    def host_of(path: str):
        host = hosts.get(path)
        return None if host is None else (host, config.args_for(os.path.join(repo_root, host)))

    tasks = [(repo_root, path, role, config.args_for(os.path.join(repo_root, path)), host_of(path))
             for role in parse_roles for path in roles[role]]
    return Facts(repo_root, roles, config, _run_tasks(tasks, jobs or os.cpu_count() or 1))


def tool_identifier_counts(repo_root: str, paths: Sequence[str]) -> Counter:
    counts: Counter = Counter()
    for path in paths:
        with open(os.path.join(repo_root, path), encoding="utf-8", errors="replace") as handle:
            counts.update(crossref.c_identifier_counts(handle.read()))
    return counts


def scan(
    repo_root: str,
    prod_dirs: Sequence[str],
    compile_db_dir: Optional[str],
    jobs: Optional[int],
) -> Dict[str, Any]:
    collected = collect_facts(repo_root, ("prod", "test"), prod_dirs, compile_db_dir, jobs)
    prod_facts = collected.of_role("prod")
    test_facts = collected.of_role("test")
    tool_counts = tool_identifier_counts(collected.repo_root, collected.roles["tool"])
    xlang = crossref.cross_language_words(collected.repo_root)
    hits: List[Dict[str, Any]] = [hit for fact in prod_facts for hit in fact["hits"]]
    hits.extend(crossref.reference_hits(prod_facts, test_facts, tool_counts, xlang))
    return {
        "prod_roots": list(prod_dirs) or ["."],
        "compile_db": collected.config.describe(),
        "file_count": len(collected.roles["prod"]),
        "reference_file_count": len(collected.roles["test"]) + len(collected.roles["tool"]),
        **collected.parse_report(),
        "hits": hits,
    }
