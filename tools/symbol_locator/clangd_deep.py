"""C++ 符号的精确层（clangd）：调用点精确跳转（--at）与编译器级调用层级（--deep）。

对应 Python 侧的 jedi_resolver / scip_deep；只在查询 C++ 符号时 lazy 导入。
clangd 不可用、缺编译数据库或索引超时时抛 ClangdUnavailable，由 render 降级或报错。
"""
from __future__ import annotations

import os
from typing import Dict, List, Tuple

from ..cpp_scan.clangd import ClangdSession, ClangdUnavailable, name_column
from .static_index import REPO_ROOT

__all__ = ["ClangdUnavailable", "query", "resolve_at"]


def resolve_at(file_rel, line, symbol):
    # type: (str, int, str) -> List[Tuple[str, int, str]]
    """在 file_rel:line 的 symbol 处跳转定义；行里找不到 symbol 时返回空列表。"""
    column = name_column(os.path.join(REPO_ROOT, file_rel), line, symbol)
    if column is None:
        return []
    with ClangdSession(REPO_ROOT) as session:
        session.wait_for_index([file_rel])
        return [(path, row, symbol) for path, row, _col in session.definition(file_rel, line, column)]


def query(name, keys, index, direction):
    # type: (str, List[str], object, str) -> Dict
    """对每个 C++ 定义问 clangd 调用层级：callers=incomingCalls，callees=outgoingCalls（含 tests 等编译数据库内全部文件）。"""
    definitions = []
    rows = []
    with ClangdSession(REPO_ROOT) as session:
        session.wait_for_index(sorted({index.info(key)["rel"] for key in keys}))
        for key in keys:
            info = index.info(key)
            column = name_column(os.path.join(REPO_ROOT, info["rel"]), info["line"], info["name"])
            if column is None:
                continue
            definitions.append({"path": info["rel"], "line": info["line"], "display": key.split("::", 1)[-1]})
            fetch = session.incoming_calls if direction == "callers" else session.outgoing_calls
            rows.extend(fetch(info["rel"], info["line"], column))
    rows = sorted({(r["path"], r["line"], r["display"]): r for r in rows}.values(),
                  key=lambda r: (r["path"], r["line"], r["display"]))
    return {"symbol": name, "direction": direction, "engine": "clangd", "definitions": definitions, "rows": rows}
