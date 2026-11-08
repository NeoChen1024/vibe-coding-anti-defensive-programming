"""静态调用图加载器:读 callgraph_extract 产物,建查询索引。

数据源(既有资产,不新造):
- functions.json:dict,key=``rel::qual``,value 含 rel/line/end/cls/name/fan_in/fan_out。
- edges.json:list,每条 ``{from, to, kind, ambiguous}``,from/to 同为 ``rel::qual`` 主键。
- dynamic_unresolved.json:list,每条 ``{func, rel, line, hints}``,func 为 ``rel::qual``——
  静态图画不出的动态调用点(getattr 等),用于给 callees 标"实际被调可能更多"盲区。

confident 边(ambiguous=False)与 ambiguous 边分开存:主结果只给 confident,
ambiguous 仅以计数形式作盲区提示,不灌进主结果。

混合仓库:C++ 快照(callgraph_extract_cpp 产物,默认 .checkup/callgraph_cpp/,CHECKUP_CALLGRAPH_CPP 覆盖)
存在时一并载入。C++ 函数 info 带 lang="cpp";被 pybind11 等导出的函数还能按导出名(exported_as)查到。
"""
from __future__ import annotations

import json
import os
from collections import defaultdict
from typing import Dict, List, Optional

_HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
CALLGRAPH_DIR = os.path.abspath(
    os.environ.get("CHECKUP_CALLGRAPH")
    or os.path.join(REPO_ROOT, ".checkup", "callgraph"))
FUNCTIONS_JSON = os.path.join(CALLGRAPH_DIR, "functions.json")
EDGES_JSON = os.path.join(CALLGRAPH_DIR, "edges.json")
DYNAMIC_JSON = os.path.join(CALLGRAPH_DIR, "dynamic_unresolved.json")
CPP_CALLGRAPH_DIR = os.path.abspath(
    os.environ.get("CHECKUP_CALLGRAPH_CPP")
    or os.path.join(REPO_ROOT, ".checkup", "callgraph_cpp"))
CPP_FUNCTIONS_JSON = os.path.join(CPP_CALLGRAPH_DIR, "functions.json")
LANGS = ("py", "cpp")


class StaticIndex:
    """functions.json + edges.json + dynamic_unresolved.json 的内存查询视图。"""

    def __init__(self, functions, edges, dynamic=None):
        self.functions = functions            # key(rel::qual) -> info dict
        self.edges = edges                     # list of {from,to,kind,ambiguous}
        self._by_name = defaultdict(list)      # bare name -> [key]
        self._callers = defaultdict(list)      # to(key)   -> [from key]  (confident)
        self._callees = defaultdict(list)      # from(key) -> [to key]    (confident)
        self._amb_callers = defaultdict(list)  # to(key)   -> [from key]  (ambiguous)
        self._amb_callees = defaultdict(list)  # from(key) -> [to key]    (ambiguous)
        self._dynamic = defaultdict(int)       # func(key) -> 动态调用点数
        for entry in (dynamic or []):
            self._dynamic[entry["func"]] += 1
        self._build()

    def _build(self):
        for key, info in self.functions.items():
            self._by_name[info["name"]].append(key)
            for alias in info.get("exported_as", []):
                if alias != info["name"]:
                    self._by_name[alias].append(key)
        for edge in self.edges:
            if edge.get("ambiguous"):
                self._amb_callers[edge["to"]].append(edge["from"])
                self._amb_callees[edge["from"]].append(edge["to"])
            else:
                self._callers[edge["to"]].append(edge["from"])
                self._callees[edge["from"]].append(edge["to"])

    def lookup_name(self, name, lang=None):
        # type: (str, Optional[str]) -> List[str]
        """裸名(或绑定导出名) -> 所有定义 key(同名碰撞时返回多个);lang 限定 py / cpp。"""
        keys = self._by_name.get(name, [])
        return [key for key in keys if lang is None or self.lang(key) == lang]

    def lang(self, key):
        # type: (str) -> str
        return self.functions[key].get("lang", "py")

    def all_names(self):
        # type: () -> List[str]
        return list(self._by_name.keys())

    def info(self, key):
        # type: (str) -> Optional[Dict]
        return self.functions.get(key)

    def callers_of(self, key):
        # type: (str) -> List[str]
        return list(self._callers.get(key, []))

    def callees_of(self, key):
        # type: (str) -> List[str]
        return list(self._callees.get(key, []))

    def ambiguous_callers_of(self, key):
        # type: (str) -> List[str]
        return list(self._amb_callers.get(key, []))

    def ambiguous_callees_of(self, key):
        # type: (str) -> List[str]
        return list(self._amb_callees.get(key, []))

    def dynamic_count(self, key):
        # type: (str) -> int
        """该函数内部的动态调用点数(>0 表示其 callees 可能不全)。"""
        return self._dynamic.get(key, 0)


def _read_snapshot(functions_path, edges_path, dynamic_path):
    with open(functions_path, encoding="utf-8") as fh:
        functions = json.load(fh)
    with open(edges_path, encoding="utf-8") as fh:
        edges = json.load(fh)
    dynamic = []
    if os.path.exists(dynamic_path):
        with open(dynamic_path, encoding="utf-8") as fh:
            dynamic = json.load(fh)
    return functions, edges, dynamic


def load(functions_path=None, edges_path=None, dynamic_path=None):
    # type: (Optional[str], Optional[str], Optional[str]) -> StaticIndex
    functions, edges, dynamic = _read_snapshot(
        functions_path or FUNCTIONS_JSON, edges_path or EDGES_JSON, dynamic_path or DYNAMIC_JSON)
    if os.path.exists(CPP_FUNCTIONS_JSON):
        cpp_functions, cpp_edges, cpp_dynamic = _read_snapshot(
            CPP_FUNCTIONS_JSON, os.path.join(CPP_CALLGRAPH_DIR, "edges.json"),
            os.path.join(CPP_CALLGRAPH_DIR, "dynamic_unresolved.json"))
        functions = dict(functions, **cpp_functions)
        edges = edges + cpp_edges
        dynamic = dynamic + cpp_dynamic
    return StaticIndex(functions, edges, dynamic=dynamic)
