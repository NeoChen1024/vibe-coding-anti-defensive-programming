"""把各文件的 libclang 事实合并成函数级调用图（产物结构与 Python 版 callgraph_extract 一致）。

节点：仓库内有定义的函数 / 方法 / 构造析构 / 函数模板，主键 `rel::Class::name`
（同文件重载冲突时追加参数表，如 `rel::Class::name(int, double)`）。lambda 体内的调用记在外层函数上。

边（from/to 同为主键）：
- call / constructor：被调方唯一确定，确信边。
- function_reference：函数名被取地址、当回调传递或登记进注册表（含 pybind11 `&func`），确信边。
- virtual：虚函数调用。仓库内没有任何覆写时是确信边；有覆写时，静态目标与每个覆写都画 ambiguous 边。
- dependent：模板依赖名调用（编译期才定），按名字连到仓库内 1~6 个同名定义，ambiguous。
画不出的回调（函数指针、std::function）与依赖名调用一并记入 dynamic_unresolved。
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

MAX_DEPENDENT_CANDIDATES = 6
EXTRA_FIELDS = ("lang", "usr", "exported_as")


def _param_list(sig: str) -> str:
    start = sig.find("(")
    return sig[start:] if start >= 0 else sig


def _assign_keys(defs: List[Dict[str, Any]]) -> Dict[str, str]:
    """loc -> 主键；同文件同限定名（重载）时追加参数表消歧。"""
    by_base: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for record in defs:
        by_base[f"{record['file']}::{record['qual']}"].append(record)
    keys: Dict[str, str] = {}
    for base, records in by_base.items():
        if len(records) == 1:
            keys[records[0]["loc"]] = base
            continue
        for record in records:
            key = base + _param_list(record["sig"])
            keys[record["loc"]] = key if key not in keys.values() else f"{key}@{record['line']}"
    return keys


def _descendants(classes: Iterable[Dict[str, Any]]) -> Dict[str, Set[str]]:
    children: Dict[str, Set[str]] = defaultdict(set)
    for item in classes:
        for base in item["bases"]:
            children[base].add(item["usr"])
    result: Dict[str, Set[str]] = {}
    for root in list(children):
        seen: Set[str] = set()
        stack = list(children[root])
        while stack:
            current = stack.pop()
            if current in seen:
                continue
            seen.add(current)
            stack.extend(children.get(current, ()))
        result[root] = seen
    return result


class CallGraph:
    def __init__(self, facts: List[Dict[str, Any]]):
        defs = {record["loc"]: record for fact in facts for record in fact["defs"]}
        self.defs = list(defs.values())
        self.key_by_loc = _assign_keys(self.defs)
        self.record_by_key = {self.key_by_loc[record["loc"]]: record for record in self.defs}
        self.key_by_usr: Dict[str, str] = {}
        self.keys_by_name: Dict[str, List[str]] = defaultdict(list)
        self.overrides: Dict[Tuple[str, str, str], str] = {}
        for record in self.defs:
            key = self.key_by_loc[record["loc"]]
            self.key_by_usr.setdefault(record["usr"], key)
            self.keys_by_name[record["name"]].append(key)
            if record["class_usr"]:
                self.overrides[(record["class_usr"], record["name"], record["sig"])] = key
        self.descendants = _descendants(item for fact in facts for item in fact["classes"])
        self.exports: Dict[str, Set[str]] = defaultdict(set)
        for fact in facts:
            for export in fact["exports"]:
                key = self.resolve(export)
                if key is not None:
                    self.exports[key].add(export["name"])
        self.edges: List[Dict[str, Any]] = []
        self.dynamic: Dict[str, Dict[str, Any]] = {}
        for fact in facts:
            for edge in fact["edges"]:
                self._add_edge(edge)
            for site in fact["unresolved"]:
                self._add_unresolved(site)
        self.edges = sorted({(e["from"], e["to"], e["kind"], e["ambiguous"]): e for e in self.edges}.values(),
                            key=lambda e: (e["from"], e["to"], e["kind"], e["ambiguous"]))

    def resolve(self, target: Dict[str, Any]) -> Optional[str]:
        loc = target.get("to_loc")
        if loc is not None and loc in self.key_by_loc:
            return self.key_by_loc[loc]
        return self.key_by_usr.get(target["to_usr"])

    def _append(self, source: str, target: str, kind: str, ambiguous: bool) -> None:
        self.edges.append({"from": source, "to": target, "kind": kind, "ambiguous": ambiguous})

    def _add_edge(self, edge: Dict[str, Any]) -> None:
        source = self.key_by_loc.get(edge["from"])
        if source is None:
            return
        target = self.resolve(edge)
        if edge["kind"] != "virtual":
            if target is not None:
                self._append(source, target, edge["kind"], False)
            return
        info = edge["virtual"]
        overrides = sorted({
            self.overrides[(cls, info["name"], info["sig"])]
            for cls in self.descendants.get(info["class_usr"], ())
            if (cls, info["name"], info["sig"]) in self.overrides
        })
        if not overrides:
            if target is not None:
                self._append(source, target, "call", False)
            return
        for candidate in ([target] if target is not None else []) + overrides:
            self._append(source, candidate, "virtual", True)

    def _add_unresolved(self, site: Dict[str, Any]) -> None:
        source = self.key_by_loc.get(site["from"])
        if source is None:
            return
        rel = source.split("::", 1)[0]
        entry = self.dynamic.setdefault(source, {"func": source, "rel": rel, "line": None, "hints": set()})
        entry["hints"].add(site["hint"])
        entry["line"] = site["line"] if entry["line"] is None else min(entry["line"], site["line"])
        if site["name"] is None:  # 函数指针 / std::function 回调：没有名字可连
            return
        candidates = [k for k in self.keys_by_name.get(site["name"], []) if k != source]
        if 1 <= len(candidates) <= MAX_DEPENDENT_CANDIDATES:
            for candidate in candidates:
                self._append(source, candidate, "dependent", True)

    def functions(self) -> Dict[str, Dict[str, Any]]:
        payload = {}
        for record in self.defs:
            key = self.key_by_loc[record["loc"]]
            info = {"rel": record["file"], "line": record["line"], "end": record["end"], "cls": record["cls"],
                    "name": record["name"], "lang": "cpp", "usr": record["usr"]}
            if key in self.exports:
                info["exported_as"] = sorted(self.exports[key])
            payload[key] = info
        return payload

    def dynamic_unresolved(self) -> List[Dict[str, Any]]:
        rows = [{**entry, "hints": sorted(entry["hints"])} for entry in self.dynamic.values()]
        return sorted(rows, key=lambda item: (item["rel"], item["line"], item["func"]))

    def islands(self) -> List[str]:
        touched = {edge["from"] for edge in self.edges} | {edge["to"] for edge in self.edges}
        return sorted(key for key in self.key_by_loc.values() if key not in touched)
