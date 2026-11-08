"""调用图的语言无关部分：扇入扇出、环 / 孤岛 / 关节点、高扇入咽喉、functions.json 载荷与产物写出。

Python（callgraph_extract.py）与 C++（callgraph_extract_cpp.py）两个提取器共用这一份口径，
保证两种语言的产物可以被 symbol_locator、死代码孤岛扫描器用同一套代码读取。纯标准库 + networkx、Py3.8。
"""
from __future__ import annotations

import json
import os
from collections import defaultdict
from typing import Any, Dict, List, Sequence, Tuple

FanCounts = Tuple[Dict[str, int], Dict[str, int], Dict[str, int], Dict[str, int]]
PAYLOAD_FIELDS = ("rel", "line", "end", "cls", "name")


def edge_key(edge: Dict[str, Any]) -> Tuple[str, str, str, bool]:
    return (str(edge["from"]), str(edge["to"]), str(edge["kind"]), bool(edge["ambiguous"]))


def write_json(out_dir: str, name: str, obj: Any) -> None:
    with open(os.path.join(out_dir, name), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(obj, fh, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        fh.write("\n")


def fan_counts(edges: List[Dict[str, Any]]) -> FanCounts:
    fan_out: Dict[str, int] = defaultdict(int)
    fan_in: Dict[str, int] = defaultdict(int)
    ambiguous_fan_out: Dict[str, int] = defaultdict(int)
    ambiguous_fan_in: Dict[str, int] = defaultdict(int)
    for edge in edges:
        if edge["ambiguous"]:
            ambiguous_fan_out[edge["from"]] += 1
            ambiguous_fan_in[edge["to"]] += 1
            continue
        fan_out[edge["from"]] += 1
        fan_in[edge["to"]] += 1
    return fan_in, fan_out, ambiguous_fan_in, ambiguous_fan_out


def _cycle_key(cycle: List[str]) -> List[str]:
    if not cycle:
        return []
    smallest = min(range(len(cycle)), key=lambda idx: cycle[idx])
    return cycle[smallest:] + cycle[:smallest]


def _bounded_cycles(nx: Any, graph: Any) -> List[List[str]]:
    cycles: List[List[str]] = []
    for cycle in nx.simple_cycles(graph):
        if 2 <= len(cycle) <= 8:
            cycles.append(_cycle_key(list(cycle)))
        if len(cycles) >= 200:
            break
    return sorted(cycles)


def _articulation_points(nx: Any, graph: Any) -> List[str]:
    undirected = graph.to_undirected()
    if not undirected.number_of_nodes():
        return []
    largest = max(nx.connected_components(undirected), key=len)
    return list(nx.articulation_points(undirected.subgraph(largest)))


def graph_metrics(out_dir: str, nodes: Sequence[str], edges: List[Dict[str, Any]]) -> Dict[str, Any]:
    """写 cycles.json / islands.json / articulation_points.json，返回 summary 里的图指标。"""
    try:
        import networkx as nx
    except ImportError as exc:
        raise RuntimeError("缺少 networkx，不能生成可信的调用图指标。") from exc

    graph = nx.DiGraph()
    total_graph = nx.DiGraph()
    graph.add_nodes_from(nodes)
    total_graph.add_nodes_from(nodes)
    graph.add_edges_from((edge["from"], edge["to"]) for edge in edges if not edge["ambiguous"])
    total_graph.add_edges_from((edge["from"], edge["to"]) for edge in edges)
    cycles = _bounded_cycles(nx, graph)
    islands = [node for node in total_graph.nodes if total_graph.in_degree(node) == 0 and total_graph.out_degree(node) == 0]
    articulation = _articulation_points(nx, graph)
    write_json(out_dir, "cycles.json", cycles)
    write_json(out_dir, "islands.json", sorted(islands))
    write_json(out_dir, "articulation_points.json", sorted(articulation))
    return {
        "node_count": graph.number_of_nodes(),
        "edge_count": graph.number_of_edges(),
        "edge_count_confident": graph.number_of_edges(),
        "edge_count_total": total_graph.number_of_edges(),
        "cycle_count": len(cycles),
        "cycle_count_semantics": "confident-edge simple cycles of length 2..8, capped at 200",
        "island_count": len(islands),
        "articulation_count": len(articulation),
    }


def high_fan_in(all_funcs: Dict[str, Dict[str, Any]], fan_in: Dict[str, int]) -> List[Dict[str, Any]]:
    rows = (
        {"func": qual, "rel": all_funcs[qual]["rel"], "line": all_funcs[qual]["line"], "fan_in": count}
        for qual, count in fan_in.items() if count >= 5
    )
    return sorted(rows, key=lambda item: (-item["fan_in"], item["rel"], item["line"], item["func"]))[:60]


def functions_payload(
    all_funcs: Dict[str, Dict[str, Any]],
    fans: FanCounts,
    extra_fields: Sequence[str] = (),
) -> Dict[str, Dict[str, Any]]:
    """functions.json：固定字段 + 扇入扇出；extra_fields 是语言特有字段（如 C++ 的 usr、exported_as），缺省不写。"""
    fan_in, fan_out, ambiguous_fan_in, ambiguous_fan_out = fans
    payload: Dict[str, Dict[str, Any]] = {}
    for qual, info in all_funcs.items():
        row = {field: info[field] for field in PAYLOAD_FIELDS}
        row.update({field: info[field] for field in extra_fields if field in info})
        row.update({
            "fan_in": fan_in.get(qual, 0) + ambiguous_fan_in.get(qual, 0),
            "fan_out": fan_out.get(qual, 0) + ambiguous_fan_out.get(qual, 0),
            "fan_in_confident": fan_in.get(qual, 0),
            "fan_out_confident": fan_out.get(qual, 0),
            "fan_in_ambiguous": ambiguous_fan_in.get(qual, 0),
            "fan_out_ambiguous": ambiguous_fan_out.get(qual, 0),
        })
        payload[qual] = row
    return payload
