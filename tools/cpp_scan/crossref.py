"""跨文件引用分析：0 引用 / 仅测试引用函数，以及默认实参的伪可选 / 恒常量 / 从不传。

引用口径（与 Python 版“按名字计数”一致，宁漏报不误报）：
- 某名字的引用数 = 该名字在源码里出现的标识符 token 数 − 它作为函数声明/定义名出现的次数。
  token 计数是纯词法的，不依赖头文件能否找到，所以缺编译参数时也不会把被调函数误判成 0 引用。
- 生产 / 测试 C++ 由 libclang 计 token；tools/、scripts/ 下的 C++ 与仓库里的 Python、绑定描述
  (.pyx/.pxd/.i)、导出表 (.def/.map) 等跨语言文件用正则计词，出现即豁免（pybind/ctypes/SWIG 按名字调用）。
- 只判全仓唯一定义、名字不短于 4、且没有豁免原因（虚函数、特殊成员、导出属性、extern "C"、
  宏生成、公开头文件声明、嵌套）的函数。

默认实参分析只对“调用全部被 libclang 解析到”的函数做：名字的引用数必须恰好等于解析到的调用数，
否则（取地址当回调、模板、解析失败）跳过。
"""

from __future__ import annotations

import io
import os
import re
import tokenize
from collections import Counter, defaultdict
from typing import Any, Dict, Iterable, List, Set

from tools.cpp_scan.frontend import skip_dir

MIN_DEF_NAME_LEN = 4
XLANG_SUFFIXES = (".py", ".pyi", ".pyx", ".pxd", ".i", ".swg", ".def", ".map", ".ld", ".lds", ".js", ".ts",
                  ".json", ".txt", ".cmake", ".in", ".yaml", ".yml", ".toml", ".cfg", ".xml", ".qml", ".ui")
XLANG_MAX_BYTES = 2 * 1024 * 1024
WORD_RE = re.compile(r"[A-Za-z_]\w*")
C_TOKEN_RE = re.compile(r"//[^\n]*|/\*.*?\*/|\"(?:\\.|[^\"\\\n])*\"|'(?:\\.|[^'\\\n])*'|[A-Za-z_]\w*", re.S)
IDENT_RE = re.compile(r"[A-Za-z_]\w*\Z")
LITERAL_RE = re.compile(r"""^(-?[\d.]+[uUlLfF]*|0[xX][\da-fA-F]+[uUlL]*|true|false|nullptr|NULL|'.*'|u?8?R?".*")$""")
NULL_LIKE = frozenset({"nullptr", "NULL", "0", "std::nullopt", "nullopt", "{}"})


def c_identifier_counts(text: str) -> Counter:
    """C/C++ 文本的标识符计数：跳过注释，字符串里形如标识符的内容也算（宏、注册表按名字引用）。"""
    counts: Counter = Counter()
    for match in C_TOKEN_RE.finditer(text):
        token = match.group(0)
        if token.startswith(("//", "/*", "'")):
            continue
        if token.startswith('"'):
            if IDENT_RE.match(token[1:-1]):
                counts[token[1:-1]] += 1
            continue
        counts[token] += 1
    return counts


def python_words(text: str) -> Set[str]:
    """Python 文件里的名字与标识符形态的字符串（ctypes `lib.func`、`getattr(lib, "func")`）。"""
    words: Set[str] = set()
    try:
        for tok in tokenize.generate_tokens(io.StringIO(text).readline):
            if tok.type == tokenize.NAME:
                words.add(tok.string)
            elif tok.type == tokenize.STRING:
                words.update(WORD_RE.findall(tok.string))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        # 坏缩进/未闭合的 Python 文件：退回整文件取词，只会多豁免、不会多报。
        return set(WORD_RE.findall(text))
    return words


def cross_language_words(repo_root: str) -> Set[str]:
    words: Set[str] = set()
    for dirpath, dirnames, filenames in os.walk(repo_root):
        dirnames[:] = sorted(d for d in dirnames if not skip_dir(d))
        for filename in filenames:
            path = os.path.join(dirpath, filename)
            if not filename.endswith(XLANG_SUFFIXES) or os.path.getsize(path) > XLANG_MAX_BYTES:
                continue
            with open(path, encoding="utf-8", errors="replace") as handle:
                text = handle.read()
            words.update(python_words(text) if filename.endswith((".py", ".pyi")) else WORD_RE.findall(text))
    return words


def _net_refs(facts: Iterable[Dict[str, Any]]) -> Counter:
    tokens: Counter = Counter()
    decls: Counter = Counter()
    for fact in facts:
        tokens.update(fact["identifiers"])
        decls.update(fact["decl_sites"])
    return Counter({name: count - decls.get(name, 0) for name, count in tokens.items() if count > decls.get(name, 0)})


def reference_hits(
    prod_facts: List[Dict[str, Any]],
    test_facts: List[Dict[str, Any]],
    tool_counts: Counter,
    xlang_words: Set[str],
) -> List[Dict[str, Any]]:
    refs_prod = _net_refs(prod_facts)
    refs_test = _net_refs(test_facts)
    defs_by_name: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for fact in prod_facts:
        for definition in fact["defs"]:
            defs_by_name[definition["name"]].append(definition)
    calls_by_usr: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for fact in prod_facts + test_facts:
        for call in fact["calls"]:
            calls_by_usr[call["usr"]].append(call)
    hits: List[Dict[str, Any]] = []
    for name, sites in sorted(defs_by_name.items()):
        if len(sites) != 1 or len(name) < MIN_DEF_NAME_LEN:
            continue
        site = sites[0]
        if site["exempt"] is not None or refs_prod[name] or tool_counts[name] or name in xlang_words:
            continue
        kind = "test_only_func" if refs_test[name] else "zero_ref_func"
        hits.append({"file": site["file"], "kind": kind, "line": site["line"], "symbol": site["qual"],
                     "func": site["qual"], "test_refs": refs_test[name], "is_method": site["is_method"]})
    for name, sites in sorted(defs_by_name.items()):
        if len(sites) != 1 or sites[0]["exempt"] is not None or not sites[0]["defaults"]:
            continue
        if tool_counts[name] or name in xlang_words:
            continue
        calls = calls_by_usr.get(sites[0]["usr"], [])
        if len(calls) != refs_prod[name] + refs_test[name]:
            continue
        hits.extend(_default_param_hits(sites[0], calls))
    return hits


def _default_param_hits(site: Dict[str, Any], calls: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    prod_calls = [c for c in calls if c["role"] == "prod"]
    test_calls = [c for c in calls if c["role"] != "prod"]
    if not prod_calls:
        return []
    base = {"file": site["file"], "line": site["line"], "func": site["qual"], "prod_calls": len(prod_calls)}
    hits: List[Dict[str, Any]] = []
    for default in site["defaults"]:
        index = default["index"]
        passed = [c["args"][index] if index < len(c["args"]) else None for c in prod_calls]
        symbol = f"{site['qual']}({default['name']})"
        if all(value is None for value in passed):
            test_passes = sum(1 for c in test_calls if index < len(c["args"]) and c["args"][index] is not None)
            hits.append({**base, "kind": "param_never_passed_in_prod", "symbol": symbol, "param": default["name"],
                         "default": default["default"], "test_passes": test_passes})
            continue
        explicit = [value for value in passed if value is not None]
        if len(explicit) != len(passed):
            continue
        values = sorted(set(explicit))
        if default["null_default"] and not any(value in NULL_LIKE for value in values):
            hits.append({**base, "kind": "optional_always_passed", "symbol": symbol, "param": default["name"],
                         "values": values[:4]})
        if len(values) == 1 and LITERAL_RE.match(values[0]):
            hits.append({**base, "kind": "param_constant_everywhere", "symbol": symbol, "param": default["name"],
                         "default": default["default"], "value": values[0]})
    return hits
