"""单个翻译单元内的 C++ 反过度防御信号（libclang AST）。

每个文件只分析位置落在它自己身上的游标（头文件单独作为主文件解析一次），
所以同一个头文件被很多 .cpp 包含也只计一次。结果是纯数据（dict/list/str），可以跨进程返回。

信号（kind）与母题对应：
- null_check_on_reference   F/K  对引用或具名对象取址后判空（`&ref == nullptr`、`if (&obj)`），恒为非空。
- null_check_on_this        F/K  `this == nullptr` / `!this`，未定义行为式的自欺防御。
- null_check_after_new      F    `new T` / `make_unique` / `make_shared` 结果紧接着判空（失败只会抛异常）。
- delete_null_guard         A    `if (p) delete p;` / `if (p) free(p);`，delete/free 空指针本就是空操作。
- param_overwritten         A    按值参数在被读取前就被整体赋值覆盖（引用/指针所指对象写出不算）。
- enum_switch_dead_default  A/O  枚举 switch 已覆盖全部枚举值仍留 `default:`（死分支，且屏蔽 -Wswitch）。
- silent_broad_catch        K    `catch (...)` / `catch (std::exception&)` 空处理体，静默吞掉一切异常。
以下只进全量探针：
- broad_catch / swallowed_catch          K  宽泛捕获（附 reraises/empty）/ 具体类型但空处理体。
- unused_param / void_cast_discard / unused_suppression   A  未用参数、`(void)x;` 骗编译器、maybe_unused 等。
- passthrough_wrapper                    B  函数体只是一个原样转发全部参数的调用。
- default_null_then_required             A  `T* p = nullptr` 默认值兜底后又对 null 抛异常/abort（伪可选）。
- const_cast / dynamic_cast_probe        F  绕开 const 契约 / 运行期类型探测。
- cast_roundtrip / string_number_roundtrip / json_roundtrip   M  往返转换。
- optional_value_or                      O  `.value_or(...)` 静默回退。
- enum_switch_default                    O  枚举 switch 未覆盖全部值时用 default 兜底。
- pure_forwarding_header                 B  只有 #include / using 的空壳转发头文件。
- defense_wording / nolint / coverage_exclusion / diagnostic_suppression   注释与编译告警压制。
"""

from __future__ import annotations

import os
import re
from collections import Counter
from typing import Any, Dict, Iterator, List, Optional, Sequence, Set, Tuple

from tools.cpp_scan.frontend import HEADER_SUFFIXES, is_public_header, load_clang, rel

DEFENSE_COMMENT_RE = re.compile(r"(兜底|防御性|以防万一|容错|保险起见|best[- ]effort|defensive|just in case|fallback)", re.I)
NOLINT_RE = re.compile(r"(NOLINT\w*|cppcheck-suppress|coverity\[)")
COVERAGE_EXCL_RE = re.compile(r"(LCOV_EXCL\w*|GCOVR_EXCL\w*)")
DIAG_PRAGMA_RE = re.compile(r"^\s*#\s*pragma\s+(?:(?:GCC|clang)\s+diagnostic\s+ignored|warning\s*\(\s*disable)")
UNUSED_MARKERS = frozenset({"maybe_unused", "Q_UNUSED", "UNUSED", "UNUSED_PARAM", "unused"})
IDENT_RE = re.compile(r"[A-Za-z_]\w*\Z")
FORWARD_LINE_RE = re.compile(
    r"^\s*(#\s*(pragma\s+once|include\b|ifndef\b|endif\b|define\s+\w+\s*$)|using\s[^;]*;|namespace\s[\w:]*\s*\{|\}\s*;?)"
)
STO_FUNCS = frozenset({"stoi", "stol", "stoll", "stoul", "stoull", "stof", "stod", "stold"})
MAKE_FUNCS = frozenset({"make_unique", "make_shared", "make_unique_for_overwrite", "make_shared_for_overwrite",
                        "allocate_shared"})
FATAL_CALLS = frozenset({"abort", "terminate", "__assert_fail", "__assert_rtn", "_assert", "exit", "quick_exit"})
RETHROW_CALLS = frozenset({"rethrow_exception", "rethrow_if_nested", "terminate", "abort"})
SNIPPET_LIMIT = 200

_cindex = None


def _ck():
    global _cindex
    if _cindex is None:
        _cindex = load_clang()
    return _cindex


class _Kinds:
    """把要用的 CursorKind 收拢到一处，避免满屏 cindex.CursorKind.X。"""

    def __init__(self, cindex):
        ck = cindex.CursorKind
        self.FUNCS = frozenset({ck.FUNCTION_DECL, ck.CXX_METHOD, ck.FUNCTION_TEMPLATE, ck.CONSTRUCTOR,
                                ck.DESTRUCTOR, ck.CONVERSION_FUNCTION})
        self.SPECIAL = frozenset({ck.CONSTRUCTOR, ck.DESTRUCTOR, ck.CONVERSION_FUNCTION})
        self.CLASSES = frozenset({ck.STRUCT_DECL, ck.CLASS_DECL, ck.UNION_DECL, ck.CLASS_TEMPLATE,
                                  ck.CLASS_TEMPLATE_PARTIAL_SPECIALIZATION})
        self.WRAPPERS = frozenset({ck.UNEXPOSED_EXPR, ck.PAREN_EXPR})
        self.EXPLICIT_CASTS = frozenset({ck.CXX_STATIC_CAST_EXPR, ck.CSTYLE_CAST_EXPR, ck.CXX_FUNCTIONAL_CAST_EXPR})
        self.NAMED_REFS = frozenset({ck.DECL_REF_EXPR, ck.MEMBER_REF_EXPR})
        self.NON_EXPR_CHILDREN = frozenset({ck.TYPE_REF, ck.NAMESPACE_REF, ck.TEMPLATE_REF, ck.UNEXPOSED_ATTR})
        self.EXPORT_ATTRS = frozenset(
            getattr(ck, name) for name in ("UNEXPOSED_ATTR", "VISIBILITY_ATTR", "DLLEXPORT_ATTR", "DLLIMPORT_ATTR",
                                           "ANNOTATE_ATTR") if hasattr(ck, name))
        self.VIRTUAL_ATTRS = frozenset({ck.CXX_OVERRIDE_ATTR, ck.CXX_FINAL_ATTR})
        self.ck = ck


class FileAnalyzer:
    def __init__(self, cindex, repo_root: str, rel_path: str, role: str, tu, text: bytes):
        self.cx = cindex
        self.k = _Kinds(cindex)
        self.ck = self.k.ck
        self.repo_root = repo_root
        self.rel_path = rel_path
        self.abs_path = os.path.normpath(os.path.join(repo_root, rel_path))
        self.role = role
        self.tu = tu
        self.text = text
        self.hits: List[Dict[str, Any]] = []
        self.decl_sites: Counter = Counter()
        self.defs: List[Dict[str, Any]] = []
        self.calls: List[Dict[str, Any]] = []
        self.identifiers: Counter = Counter()
        self._null_seen: Set[int] = set()
        self._line_offsets = [0]
        for index, byte in enumerate(text):
            if byte == 0x0A:
                self._line_offsets.append(index + 1)

    # ---------- 基础工具 ----------

    def in_main(self, cursor) -> bool:
        loc_file = cursor.location.file
        return loc_file is not None and os.path.normpath(loc_file.name) == self.abs_path

    def children(self, cursor) -> List[Any]:
        return list(cursor.get_children())

    def strip(self, cursor):
        while cursor.kind in self.k.WRAPPERS:
            kids = self.children(cursor)
            if len(kids) != 1:
                break
            cursor = kids[0]
        return cursor

    def strip_conversions(self, cursor):
        """再穿过单参构造（std::string 临时量等隐式转换）。"""
        cursor = self.strip(cursor)
        while cursor.kind == self.ck.CALL_EXPR and cursor.referenced is not None \
                and cursor.referenced.kind == self.ck.CONSTRUCTOR:
            args = [a for a in cursor.get_arguments() if a.extent.start.file is not None]
            if len(args) != 1:
                break
            cursor = self.strip(args[0])
        return cursor

    def walk(self, cursor, stop_at=frozenset()) -> Iterator[Any]:
        stack = [cursor]
        while stack:
            node = stack.pop()
            yield node
            if node is not cursor and node.kind in stop_at:
                continue
            stack.extend(reversed(self.children(node)))

    def snippet(self, cursor) -> str:
        start, end = cursor.extent.start, cursor.extent.end
        if start.file is not None and end.file is not None and start.file.name == end.file.name \
                and os.path.normpath(start.file.name) == self.abs_path and end.offset > start.offset:
            raw = self.text[start.offset:end.offset].decode("utf-8", errors="replace")
        else:
            raw = " ".join(t.spelling for t in cursor.get_tokens())
        return " ".join(raw.split())[:SNIPPET_LIMIT]

    def tokens(self, cursor) -> List[str]:
        return [t.spelling for t in cursor.get_tokens()]

    def text_of(self, cursor) -> str:
        return "".join(self.tokens(cursor))

    def first_token(self, cursor) -> str:
        for token in cursor.get_tokens():
            return token.spelling
        return ""

    def qualname(self, func) -> str:
        parent = func.semantic_parent
        if parent is not None and parent.kind in self.k.CLASSES:
            return f"{parent.spelling}::{func.spelling}"
        return func.spelling

    def hit(self, kind: str, cursor, symbol: str, func=None, **extra: Any) -> None:
        record = {"file": self.rel_path, "kind": kind, "line": cursor.location.line, "symbol": symbol,
                  "func": self.qualname(func) if func is not None else "<file>"}
        record.update(extra)
        self.hits.append(record)

    def name_token_at(self, cursor) -> bool:
        """定义处的名字确实写在源码里（不是宏拼出来的）。"""
        loc = cursor.location
        if not self.in_main(cursor):
            return False
        raw = self.text[loc.offset:loc.offset + len(cursor.spelling.encode("utf-8"))]
        return raw.decode("utf-8", errors="replace") == cursor.spelling

    def is_null_literal(self, cursor) -> bool:
        cursor = self.strip(cursor)
        if cursor.kind in (self.ck.CXX_NULL_PTR_LITERAL_EXPR, self.ck.GNU_NULL_EXPR):
            return True
        return cursor.kind == self.ck.INTEGER_LITERAL and self.tokens(cursor) == ["0"]

    def is_pointerish(self, cursor) -> bool:
        if cursor.kind == self.ck.CXX_THIS_EXPR:
            return True
        kind = cursor.type.get_canonical().kind
        return kind in (self.cx.TypeKind.POINTER, self.cx.TypeKind.MEMBERPOINTER)

    def null_test(self, cond) -> Optional[Tuple[Any, bool]]:
        """把条件识别成对某个指针的判空，返回 (被判的表达式, 是否在判“为空”)。"""
        cond = self.strip(cond)
        if cond.kind == self.ck.BINARY_OPERATOR:
            op = cond.binary_operator
            if op not in (self.cx.BinaryOperator.EQ, self.cx.BinaryOperator.NE):
                return None
            kids = self.children(cond)
            if len(kids) != 2:
                return None
            is_null = op == self.cx.BinaryOperator.EQ
            if self.is_null_literal(kids[1]):
                return self.strip(kids[0]), is_null
            if self.is_null_literal(kids[0]):
                return self.strip(kids[1]), is_null
            return None
        if cond.kind == self.ck.UNARY_OPERATOR and self.first_token(cond) == "!":
            kids = self.children(cond)
            operand = self.strip(kids[0]) if len(kids) == 1 else None
            if operand is not None and self.is_pointerish(operand):
                return operand, True
            return None
        if self.is_pointerish(cond):
            return cond, False
        return None

    def if_parts(self, node) -> Tuple[Any, Any, Any]:
        kids = [c for c in self.children(node) if c.kind not in (self.ck.DECL_STMT, self.ck.VAR_DECL)]
        cond = kids[0] if kids else None
        then = kids[1] if len(kids) > 1 else None
        orelse = kids[2] if len(kids) > 2 else None
        return cond, then, orelse

    def body_statements(self, stmt) -> List[Any]:
        return self.children(stmt) if stmt.kind == self.ck.COMPOUND_STMT else [stmt]

    # ---------- 主流程 ----------

    def run(self) -> None:
        self._scan_tokens()
        top = [c for c in self.tu.cursor.get_children() if self.in_main(c)]
        for root in top:
            self._visit_tree(root)
        if self.role == "prod":
            self._scan_lines()

    def _visit_tree(self, root) -> None:
        stack: List[Tuple[Any, Any]] = [(root, None)]
        while stack:
            node, func = stack.pop()
            loc_file = node.location.file
            if loc_file is not None and os.path.normpath(loc_file.name) != self.abs_path:
                continue
            kind = node.kind
            inner_func = func
            if kind in self.k.FUNCS:
                if node.spelling and self.name_token_at(node):
                    self.decl_sites[node.spelling] += 1
                if node.is_definition():
                    inner_func = node
                    if self.role == "prod":
                        self._function(node, func)
            elif kind == self.ck.CALL_EXPR:
                self._call(node, func)
            elif self.role == "prod":
                self._node(node, func)
            stack.extend((child, inner_func) for child in reversed(self.children(node)))

    def _node(self, node, func) -> None:
        ck = self.ck
        kind = node.kind
        if kind == ck.BINARY_OPERATOR:
            op = node.binary_operator
            if op in (self.cx.BinaryOperator.EQ, self.cx.BinaryOperator.NE):
                self._null_operand(node, func)
            elif op in (self.cx.BinaryOperator.LAnd, self.cx.BinaryOperator.LOr):
                for child in self.children(node):
                    self._null_operand(child, func)
        elif kind == ck.UNARY_OPERATOR:
            if self.first_token(node) == "!":
                self._null_operand(node, func)
        elif kind == ck.IF_STMT:
            cond, then, orelse = self.if_parts(node)
            if cond is not None:
                self._null_operand(cond, func)
                if then is not None and orelse is None:
                    self._delete_guard(node, cond, then, func)
        elif kind in (ck.WHILE_STMT, ck.CONDITIONAL_OPERATOR):
            kids = self.children(node)
            if kids:
                self._null_operand(kids[0], func)
        elif kind == ck.COMPOUND_STMT:
            self._after_new(node, func)
        elif kind == ck.SWITCH_STMT:
            self._enum_switch(node, func)
        elif kind == ck.CXX_CATCH_STMT:
            self._catch(node, func)
        elif kind == ck.CXX_CONST_CAST_EXPR:
            self.hit("const_cast", node, node.type.spelling, func, code=self.snippet(node))
        elif kind == ck.CXX_DYNAMIC_CAST_EXPR:
            self.hit("dynamic_cast_probe", node, node.type.spelling, func, code=self.snippet(node))
        elif kind in self.k.EXPLICIT_CASTS:
            self._cast(node, func)

    # ---------- 判空类 ----------

    def _null_operand(self, cond, func) -> None:
        test = self.null_test(cond)
        if test is None:
            return
        operand = test[0]
        key = operand.extent.start.offset
        if key in self._null_seen:
            return
        self._null_seen.add(key)
        if operand.kind == self.ck.CXX_THIS_EXPR:
            self.hit("null_check_on_this", cond, "this", func, code=self.snippet(cond))
            return
        if operand.kind == self.ck.UNARY_OPERATOR and self.first_token(operand) == "&":
            kids = self.children(operand)
            target = self.strip(kids[0]) if len(kids) == 1 else None
            if target is not None and target.kind in self.k.NAMED_REFS and target.referenced is not None \
                    and target.referenced.kind in (self.ck.VAR_DECL, self.ck.PARM_DECL, self.ck.FIELD_DECL):
                ref_kind = target.referenced.type.kind
                is_ref = ref_kind in (self.cx.TypeKind.LVALUEREFERENCE, self.cx.TypeKind.RVALUEREFERENCE)
                self.hit("null_check_on_reference", cond, f"&{target.spelling}", func,
                         declared_reference=is_ref, code=self.snippet(cond))

    def _nonnull_source(self, expr) -> bool:
        sources = 0
        for node in self.walk(expr, stop_at=frozenset({self.ck.CXX_NEW_EXPR, self.ck.CALL_EXPR})):
            if node.kind in (self.ck.CONDITIONAL_OPERATOR, self.ck.BINARY_OPERATOR):
                return False
            if node.kind == self.ck.CXX_NEW_EXPR:
                toks = self.tokens(node)
                start = 1 if toks[:1] == ["new"] else 2
                if "nothrow" in toks or toks[start:start + 1] == ["("]:
                    return False
                sources += 1
            elif node.kind == self.ck.CALL_EXPR and node.spelling in MAKE_FUNCS:
                sources += 1
        return sources == 1

    def _fresh_target(self, stmt) -> Optional[str]:
        if stmt.kind == self.ck.DECL_STMT:
            decls = self.children(stmt)
            if len(decls) != 1 or decls[0].kind != self.ck.VAR_DECL:
                return None
            inits = [c for c in self.children(decls[0]) if c.kind not in self.k.NON_EXPR_CHILDREN]
            if inits and self._nonnull_source(inits[-1]):
                return decls[0].spelling
            return None
        stmt = self.strip(stmt)
        if stmt.kind == self.ck.BINARY_OPERATOR and stmt.binary_operator == self.cx.BinaryOperator.Assign:
            lhs, rhs = self.children(stmt)
            if self.strip(lhs).kind in self.k.NAMED_REFS and self._nonnull_source(rhs):
                return self.text_of(lhs)
        return None

    def _after_new(self, block, func) -> None:
        stmts = self.children(block)
        for current, following in zip(stmts, stmts[1:]):
            if following.kind != self.ck.IF_STMT:
                continue
            target = self._fresh_target(current)
            if target is None:
                continue
            cond, _then, _else = self.if_parts(following)
            test = self.null_test(cond) if cond is not None else None
            if test is not None and self.text_of(test[0]) == target:
                self.hit("null_check_after_new", following, target, func, code=self.snippet(cond))

    def _delete_guard(self, node, cond, then, func) -> None:
        test = self.null_test(cond)
        if test is None or test[1]:
            return
        guarded = self.text_of(test[0])
        stmts = self.body_statements(then)
        if not 1 <= len(stmts) <= 2:
            return
        first = self.strip(stmts[0])
        released = False
        if first.kind == self.ck.CXX_DELETE_EXPR:
            kids = self.children(first)
            released = len(kids) == 1 and self.text_of(kids[0]) == guarded
        elif first.kind == self.ck.CALL_EXPR and first.spelling == "free":
            args = list(first.get_arguments())
            released = len(args) == 1 and self.text_of(args[0]) == guarded
        if not released:
            return
        if len(stmts) == 2:
            reset = self.strip(stmts[1])
            if not (reset.kind == self.ck.BINARY_OPERATOR and reset.binary_operator == self.cx.BinaryOperator.Assign):
                return
            lhs, rhs = self.children(reset)
            if self.text_of(lhs) != guarded or not self.is_null_literal(rhs):
                return
        self.hit("delete_null_guard", node, guarded, func, code=self.snippet(cond))

    # ---------- 分支 / 异常 / 转换 ----------

    def _enum_switch(self, node, func) -> None:
        kids = self.children(node)
        if len(kids) < 2:
            return
        cond, body = self.strip(kids[-2]), kids[-1]
        enum_type = cond.type.get_canonical()
        if enum_type.kind != self.cx.TypeKind.ENUM:
            return
        decl = enum_type.get_declaration()
        enumerators = {c.enum_value for c in decl.get_children() if c.kind == self.ck.ENUM_CONSTANT_DECL}
        covered: Set[int] = set()
        unresolved = False
        default_node = None
        for sub in self.walk(body, stop_at=frozenset({self.ck.SWITCH_STMT})):
            if sub.kind == self.ck.DEFAULT_STMT and default_node is None:
                default_node = sub
            elif sub.kind == self.ck.CASE_STMT:
                label = self.children(sub)
                value = self.strip(label[0]) if label else None
                if value is not None and value.kind == self.ck.DECL_REF_EXPR and value.referenced is not None \
                        and value.referenced.kind == self.ck.ENUM_CONSTANT_DECL:
                    covered.add(value.referenced.enum_value)
                else:
                    unresolved = True
        if default_node is None or not enumerators:
            return
        if not unresolved and enumerators <= covered:
            self.hit("enum_switch_dead_default", default_node, decl.spelling, func, enumerators=len(enumerators))
        else:
            self.hit("enum_switch_default", default_node, decl.spelling, func,
                     covered=len(covered & enumerators), enumerators=len(enumerators), unresolved_labels=unresolved)

    def _catch(self, node, func) -> None:
        kids = self.children(node)
        if not kids:
            return
        body = kids[-1]
        toks = self.tokens(node)
        depth, type_toks = 0, []
        for token in toks[1:]:
            if token == "(":
                depth += 1
                if depth == 1:
                    continue
            elif token == ")":
                depth -= 1
                if depth == 0:
                    break
            type_toks.append(token)
        caught = " ".join(type_toks).replace(" :: ", "::").replace(" &", "&").lstrip(": ")
        var_names = [c.spelling for c in kids if c.kind == self.ck.VAR_DECL and c.spelling]
        if var_names and type_toks and type_toks[-1] == var_names[0]:
            type_toks = type_toks[:-1]
        core = "".join(t for t in type_toks if t not in ("const", "volatile", "&", "&&")).lstrip(":")
        broad = caught == "..." or core in ("std::exception", "exception")
        empty = body.kind == self.ck.COMPOUND_STMT and not self.children(body)
        reraises = any(
            sub.kind == self.ck.CXX_THROW_EXPR or (sub.kind == self.ck.CALL_EXPR and sub.spelling in RETHROW_CALLS)
            for sub in self.walk(body)
        )
        if broad and empty:
            self.hit("silent_broad_catch", node, caught, func)
        if broad:
            self.hit("broad_catch", node, caught, func, reraises=reraises, empty=empty)
        elif empty:
            self.hit("swallowed_catch", node, caught, func)

    def _cast(self, node, func) -> None:
        exprs = [c for c in self.children(node) if c.kind not in self.k.NON_EXPR_CHILDREN]
        if not exprs:
            return
        inner = self.strip(exprs[-1])
        if node.type.kind == self.cx.TypeKind.VOID:
            if inner.kind in self.k.NAMED_REFS:
                self.hit("void_cast_discard", node, inner.spelling, func, code=self.snippet(node))
            return
        if inner.kind not in self.k.EXPLICIT_CASTS:
            return
        inner_exprs = [c for c in self.children(inner) if c.kind not in self.k.NON_EXPR_CHILDREN]
        if not inner_exprs:
            return
        origin = self.strip(inner_exprs[-1]).type.get_canonical().spelling
        outer = node.type.get_canonical().spelling
        middle = inner.type.get_canonical().spelling
        if origin == outer and middle != outer:
            self.hit("cast_roundtrip", node, f"{outer}->{middle}->{outer}", func, code=self.snippet(node))

    def _call(self, node, func) -> None:
        name = node.spelling
        ref = node.referenced
        if ref is not None and ref.kind in (self.ck.FUNCTION_DECL, self.ck.CXX_METHOD) and not name.startswith("operator"):
            self._record_call(node, ref)
        if self.role != "prod":
            return
        args = [a for a in node.get_arguments() if a.extent.start.file is not None]
        if name == "value_or":
            self.hit("optional_value_or", node, name, func, code=self.snippet(node))
        elif args and (name == "to_string" and self.strip_conversions(args[0]).spelling in STO_FUNCS
                       or name in STO_FUNCS and self.strip_conversions(args[0]).spelling == "to_string"):
            self.hit("string_number_roundtrip", node, name, func, code=self.snippet(node))
        elif args and name == "parse" and self.strip_conversions(args[0]).spelling == "dump":
            self.hit("json_roundtrip", node, name, func, code=self.snippet(node))

    def _record_call(self, node, ref) -> None:
        decl_file = ref.location.file
        if decl_file is None:
            return
        decl_path = os.path.normpath(decl_file.name)
        if not decl_path.startswith(self.repo_root + os.sep):
            return
        start, end = node.extent.start.offset, node.extent.end.offset
        args: List[Optional[str]] = []
        for arg in node.get_arguments():
            loc = arg.extent.start
            explicit = loc.file is not None and os.path.normpath(loc.file.name) == self.abs_path \
                and start <= loc.offset <= end
            args.append(self.snippet(arg) if explicit else None)
        self.calls.append({"usr": ref.get_usr(), "name": ref.spelling, "role": self.role, "args": args})

    # ---------- 函数级 ----------

    def _param_refs(self, node, param_hashes: Set[int]) -> Set[int]:
        found: Set[int] = set()
        for sub in self.walk(node):
            if sub.kind == self.ck.DECL_REF_EXPR and sub.referenced is not None and sub.referenced.hash in param_hashes:
                found.add(sub.referenced.hash)
        return found

    def _exempt_reason(self, func, nested: bool) -> Optional[str]:
        kids = self.children(func)
        name = func.spelling
        if func.kind in self.k.SPECIAL or name.startswith("operator") or name == "main":
            return "special"
        if nested:
            return "nested"
        if (func.kind == self.ck.CXX_METHOD and func.is_virtual_method()) or any(c.kind in self.k.VIRTUAL_ATTRS for c in kids):
            return "virtual"
        canonical = func.canonical
        if any(c.kind in self.k.EXPORT_ATTRS for c in list(kids) + self.children(canonical)):
            return "attribute"
        parent = func.lexical_parent
        while parent is not None and parent.kind != self.ck.TRANSLATION_UNIT:
            if parent.kind == self.ck.LINKAGE_SPEC:
                return "extern_c"
            parent = parent.lexical_parent
        if not self.name_token_at(func):
            return "macro"
        decl_file = canonical.location.file
        if decl_file is not None:
            if is_public_header(rel(self.repo_root, os.path.normpath(decl_file.name))):
                return "public_header"
        return None

    def _function(self, func, outer) -> None:
        kids = self.children(func)
        params = [c for c in kids if c.kind == self.ck.PARM_DECL]
        bodies = [c for c in kids if c.kind == self.ck.COMPOUND_STMT]
        nested = outer is not None or (func.semantic_parent is not None and func.semantic_parent.kind in self.k.FUNCS)
        exempt = self._exempt_reason(func, nested)
        defaults = []
        for index, param in enumerate(params):
            exprs = [c for c in self.children(param) if c.kind not in self.k.NON_EXPR_CHILDREN]
            if exprs:
                defaults.append({"index": index, "name": param.spelling, "default": self.snippet(exprs[-1]),
                                 "null_default": self.is_null_literal(exprs[-1])})
        self.defs.append({"file": self.rel_path, "line": func.location.line, "name": func.spelling,
                          "qual": self.qualname(func), "usr": func.get_usr(), "exempt": exempt,
                          "is_method": func.kind in (self.ck.CXX_METHOD, self.ck.CONSTRUCTOR, self.ck.DESTRUCTOR),
                          "defaults": defaults})
        if not bodies:
            return
        body = bodies[-1]
        named = [p for p in params if p.spelling]
        hashes = {p.hash: p for p in named}
        stmts = self.children(body)
        pre_body = [c for c in kids if c is not body and c.kind not in (self.ck.PARM_DECL,) and c.kind not in self.k.NON_EXPR_CHILDREN]
        pre_refs: Set[int] = set()
        for node in pre_body:
            pre_refs |= self._param_refs(node, set(hashes))
        stmt_refs = [self._param_refs(stmt, set(hashes)) for stmt in stmts]
        self._param_overwritten(func, named, stmts, stmt_refs, pre_refs)
        if exempt in ("virtual", "special") and func.spelling != "main":
            return
        self._unused_params(func, named, stmts, stmt_refs, pre_refs, exempt)
        self._passthrough(func, named, stmts, exempt)
        self._default_null_required(func, defaults, params, body)

    def _param_overwritten(self, func, named, stmts, stmt_refs, pre_refs) -> None:
        value_params = [p for p in named if p.type.kind not in
                        (self.cx.TypeKind.LVALUEREFERENCE, self.cx.TypeKind.RVALUEREFERENCE) and p.hash not in pre_refs]
        for param in value_params:
            for stmt, refs in zip(stmts, stmt_refs):
                if param.hash not in refs:
                    continue
                lhs_rhs = self._assignment_sides(stmt)
                if lhs_rhs is not None:
                    lhs, rhs = lhs_rhs
                    lhs = self.strip(lhs)
                    if lhs.kind == self.ck.DECL_REF_EXPR and lhs.referenced is not None \
                            and lhs.referenced.hash == param.hash and param.hash not in self._param_refs(rhs, {param.hash}):
                        self.hit("param_overwritten", stmt, f"{self.qualname(func)}({param.spelling})", func,
                                 param=param.spelling, code=self.snippet(stmt))
                break

    def _assignment_sides(self, stmt) -> Optional[Tuple[Any, Any]]:
        stmt = self.strip(stmt)
        if stmt.kind == self.ck.BINARY_OPERATOR and stmt.binary_operator == self.cx.BinaryOperator.Assign:
            kids = self.children(stmt)
            return (kids[0], kids[1]) if len(kids) == 2 else None
        if stmt.kind == self.ck.CALL_EXPR and stmt.spelling == "operator=":
            args = list(stmt.get_arguments())
            return (args[0], args[1]) if len(args) == 2 else None
        return None

    def _is_stub(self, stmts) -> bool:
        for stmt in stmts:
            stmt = self.strip(stmt)
            if stmt.kind in (self.ck.NULL_STMT, self.ck.CXX_THROW_EXPR):
                continue
            if stmt.kind == self.ck.RETURN_STMT and all(
                    self.strip(c).kind in (self.ck.INTEGER_LITERAL, self.ck.CXX_BOOL_LITERAL_EXPR, self.ck.STRING_LITERAL,
                                           self.ck.CXX_NULL_PTR_LITERAL_EXPR, self.ck.FLOATING_LITERAL)
                    for c in self.children(stmt)):
                continue
            return False
        return True

    def _unused_params(self, func, named, stmts, stmt_refs, pre_refs, exempt) -> None:
        if self._is_stub(stmts):
            return
        used = set(pre_refs).union(*stmt_refs) if stmt_refs else set(pre_refs)
        for param in named:
            name = param.spelling
            if param.hash in used or name.startswith("_") or "unused" in name.lower():
                continue
            if any(t in UNUSED_MARKERS for t in self.tokens(param)):
                continue
            self.hit("unused_param", param, f"{self.qualname(func)}({name})", func, param=name,
                     is_method=func.kind == self.ck.CXX_METHOD, exempt=exempt,
                     internal_linkage=func.linkage == self.cx.LinkageKind.INTERNAL)

    def _passthrough(self, func, named, stmts, exempt) -> None:
        if len(stmts) != 1:
            return
        stmt = stmts[0]
        if stmt.kind == self.ck.RETURN_STMT:
            kids = self.children(stmt)
            if len(kids) != 1:
                return
            stmt = kids[0]
        call = self.strip(stmt)
        if call.kind != self.ck.CALL_EXPR or call.spelling.startswith("operator") or call.referenced is None \
                or call.referenced.kind == self.ck.CONSTRUCTOR:
            return
        args = list(call.get_arguments())
        if len(args) != len(named) or len(named) != len([c for c in self.children(func) if c.kind == self.ck.PARM_DECL]):
            return
        forwarded = []
        for arg in args:
            arg = self.strip(arg)
            if arg.kind == self.ck.CALL_EXPR and arg.spelling in ("forward", "move"):
                inner = list(arg.get_arguments())
                arg = self.strip(inner[0]) if len(inner) == 1 else arg
            if arg.kind != self.ck.DECL_REF_EXPR or arg.referenced is None:
                return
            forwarded.append(arg.referenced.hash)
        if forwarded != [p.hash for p in named]:
            return
        callee = self.children(call)
        # `return compute(x).count();` 这类对计算结果再调成员的不是转发包装：被调方本身不能再含调用。
        if callee and any(sub.kind == self.ck.CALL_EXPR for sub in self.walk(callee[0])):
            return
        self.hit("passthrough_wrapper", func, self.qualname(func), func,
                 callee=self.snippet(callee[0]) if callee else call.spelling,
                 is_method=func.kind == self.ck.CXX_METHOD, exempt=exempt)

    def _default_null_required(self, func, defaults, params, body) -> None:
        nullable = {params[d["index"]].hash: params[d["index"]].spelling for d in defaults if d["null_default"]}
        if not nullable:
            return
        for node in self.walk(body):
            if node.kind != self.ck.IF_STMT:
                continue
            cond, then, _else = self.if_parts(node)
            test = self.null_test(cond) if cond is not None else None
            if test is None or not test[1]:
                continue
            operand = test[0]
            if operand.kind != self.ck.DECL_REF_EXPR or operand.referenced is None \
                    or operand.referenced.hash not in nullable or then is None:
                continue
            if any(sub.kind == self.ck.CXX_THROW_EXPR or (sub.kind == self.ck.CALL_EXPR and sub.spelling in FATAL_CALLS)
                   for sub in self.walk(then)):
                name = nullable[operand.referenced.hash]
                self.hit("default_null_then_required", node, f"{self.qualname(func)}({name})", func,
                         param=name, code=self.snippet(cond))

    # ---------- token 与文本 ----------

    def _scan_tokens(self) -> None:
        token_kind = self.cx.TokenKind
        prod = self.role == "prod"
        for token in self.tu.get_tokens(extent=self.tu.cursor.extent):
            loc_file = token.location.file
            if loc_file is None or os.path.normpath(loc_file.name) != self.abs_path:
                continue
            spelling = token.spelling
            if token.kind == token_kind.IDENTIFIER:
                self.identifiers[spelling] += 1
                if prod and spelling in UNUSED_MARKERS:
                    self.hits.append({"file": self.rel_path, "kind": "unused_suppression", "line": token.location.line,
                                      "symbol": spelling, "func": "<file>"})
            elif token.kind == token_kind.LITERAL and spelling.endswith('"'):
                content = spelling[spelling.find('"') + 1:-1]
                if IDENT_RE.match(content):
                    self.identifiers[content] += 1
            elif prod and token.kind == token_kind.COMMENT:
                self._comment(spelling, token.location.line)

    def _comment(self, comment: str, first_line: int) -> None:
        for offset, line in enumerate(comment.splitlines()):
            for kind, pattern in (("defense_wording", DEFENSE_COMMENT_RE), ("nolint", NOLINT_RE),
                                  ("coverage_exclusion", COVERAGE_EXCL_RE)):
                match = pattern.search(line)
                if match:
                    self.hits.append({"file": self.rel_path, "kind": kind, "line": first_line + offset,
                                      "symbol": match.group(1), "func": "<file>", "code": line.strip()[:160]})

    def _scan_lines(self) -> None:
        lines = self.text.decode("utf-8", errors="replace").splitlines()
        for number, line in enumerate(lines, 1):
            if DIAG_PRAGMA_RE.match(line):
                self.hits.append({"file": self.rel_path, "kind": "diagnostic_suppression", "line": number,
                                  "symbol": "pragma", "func": "<file>", "code": line.strip()[:160]})
        if self.rel_path.endswith(HEADER_SUFFIXES):
            self._forwarding_header(lines)

    def _forwarding_header(self, lines: Sequence[str]) -> None:
        body = re.sub(r"/\*.*?\*/", "", "\n".join(lines), flags=re.S)
        meaningful = [ln for ln in (re.sub(r"//.*", "", raw) for raw in body.splitlines()) if ln.strip()]
        includes = sum(1 for ln in meaningful if re.match(r"\s*#\s*include\b", ln))
        if includes and all(FORWARD_LINE_RE.match(ln) for ln in meaningful):
            self.hits.append({"file": self.rel_path, "kind": "pure_forwarding_header", "line": 1,
                              "symbol": os.path.basename(self.rel_path), "func": "<file>", "includes": includes})


def analyze_task(task: Tuple[str, str, str, List[str]]) -> Dict[str, Any]:
    """子进程入口：解析一个文件，返回纯数据事实。"""
    repo_root, rel_path, role, args = task
    cindex = _ck()
    abs_path = os.path.normpath(os.path.join(repo_root, rel_path))
    with open(abs_path, "rb") as handle:
        text = handle.read()
    try:
        tu = cindex.Index.create().parse(abs_path, args=args)
    except cindex.TranslationUnitLoadError as exc:
        return {"path": rel_path, "role": role, "fatal": str(exc), "errors": [], "hits": [], "decl_sites": {},
                "defs": [], "calls": [], "identifiers": {}}
    errors = [
        f"{d.location.line}: {d.spelling}" for d in tu.diagnostics
        if d.severity >= cindex.Diagnostic.Error and d.location.file is not None
    ]
    analyzer = FileAnalyzer(cindex, repo_root, rel_path, role, tu, text)
    analyzer.run()
    return {"path": rel_path, "role": role, "fatal": None, "errors": errors[:5], "error_count": len(errors),
            "hits": analyzer.hits, "decl_sites": dict(analyzer.decl_sites), "defs": analyzer.defs,
            "calls": analyzer.calls, "identifiers": dict(analyzer.identifiers)}
