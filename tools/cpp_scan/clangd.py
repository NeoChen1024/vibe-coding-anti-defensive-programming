"""clangd 最小 LSP 客户端：C++ 侧的“精确层”（对应 Python 侧的 jedi / SCIP）。

用途：
- definition：调用点精确跳转（symbol_locator whereis --at）。
- incoming_calls / outgoing_calls：编译器级调用层级（symbol_locator callers/callees --deep）。
- references：全量引用（scan_dead_code_islands_cpp --mode precise）。

前提：clangd 在 PATH（或 CLANGD 环境变量指定），且仓库有 compile_commands.json——clangd 的
后台索引只覆盖编译数据库里的文件；没有编译数据库时跨文件查询不可信，直接报 ClangdUnavailable。
clangd 会把后台索引缓存写到编译数据库所在目录的 .cache/clangd/index/（编辑器里用 clangd 的同一份缓存），
首次建索引可能较慢，之后增量加载；等待上限由 CLANGD_INDEX_TIMEOUT（秒，默认 900）控制。
"""

from __future__ import annotations

import json
import os
import queue
import re
import shutil
import subprocess
import threading
import time
from typing import IO, Any, Dict, List, Optional, Sequence, Tuple, cast
from urllib.parse import unquote, urlparse

from tools.cpp_scan.frontend import find_compile_dbs, rel

INDEX_TOKEN = "backgroundIndexProgress"
REQUEST_TIMEOUT = 120.0
#: 打开文件后多久内没看到后台索引开始，就认为索引已是最新（从磁盘缓存加载完毕）。
INDEX_SETTLE_SECONDS = 4.0
Location = Tuple[str, int, int]


class ClangdUnavailable(Exception):
    """clangd 或编译数据库缺失、索引超时等，精确层无法给出可信答案。"""

    def __init__(self, code: str, message: str, hints: Sequence[str] = ()):
        super().__init__(message)
        self.code = code
        self.message = message
        self.hints = list(hints)


def name_column(abs_path: str, line: int, name: str) -> Optional[int]:
    """定义行里函数名的 0 基列号（优先匹配 `name(`，避免撞上同名类型）。"""
    with open(abs_path, encoding="utf-8", errors="replace") as handle:
        rows = handle.read().splitlines()
    if not 1 <= line <= len(rows):
        return None
    text = rows[line - 1]
    match = re.search(r"\b" + re.escape(name) + r"\s*\(", text) or re.search(r"\b" + re.escape(name) + r"\b", text)
    return match.start() if match else None


class ClangdSession:
    def __init__(self, repo_root: str, compile_db_dir: Optional[str] = None):
        self.repo_root = os.path.abspath(repo_root)
        executable = shutil.which(os.environ.get("CLANGD", "clangd"))
        if executable is None:
            raise ClangdUnavailable("missing_clangd", "未找到 clangd，无法做 C++ 精确查询。",
                                    ["安装 clangd（LLVM 发行包或发行版的 clang/clang-tools 包），或用 CLANGD 指定路径。"])
        if not find_compile_dbs(self.repo_root, compile_db_dir):
            raise ClangdUnavailable("missing_compile_db", "未找到 compile_commands.json，clangd 后台索引无法覆盖全仓。",
                                    ["CMake：cmake -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
                                     "Make 等其他构建：bear -- make"])
        args = [executable, "--background-index", "--log=error", "--pch-storage=memory",
                f"-j={os.cpu_count() or 1}"]
        if compile_db_dir:
            args.append(f"--compile-commands-dir={os.path.abspath(compile_db_dir)}")
        self._proc = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=subprocess.DEVNULL, cwd=self.repo_root)
        self._stdin = cast(IO[bytes], self._proc.stdin)
        self._stdout = cast(IO[bytes], self._proc.stdout)
        self._inbox: "queue.Queue[Optional[Dict[str, Any]]]" = queue.Queue()
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()
        self._next_id = 0
        self._opened: Dict[str, bool] = {}
        self._index_state: Optional[str] = None
        self._index_events = 0
        self._request("initialize", {
            "processId": os.getpid(),
            "rootUri": self._uri(self.repo_root),
            "capabilities": {
                "general": {"positionEncodings": ["utf-32"]},
                "offsetEncoding": ["utf-32"],
                "window": {"workDoneProgress": True},
                "textDocument": {"callHierarchy": {}, "references": {}, "definition": {}},
            },
        })
        self._notify("initialized", {})

    # ---------- 生命周期 ----------

    def __enter__(self) -> "ClangdSession":
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.close()

    def close(self) -> None:
        if self._proc.poll() is None:
            self._request("shutdown", None)
            self._notify("exit", None)
            try:
                self._proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._proc.kill()

    # ---------- 协议 ----------

    def _read_loop(self) -> None:
        stream = self._stdout
        while True:
            length = None
            while True:
                header = stream.readline()
                if not header:
                    self._inbox.put(None)
                    return
                header = header.strip()
                if not header:
                    break
                if header.lower().startswith(b"content-length:"):
                    length = int(header.split(b":", 1)[1])
            if length is None:
                continue
            self._inbox.put(json.loads(stream.read(length)))

    def _send(self, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self._stdin.write(b"Content-Length: %d\r\n\r\n" % len(body) + body)
        self._stdin.flush()

    def _notify(self, method: str, params: Any) -> None:
        self._send({"jsonrpc": "2.0", "method": method, "params": params})

    def _handle(self, message: Dict[str, Any]) -> None:
        method = message.get("method")
        if method is not None and "id" in message:
            # 服务器发来的请求（如 window/workDoneProgress/create）：一律应答空结果。
            self._send({"jsonrpc": "2.0", "id": message["id"], "result": None})
        elif method == "$/progress" and message["params"].get("token") == INDEX_TOKEN:
            self._index_state = message["params"]["value"].get("kind")
            self._index_events += 1

    def _next(self, deadline: float) -> Optional[Dict[str, Any]]:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        try:
            message = self._inbox.get(timeout=remaining)
        except queue.Empty:
            return None
        if message is None:
            raise ClangdUnavailable("clangd_exited", "clangd 进程意外退出。")
        return message

    def _request(self, method: str, params: Any) -> Any:
        self._next_id += 1
        request_id = self._next_id
        self._send({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
        deadline = time.monotonic() + REQUEST_TIMEOUT
        while True:
            message = self._next(deadline)
            if message is None:
                raise ClangdUnavailable("request_timeout", f"clangd 请求 {method} 超时（{REQUEST_TIMEOUT:.0f}s）。")
            if message.get("id") == request_id and "method" not in message:
                if "error" in message:
                    raise ClangdUnavailable("request_failed", f"clangd {method} 失败：{message['error'].get('message')}")
                return message.get("result")
            self._handle(message)

    # ---------- 文件与索引 ----------

    @staticmethod
    def _uri(path: str) -> str:
        from pathlib import Path

        return Path(path).as_uri()

    def _from_uri(self, uri: str) -> Tuple[Optional[str], str]:
        path = unquote(urlparse(uri).path)
        inside = path.startswith(self.repo_root + os.sep)
        return (rel(self.repo_root, path) if inside else None), path

    def open(self, rel_path: str) -> None:
        if rel_path in self._opened:
            return
        path = os.path.join(self.repo_root, rel_path)
        with open(path, encoding="utf-8", errors="replace") as handle:
            text = handle.read()
        self._notify("textDocument/didOpen", {"textDocument": {
            "uri": self._uri(path), "languageId": "cpp", "version": 1, "text": text}})
        self._opened[rel_path] = True

    def wait_for_index(self, rel_paths: List[str]) -> None:
        """打开文件触发 clangd 发现编译数据库，再等后台索引跑完（或确认无事可做）。"""
        for rel_path in rel_paths:
            self.open(rel_path)
        limit = float(os.environ.get("CLANGD_INDEX_TIMEOUT") or 900)
        hard_deadline = time.monotonic() + limit
        quiet_deadline = time.monotonic() + INDEX_SETTLE_SECONDS
        while True:
            now = time.monotonic()
            if self._index_state in (None, "end") and now >= quiet_deadline:
                return
            if now >= hard_deadline:
                raise ClangdUnavailable("index_timeout", f"clangd 后台索引 {limit:.0f}s 内未完成。",
                                        ["调大 CLANGD_INDEX_TIMEOUT 后重试；首次索引大型仓库可能需要数分钟。"])
            seen = self._index_events
            message = self._next(min(hard_deadline, now + 0.5))
            if message is not None:
                self._handle(message)
            if self._index_events != seen:
                quiet_deadline = time.monotonic() + 1.5

    def _position(self, rel_path: str, line: int, column: int) -> Dict[str, Any]:
        self.open(rel_path)
        return {"textDocument": {"uri": self._uri(os.path.join(self.repo_root, rel_path))},
                "position": {"line": line - 1, "character": column}}

    def _location(self, uri: str, range_: Dict[str, Any]) -> Location:
        rel_path, abs_path = self._from_uri(uri)
        start = range_["start"]
        return (rel_path or abs_path, start["line"] + 1, start["character"])

    # ---------- 查询 ----------

    def definition(self, rel_path: str, line: int, column: int) -> List[Location]:
        result = self._request("textDocument/definition", self._position(rel_path, line, column)) or []
        return [self._location(item["uri"], item["range"]) for item in result]

    def references(self, rel_path: str, line: int, column: int) -> List[Location]:
        params = self._position(rel_path, line, column)
        params["context"] = {"includeDeclaration": False}
        result = self._request("textDocument/references", params) or []
        return [self._location(item["uri"], item["range"]) for item in result]

    def _prepare(self, rel_path: str, line: int, column: int) -> List[Dict[str, Any]]:
        return self._request("textDocument/prepareCallHierarchy", self._position(rel_path, line, column)) or []

    def incoming_calls(self, rel_path: str, line: int, column: int) -> List[Dict[str, Any]]:
        rows = []
        for item in self._prepare(rel_path, line, column):
            for call in self._request("callHierarchy/incomingCalls", {"item": item}) or []:
                peer = call["from"]
                for span in call.get("fromRanges") or [peer["selectionRange"]]:
                    path, row, _col = self._location(peer["uri"], span)
                    rows.append({"path": path, "line": row, "display": peer.get("detail") or peer["name"]})
        return rows

    def outgoing_calls(self, rel_path: str, line: int, column: int) -> List[Dict[str, Any]]:
        rows = []
        for item in self._prepare(rel_path, line, column):
            for call in self._request("callHierarchy/outgoingCalls", {"item": item}) or []:
                peer = call["to"]
                path, row, _col = self._location(peer["uri"], peer["selectionRange"])
                rows.append({"path": path, "line": row, "display": peer.get("detail") or peer["name"]})
        return rows
