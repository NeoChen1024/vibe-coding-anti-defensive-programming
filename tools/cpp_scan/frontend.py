"""C++ 源码发现、角色划分与 libclang 解析参数。

角色按路径片段判断（适配 monorepo 里嵌套的子项目，如 libfoo/tests、libfoo/include）：
- 任一目录片段是 tests/test/... 或文件名形如 test_x.cpp、x_test.cc → test；
- 任一目录片段是 tools/scripts/benchmarks/examples/... → tool（只用来计引用，不报信号）；
- 其余 → prod。--prod-dirs 指定时，只有落在这些目录下的 prod 文件才报信号，其余降为 tool。
build/、third_party/、vendor/、contrib/ 等依赖与产物目录整体跳过。

解析参数来源（按优先级）：
1. compile_commands.json：--compile-commands 指定目录，否则自动收集仓库根与一、二级子目录下
   build/、out/、cmake-build-* 里的全部编译数据库并合并。源文件用自己的编译命令；
   不在库里的头文件用全库 -I/-D/-std 的并集（相对路径已按各自 directory 转成绝对路径）。
2. 无编译数据库：-xc++ -std=gnu++20，-I 仓库根、所有名为 include/ 的目录与所有含头文件的目录。

缺头文件时 libclang 仍产出 AST，只是依赖类型的信号（引用类型、枚举覆盖、调用解析）会漏报；
所以扫描结果会附带解析出错的文件数，门禁可用 --strict-parse 把它升级成阻断。
"""

from __future__ import annotations

import glob
import json
import os
import re
import shlex
import shutil
import subprocess
from typing import Dict, List, Optional, Sequence, Tuple

SOURCE_SUFFIXES = (".cpp", ".cc", ".cxx", ".c++")
HEADER_SUFFIXES = (".h", ".hh", ".hpp", ".hxx", ".h++", ".ipp", ".inl", ".tcc")
CPP_SUFFIXES = SOURCE_SUFFIXES + HEADER_SUFFIXES

TEST_DIR_NAMES = frozenset({"tests", "test", "testing", "unittests", "unit_tests", "gtest"})
TOOL_DIR_NAMES = frozenset({"tools", "scripts", "benchmarks", "bench", "examples", "example", "samples", "demo"})
TEST_FILE_PREFIXES = ("test_",)
TEST_FILE_STEMS = ("_test", "_tests", "_unittest", "Test", "Tests")
#: 公开头文件目录名：在这里声明的函数视为对外 API，不判 0 引用。
PUBLIC_HEADER_DIRS = frozenset({"include"})
SKIP_DIRS = frozenset({
    "__pycache__", "node_modules", "vendor", "third_party", "thirdparty", "3rdparty", "external", "extern",
    "deps", "contrib", ".venv", "venv", "build", "out", "dist", "tmp",
})
#: 编译命令没写 -std 时 g++ 用自己的（较新）默认标准，而 libclang 默认较旧，所以统一补一个。
FALLBACK_STD = "-std=gnu++20"
#: 编译命令里与解析无关、或会让 libclang 去写文件的参数。
_DROP_FLAGS = frozenset({"-c", "-MD", "-MMD", "-MP", "-Werror", "-fcolor-diagnostics", "-pipe"})
_DROP_FLAGS_WITH_VALUE = frozenset({"-o", "-MF", "-MT", "-MQ"})
_PATH_FLAGS = ("-I", "-isystem", "-iquote")
_SHARED_PREFIXES = ("-I", "-D", "-U", "-std=", "--std", "-isystem", "-iquote", "-f", "-m")


def rel(repo_root: str, path: str) -> str:
    return os.path.relpath(path, repo_root).replace("\\", "/")


def skip_dir(name: str) -> bool:
    return name in SKIP_DIRS or name.startswith(("cmake-build-", "."))


def iter_files(repo_root: str, suffixes: Tuple[str, ...]) -> List[str]:
    files: List[str] = []
    for dirpath, dirnames, filenames in os.walk(repo_root):
        dirnames[:] = sorted(d for d in dirnames if not skip_dir(d))
        files.extend(rel(repo_root, os.path.join(dirpath, f)) for f in filenames if f.endswith(suffixes))
    return sorted(files)


def classify(rel_path: str) -> str:
    parts = rel_path.split("/")
    stem = os.path.splitext(parts[-1])[0]
    if any(p in TEST_DIR_NAMES for p in parts[:-1]) or stem.startswith(TEST_FILE_PREFIXES) or stem.endswith(TEST_FILE_STEMS):
        return "test"
    if any(p in TOOL_DIR_NAMES for p in parts[:-1]):
        return "tool"
    return "prod"


def discover(repo_root: str, prod_dirs: Sequence[str] = ()) -> Dict[str, List[str]]:
    roles: Dict[str, List[str]] = {"prod": [], "test": [], "tool": []}
    prefixes = tuple(d.strip("/") + "/" for d in prod_dirs)
    for path in iter_files(repo_root, CPP_SUFFIXES):
        role = classify(path)
        if role == "prod" and prefixes and not path.startswith(prefixes):
            role = "tool"
        roles[role].append(path)
    return roles


INCLUDE_RE = re.compile(r'^\s*#\s*include\s*([<"])([^>"]+)[>"]', re.M)


def include_search_dirs(args: Sequence[str]) -> Dict[str, List[str]]:
    """从解析参数里取头文件搜索路径（-iquote / -I / -isystem，均已是绝对路径）。"""
    dirs: Dict[str, List[str]] = {"-iquote": [], "-I": [], "-isystem": []}
    for arg in args:
        for flag in dirs:
            if arg.startswith(flag) and len(arg) > len(flag):
                dirs[flag].append(arg[len(flag):])
                break
    return dirs


def resolve_include(includer: str, target: str, quoted: bool, dirs: Dict[str, List[str]]) -> Optional[str]:
    """按编译器顺序解析 #include：引号形式先找包含者所在目录与 -iquote，再 -I、-isystem。"""
    search = ([os.path.dirname(includer)] + dirs["-iquote"] if quoted else []) + dirs["-I"] + dirs["-isystem"]
    for directory in search:
        candidate = os.path.normpath(os.path.join(directory, target))
        if os.path.isfile(candidate):
            return candidate
    return None


def is_public_header(rel_path: str) -> bool:
    return any(p in PUBLIC_HEADER_DIRS for p in rel_path.split("/")[:-1])


def load_clang():
    """导入 clang.cindex；LIBCLANG_PATH 可指定 libclang.so 路径（pip 版 libclang 自带，无需设置）。"""
    try:
        import clang.cindex as cindex
    except ImportError as exc:
        raise SystemExit(
            "[cpp-scan] 需要 libclang 的 Python 绑定：pip install libclang，或安装发行版的 python-clang"
        ) from exc
    library = os.environ.get("LIBCLANG_PATH")
    if library and not cindex.Config.loaded:
        cindex.Config.set_library_file(library)
    return cindex


def _resource_dir() -> Optional[str]:
    """libclang 自身找不到 stddef.h 等内建头时，借用系统 clang 的 resource-dir。"""
    clang = shutil.which("clang") or shutil.which("clang++")
    if clang is None:
        return None
    proc = subprocess.run([clang, "-print-resource-dir"], capture_output=True, text=True)
    path = proc.stdout.strip()
    return path if proc.returncode == 0 and os.path.isdir(path) else None


def _clean_arguments(arguments: Sequence[str], source: str, directory: str) -> List[str]:
    """去掉编译器本身、源文件、输出/依赖文件参数，并把 -I 等相对路径转成绝对路径。"""
    cleaned: List[str] = []
    pending = iter(list(arguments)[1:])
    for arg in pending:
        if arg in _DROP_FLAGS_WITH_VALUE:
            next(pending, None)
            continue
        if arg in _DROP_FLAGS or (arg.startswith("-o") and len(arg) > 2):
            continue
        if not arg.startswith("-") and os.path.normpath(os.path.join(directory, arg)) == source:
            continue
        if arg in _PATH_FLAGS:
            value = next(pending, None)
            if value is None:
                continue
            arg = arg + value
        for flag in _PATH_FLAGS:
            if arg.startswith(flag) and len(arg) > len(flag):
                arg = flag + os.path.normpath(os.path.join(directory, arg[len(flag):]))
                break
        cleaned.append(arg)
    return cleaned


def find_compile_dbs(repo_root: str, override: Optional[str]) -> List[str]:
    if override:
        path = os.path.join(override, "compile_commands.json")
        if not os.path.isfile(path):
            raise SystemExit(f"[cpp-scan] {override} 下没有 compile_commands.json")
        return [path]
    patterns = ["compile_commands.json"]
    for depth in ("", "*/", "*/*/"):
        patterns += [f"{depth}{d}/compile_commands.json" for d in ("build", "out", "cmake-build-*")]
    found: List[str] = []
    for pattern in patterns:
        found.extend(sorted(glob.glob(os.path.join(repo_root, pattern))))
    return list(dict.fromkeys(os.path.normpath(p) for p in found))


class ParseConfig:
    """为每个文件给出 libclang 解析参数。只含字符串，可以安全地发给子进程。"""

    def __init__(self, repo_root: str, headers: Sequence[str], compile_db_dir: Optional[str] = None):
        self.repo_root = repo_root
        self.compile_dbs = find_compile_dbs(repo_root, compile_db_dir)
        self.per_file: Dict[str, List[str]] = {}
        resource = _resource_dir()
        self.base = ["-xc++", "-ferror-limit=0", "-Wno-everything"] + (["-resource-dir", resource] if resource else [])
        for path in self.compile_dbs:
            self._load_compile_db(path)
        if self.per_file:
            shared = list(dict.fromkeys(
                arg for args in self.per_file.values() for arg in args if arg.startswith(_SHARED_PREFIXES)
            ))
            has_std = any(a.startswith(("-std=", "--std")) for a in shared)
            # 不同子项目可能用不同 -std；并集里只留第一个，避免互相覆盖成意外的标准。
            stds = [a for a in shared if a.startswith(("-std=", "--std"))]
            self.fallback = ([] if has_std else [FALLBACK_STD]) + [a for a in shared if a not in stds[1:]]
        else:
            include_dirs = {repo_root}
            for header in headers:
                parts = header.split("/")
                include_dirs.add(os.path.join(repo_root, *parts[:-1]))
                for index, part in enumerate(parts[:-1]):
                    if part in PUBLIC_HEADER_DIRS:
                        include_dirs.add(os.path.join(repo_root, *parts[:index + 1]))
            self.fallback = [FALLBACK_STD] + [f"-I{path}" for path in sorted(include_dirs)]

    def _load_compile_db(self, path: str) -> None:
        with open(path, encoding="utf-8") as handle:
            entries = json.load(handle)
        for entry in entries:
            directory = entry["directory"]
            source = os.path.normpath(os.path.join(directory, entry["file"]))
            arguments = entry.get("arguments") or shlex.split(entry["command"])
            cleaned = _clean_arguments(arguments, source, directory)
            if not any(a.startswith(("-std=", "--std")) for a in cleaned):
                cleaned.insert(0, FALLBACK_STD)
            self.per_file.setdefault(source, [f"-working-directory={directory}"] + cleaned)

    def args_for(self, abs_path: str) -> List[str]:
        specific = self.per_file.get(os.path.normpath(abs_path))
        return self.base + (specific if specific is not None else self.fallback)

    def describe(self) -> Optional[List[str]]:
        return [rel(self.repo_root, p) for p in self.compile_dbs] or None
