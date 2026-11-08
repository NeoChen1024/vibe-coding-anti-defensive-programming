# Vibe Coding 反防御性编程（Anti-Over-Defense & Multi-Model Pipeline Kit）

> **告别 AI 堆屎山与防御性垃圾代码**：用 **4 条第一性原理 + 15 大母题 + 140 项实战黑名单** 约束大模型，配合 **三模型多车道制衡流水线（Gemini 广撒网/首稿 ↔ Claude 核验/返修 ↔ Codex 反方/严审）** 与 **Python / C++ AST 与调用图静态猎杀工具集**，让 Vibe Coding 写出真正源头统一、零冗余兜底的生产级代码。

---

## 一、目录结构

```text
vibe-coding-anti-defensive-programming/
├── README.md                                  # 本说明文档
├── 反过度防御140项黑名单全集.md                   # 单文件完整版（4条第一性原理 + 15母题总结 + 140项实战案例全集）
├── skills/                                    # 核心工作流与方法论 Skills
│   ├── agy-dual-model-pipeline/               # 反重力三模型流水线（Gemini 广撒网/首稿 + Claude 核验/返修 + Codex 反方/严审 + 主代理裁决）
│   │   ├── SKILL.md                           # 三模型多车道并行流水线主指令
│   │   ├── references/
│   │   │   ├── blacklist.md                   # 4条第一性原理拷问 + 4×15全景速览 + A～O 15个母题主表（派发子代理必传）
│   │   │   └── blacklist-cases.md             # 140项反过度防御与冗余实战案例库（按编号按需检索）
│   │   └── scripts/
│   │       ├── codex_drive.py                 # Codex app-server WebSocket JSON-RPC 多车道驱动器
│   │       ├── codex_view.py                  # Codex 实时终端观看器（codex watch [lane]）
│   │       ├── claude_drive.py                # Claude Code tmux + hooks 多车道驱动器
│   │       └── claude_view.py                 # Claude 实时终端观看器（claude watch [lane]）
│   ├── omp-dual-model-pipeline/               # OMP 宿主双模型反转流水线（Gemini 4 Argon 分片编码 ↔ 原生 Codex 流式严审）
│   │   ├── SKILL.md
│   │   └── references/
│   │       ├── blacklist.md
│   │       └── blacklist-cases.md
│   ├── 认知一致性/                             # 《认知一致性》核心设计原则 Skill（立：源头统一，同一件事只有一条路）
│   │   ├── SKILL.md
│   │   ├── LICENSE
│   │   └── agents/openai.yaml
│   └── stop-that-shit/                        # 《Stop That Shit》执行边界、防测试膨胀与无用哈希约束 Skill
│       └── SKILL.md
└── tools/                                     # 配套的反过度防御扫描、死代码检测与调用链定位工具集
    ├── __init__.py
    ├── scan_over_defense.py                   # 1. 高精度反过度防御棘轮门禁扫描器（6大高精度信号 + 基线棘轮）
    ├── scan_over_defense_deep.py              # 2. 全量 15 母题深度探针扫描器（覆盖 20+ 种 Python AST / JS 反模式信号）
    ├── boundary_baseline.py                   # 3. 棘轮基线对比与受控刷新公共库（只减不增）
    ├── scan_private_imports.py                # 4. 跨模块私有符号导入棘轮扫描器
    ├── scan_dead_path_literals.py             # 5. 失效路径字面量棘轮扫描器（防删文件后残留死路径字符串）
    ├── scan_dead_code_islands.py              # 6. 0 调用死代码孤岛防回潮扫描器（AST 快模 + SCIP 精模）
    ├── dead_code_usage/                       # 死代码孤岛 AST / SCIP 引用分析引擎
    ├── symbol_locator/                        # 7. 函数定义与上下游调用链定位器（whereis / callers / callees）
    ├── callgraph/                             # 8. 函数级静态调用图与风险数据流提取引擎（含 C++ 版 callgraph_extract_cpp.py）
    ├── scan_over_defense_cpp.py               # 9. C++ 反过度防御棘轮门禁（9 类高精度信号，与 Python 版共用基线库）
    ├── scan_over_defense_cpp_deep.py          # 10. C++ 全量深度探针（31 类 libclang AST / 跨文件信号）
    ├── scan_dead_code_islands_cpp.py          # 11. C++ 死代码孤岛防回潮（quick 按名字 / precise 用 clangd）
    ├── scan_private_includes_cpp.py           # 12. C++ 跨组件包含私有/实现头文件棘轮
    ├── scan_dead_path_literals_cpp.py         # 13. C++ 失效路径字面量棘轮
    └── cpp_scan/                              # C++ 引擎（libclang 解析与检测、调用图建图、clangd LSP 客户端）
```

---

## 二、快速安装与接入

### 1. 安装 Skills
根据你使用的宿主环境，将 `skills/` 下的目录复制到对应配置路径：

- **Antigravity (AGY) 宿主**：
  ```bash
  mkdir -p ~/.gemini/config/skills ~/.codex/skills
  cp -r skills/agy-dual-model-pipeline ~/.gemini/config/skills/
  cp -r skills/认知一致性 skills/stop-that-shit ~/.codex/skills/
  ```
- **OMP / Codex 宿主**：
  ```bash
  mkdir -p ~/.agents/skills ~/.codex/skills
  cp -r skills/omp-dual-model-pipeline ~/.agents/skills/
  cp -r skills/认知一致性 skills/stop-that-shit ~/.codex/skills/
  ```

### 2. 配置终端实时观看别名（可选，用于 `agy-dual-model-pipeline`）
在 `~/.zshrc` 或 `~/.bashrc` 中添加辅助函数，即可在终端通过 `codex watch [lane]` / `claude watch [lane]` 实时观看各车道子代理的思考与执行过程：
```bash
codex() {
  if [ "$1" = "watch" ]; then
    shift
    python3 ~/.gemini/config/skills/agy-dual-model-pipeline/scripts/codex_view.py "$@"
  else
    command codex "$@"
  fi
}

claude() {
  if [ "$1" = "watch" ]; then
    shift
    python3 ~/.gemini/config/skills/agy-dual-model-pipeline/scripts/claude_view.py "$@"
  else
    command claude "$@"
  fi
}
```

### 3. 接入 `tools/` 扫描与定位工具集
将 `tools/` 目录复制到目标 Python 仓库根目录下（或放入 `PYTHONPATH`），并根据目标仓库的实际顶层源码目录调整 `SCAN_ROOTS` / `PROD_ROOTS`（默认已涵盖 `src`, `core`, `web`, `data`, `app`, `plugins`, `desktop` 等常见目录）。

C++ 扫描器额外依赖 libclang 的 Python 绑定（`pip install libclang`，或发行版的 `python-clang` / `python3-clang`）；
强烈建议在目标仓库生成 `compile_commands.json`（`cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON`，或 `bear -- make`），否则依赖类型的信号会因找不到头文件而漏报。

---

## 三、配套工具使用指南

### 1. 全量 15 母题深度探针扫描器（`scan_over_defense_deep.py`）
对照 140 项黑名单中的可机械识别信号，一次性扫描仓库中的 20+ 类过度防御与冗余坏味道（反射探测、宽泛 `except`、`or` 空字面量、深拷贝/往返转换、裸抛缓存异常、`_ = unused`、外部塞属性、参数进门被覆盖、未使用参数、单行透传包装、对非 Optional 参数判 `None`、默认值兜底后假必填校验、事务内做文件 I/O、0 引用函数、仅测试引用函数、伪可选恒传参、恒常量开关、纯重导出空壳模块、防御性注释与前端 JS/JSX 反模式），输出结构化 JSON 供审查：
```bash
python3 tools/scan_over_defense_deep.py --root . --out /tmp/over_defense_report
```

### 2. 高精度反过度防御棘轮门禁（`scan_over_defense.py`）
针对误报率极低的 6 类核心反模式信号（内部字面量反射、参数进门即覆盖、0 引用函数、仅测试引用函数、往外部对象塞私有属性、前端死守卫）建立**只减不增**的棘轮基线（默认存于 `.checkup/over_defense_baseline.json`）：
```bash
# 查看当前扫描统计
python3 -m tools.scan_over_defense

# 首次建立或清理债务后收紧基线（默认拒绝总数增长）
python3 -m tools.scan_over_defense --refresh

# 在 CI / pre-commit / 门禁中阻断任何新增过度防御
python3 -m tools.scan_over_defense --fail-on-new
```

### 3. 符号定义与调用链影响面定位器（`tools.symbol_locator`）
在修改函数签名、删除疑似死代码或排查跨层调用链前，秒级查询全仓定义位置、上游调用者（Callers）与下游被调函数（Callees）：
```bash
# 查定义位置（支持 --at FILE:LINE 结合 jedi 精确消歧）
python3 -m tools.symbol_locator whereis <func_name>

# 查谁调用了它（评估改动影响面 / 确认是否 0 生产调用）
python3 -m tools.symbol_locator callers <func_name>

# 查它调用了谁
python3 -m tools.symbol_locator callees <func_name>
```
*(注：首次运行或源码变更时会自动调用 `tools/callgraph/callgraph_extract.py` 重建静态调用图快照，需 Python 环境安装 `networkx`；`--at` 消歧可选依赖 `jedi`。)*

### 4. 两档调用图提取（`light` 轻量 AST 档 vs `deep` 重型 SCIP + Runtime 融合档）
针对 Python 动态与多态调用，`callgraph_extract.py`（配合 `callgraph_type_resolver.py`）提供**轻量 / 重型两档消歧能力**：
- **轻量档（`--mode light`，默认开启，0 外部依赖，秒级）**：
  基于纯标准库 AST 构建类继承表，结合函数参数/返回值类型注解、类属性注解、`__init__` 实例属性赋值（`self.repo = Cls(...)`）与局部变量构造/上下文管理器绑定，将 `obj.method()` 与 `self.attr.method()` 直接消解为 `kind="typed", ambiguous=False` 的确信实线边，并自动过滤 Python 内置容器与标准库模块调用，单档即可消除超 50% 的属性调用模糊边。
- **重型档（`--mode deep`，融合 SCIP Pyright 全量类型索引 + `sys.setprofile` 运行时录像）**：
  在轻量档基础上，自动读取 SCIP 索引（`index.scip`）与 `runtime_callgraph_collect.py` 录制的运行时调用边（`runtime_edges.json`），将命中的模糊边升级为确信实线边、剪除同调用点的未命中同名假候选，并将纯动态派发（`getattr` / 高阶回调）补入主调用图，可消除超 73% 的属性调用模糊边。

```bash
# 档次 1：轻量档（默认，秒级产出 .checkup/callgraph/）
python3 tools/callgraph/callgraph_extract.py --mode light

# 档次 2：重型档（融合 SCIP 索引 + 运行时 setprofile 真实调用边）
python3 -m tools.symbol_locator build-index                        # 可选：生成 .checkup/scip/index.scip
python3 tools/callgraph/runtime_callgraph_collect.py tests/        # 可选：录制 .checkup/callgraph_runtime/runtime_edges.json
python3 tools/callgraph/callgraph_extract.py --mode deep           # 融合产出高精度调用图

# 静态图 × 运行时边独立对账报告
python3 tools/callgraph/callgraph_crossval.py
```

### 5. 死代码孤岛、跨模块私有导入与失效路径棘轮扫描
```bash
# 扫描 0 调用死代码孤岛（AST 快速模式 / SCIP 精确模式）
python3 -m tools.scan_dead_code_islands --mode quick

# 扫描跨模块导入单下划线私有符号（from mod import _private）
python3 -m tools.scan_private_imports --fail-on-new

# 扫描删文件后残留在源码或测试中的失效路径字符串
python3 -m tools.scan_dead_path_literals --fail-on-new
```

### 6. C++ 版反过度防御扫描（Python + C++ 混合仓库）
`tools/cpp_scan/` 用 libclang 解析 C++ AST，把 Python 版的母题信号翻译成 C++ 形态；两个入口与 Python 版**同口径、同输出结构、同一套棘轮基线库**，混合仓库可以并排跑、把两份报告一起交给审查：

| Python 版信号 | C++ 对应信号 | 母题 |
| :--- | :--- | :--- |
| 对非 Optional 参数判 `None` | `null_check_on_reference`（`&ref == nullptr`）、`null_check_on_this`、`null_check_after_new`（`new` / `make_unique` 后判空） | F / K |
| 宽泛 `except` | `silent_broad_catch`、`broad_catch`（`catch (...)` / `catch (std::exception&)`，附 reraises/empty）、`swallowed_catch` | K |
| 参数进门即被覆盖 / 未使用参数 / `_ = name` | `param_overwritten`（按值参数）、`unused_param`、`void_cast_discard`（`(void)x;`）、`unused_suppression`（`[[maybe_unused]]` 等） | A |
| 默认值兜底后假必填 / 伪可选 / 恒常量开关 | `default_null_then_required`（`T* p = nullptr` 又对 null 抛异常）、`optional_always_passed`、`param_never_passed_in_prod`、`param_constant_everywhere` | A |
| 0 引用 / 仅测试引用函数 | `zero_ref_func` / `test_only_func`（虚函数、特殊成员、`extern "C"`、导出属性、宏生成、`include/` 公开 API 豁免；Python/Cython/SWIG 里出现同名即豁免） | A / D |
| 单行透传包装 / 纯重导出空壳 | `passthrough_wrapper`、`pure_forwarding_header` | B |
| 往返转换 / 反射探测 / `or` 空字面量兜底 | `cast_roundtrip`、`string_number_roundtrip`、`json_roundtrip`；`dynamic_cast_probe`、`const_cast`；`optional_value_or` | M / F / O |
| 死分支 | `delete_null_guard`（`if (p) delete p;`）、`enum_switch_dead_default`（已覆盖全部枚举值仍留 `default:`）、`enum_switch_default` | A / O |
| 防御性注释 / `noqa` / `pragma: no cover` | `defense_wording`、`nolint`、`coverage_exclusion`（LCOV_EXCL）、`diagnostic_suppression`（`#pragma ... diagnostic ignored`） | — |

```bash
# 全量深度探针：输出 hits.json（结构同 Python 版）
python3 tools/scan_over_defense_cpp_deep.py --root . --out /tmp/over_defense_cpp_report

# 高精度棘轮门禁（前 9 类信号；基线存于 .checkup/over_defense_cpp_baseline.json，只减不增）
python3 -m tools.scan_over_defense_cpp
python3 -m tools.scan_over_defense_cpp --refresh
python3 -m tools.scan_over_defense_cpp --fail-on-new --strict-parse   # 门禁环境：解析出错也阻断
```
- **文件角色**按路径片段判断，适配 monorepo 中嵌套的子项目：任一级目录名为 `tests/test/...` 或文件名形如 `test_x.cpp`、`x_test.cc` 为测试；`tools/scripts/examples/benchmarks/...` 为工具（只计引用不报信号）；`build/`、`third_party/`、`vendor/`、`contrib/` 等整体跳过；`--prod-dirs a,b` 可收窄报信号的范围。
- **编译参数**：自动合并仓库根及一、二级子目录下 `build/`、`out/`、`cmake-build-*` 里的全部 `compile_commands.json`，也可用 `--compile-commands DIR` 指定；没有时退回 `-std=gnu++20` 并把所有 `include/` 与含头文件的目录加入 `-I`。
- **跨语言引用**：C++ 版会读取仓库里的 Python、`.pyx/.pxd`、SWIG `.i`、导出表 `.def/.map` 等，ctypes / pybind11 按名字调用的 C++ 函数不会被误判为 0 引用；反过来 Python 版的 0 引用判定也会读取仓库内 C/C++ 源码（pybind11 `.attr("func")` 等）。
- **代价**：解析时间主要花在 libclang 处理重型头文件（pybind11、nlohmann/json 等）上，按 CPU 核数并行（`--jobs N` 可调）；实测 70 个文件的混合仓库约 30～50 秒。
- **不能自洽的头文件**（缺前置 `#include`、被包在宿主的 `namespace` 里 include）单独解析会出错，引擎会改在包含它的源文件的翻译单元里分析它，避免类型丢失造成的误报。

### 7. C++ 调用图、符号定位、死代码与边界棘轮
C++ 版与 Python 版共用产物结构、基线库与图指标（`tools/callgraph/callgraph_graph_metrics.py`），精确层由 clangd 担任（对应 Python 侧的 jedi / SCIP）：

| Python 工具 | C++ 对应 | 精确层 |
| :--- | :--- | :--- |
| `callgraph/callgraph_extract.py` | `callgraph/callgraph_extract_cpp.py`：直接调用/构造/取地址回调为确信边；虚函数有覆写、模板依赖名为 ambiguous 边；函数指针与 `std::function` 记入 `dynamic_unresolved`；产物另带 `lang`、`usr` 与 pybind11 导出名 `exported_as` | libclang（编译器级名字查找） |
| `symbol_locator` | 同一个命令同时载入 Python 与 C++ 快照（C++ 快照过期自动重建）；`--lang py\|cpp` 区分同名；可按 pybind11 导出名查到 C++ 函数 | `--at`、`--deep` 对 C++ 符号走 clangd |
| `scan_dead_code_islands.py` | `scan_dead_code_islands_cpp.py`：quick 按名字找引用；precise 改用 clangd 的编译器级引用（同名重载、同名局部变量不再掩护死函数）；仍有解析错误的文件里的孤岛列为 unverified | clangd `textDocument/references` |
| `scan_private_imports.py` | `scan_private_includes_cpp.py`：跨组件 `#include` 别人的 `detail/`、`internal/`、`*_impl.h`、`*_p.h`，或伸手进别的组件的 `src/` | — |
| `scan_dead_path_literals.py` | `scan_dead_path_literals_cpp.py`：C++ 字符串（含 `R"(...)"`）里指向已删除仓库文件的路径 | — |

```bash
# C++ 调用图（产物默认 .checkup/callgraph_cpp/，CHECKUP_CALLGRAPH_CPP 可覆盖；需 networkx + libclang）
python3 tools/callgraph/callgraph_extract_cpp.py

# 符号定位：Python 与 C++ 一起查
python3 -m tools.symbol_locator whereis <函数名或 pybind 导出名> [--lang cpp]
python3 -m tools.symbol_locator callers <函数名> --deep          # C++ 符号走 clangd 调用层级（含 tests）
python3 -m tools.symbol_locator whereis <函数名> --at src/a.cpp:42

# 死代码孤岛 / 私有头文件 / 失效路径棘轮
python3 tools/scan_dead_code_islands_cpp.py --mode quick           # 或 --mode precise（clangd）
python3 -m tools.scan_private_includes_cpp --fail-on-new
python3 -m tools.scan_dead_path_literals_cpp --fail-on-new
```
- **clangd 精确层**需要 `compile_commands.json`；clangd 后台索引缓存写在项目的 `.cache/clangd/index/`（与编辑器里的 clangd 共用），首次索引大型仓库可能需要数分钟，等待上限由 `CLANGD_INDEX_TIMEOUT`（秒）控制。
- **未移植**：`runtime_callgraph_collect.py` / `callgraph_crossval.py`（依赖 Python `sys.setprofile` 运行时录像，C++ 需要插桩重新编译，不在静态工具范围内）；Python 版的敏感值数据流（`dataflow_nodes` / `risk_dataflow`）是业务项目专用规则，C++ 调用图不产出。
