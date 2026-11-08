"""C++ 静态分析引擎（libclang AST + clangd 精确层），所有 C++ 工具共用。

- frontend：文件发现与角色划分、compile_commands.json 处理、#include 解析。
- detectors：单个翻译单元一次遍历产出全部事实——反过度防御信号、函数定义、调用/引用边、
  类继承、pybind11 导出、标识符计数；不能自洽的头文件借包含它的源文件解析。
- engine：并行解析调度（collect_facts 是唯一解析入口）与反过度防御汇总。
- crossref：跨文件的 0 引用 / 仅测试引用函数，以及默认实参的伪可选 / 恒常量分析。
- callgraph：把事实合并成与 Python 版同结构的函数级调用图。
- clangd：最小 LSP 客户端，C++ 侧的 jedi / SCIP（--at、--deep、死代码精确模式）。
"""
