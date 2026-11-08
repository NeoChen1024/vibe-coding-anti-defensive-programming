"""C++ 反过度防御扫描引擎（libclang AST + 全仓标识符计数）。

与 Python 版扫描器对称：
- detectors：单个翻译单元内的结构性信号（判空、吞异常、参数进门覆盖、枚举死 default……）。
- crossref：跨文件的 0 引用 / 仅测试引用函数，以及默认实参的伪可选 / 恒常量分析。
- engine：文件发现、并行解析与汇总，供 scan_over_defense_cpp（棘轮门禁）与
  scan_over_defense_cpp_deep（全量探针）共用同一套口径。
"""
