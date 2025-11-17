# Unidbg Trace Viewer

> 强大的 Unidbg Trace 可视化分析工具

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://www.python.org/)
[![PyQt5](https://img.shields.io/badge/PyQt5-5.15.2%2B-green)](https://www.riverbankcomputing.com/software/pyqt/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## 📸 界面预览

![Trace Viewer Screenshot](https://github.com/user-attachments/assets/9bf97edf-e529-4b95-9a05-6f1581b13fe3)

## ✨ 核心功能

### 🔍 值流追踪

- **反向追踪**：追踪寄存器值的来源
- **前向污点分析**：追踪数据的传播路径
- **增强污点分析** 🆕：字节级内存追踪 + 污点标签系统 + 汇合点检测
- **候选选择**：精确定位多次执行中的目标事件
- **实时联动**：寄存器面板与追踪结果同步更新

### 📊 可视化分析

- **三联动视图**：函数列表 / 代码窗口 / 寄存器窗口
- **内存写入对比**：字节级差异高亮显示
- **智能跳转**：代码、函数、地址一键定位
- **语法高亮**：助记符、寄存器、立即数彩色标注

### 🎯 交互体验

- **后台处理**：解析、追踪等耗时操作不阻塞界面
- **快捷操作**：右键菜单、双击跳转、快捷键支持
- **寄存器复原**：点击代码行自动复原该时刻的寄存器状态
- **字体调节**：Ctrl+= / Ctrl+- 调整代码字体大小

## 🚀 快速开始

### 安装

```bash
# 克隆仓库
git clone https://github.com/yourusername/UnidbgTraceViewer.git
cd UnidbgTraceViewer

# 安装依赖
pip install -r requirements.txt

# 或使用 pip 安装
pip install -e .
```

### 运行

```bash
# 直接启动（会弹出文件选择对话框）
python3 -m trace_viewer.app

# 或指定trace文件
python3 -m trace_viewer.app /path/to/trace.txt

# 安装后可使用命令
trace-viewer
trace-viewer /path/to/trace.txt
```

## 📖 使用指南

### 1. 值流反向追踪

**场景**：追踪某个寄存器值的来源

**步骤**：

1. **在代码区找到目标指令**
   ```
   例如：0x12025890: strb r1, [r0]
   ```

2. **右键点击该行，选择"反向追踪寄存器值来源..."**

3. **在弹出的对话框中输入**：
   - 寄存器名：`r1`
   - 执行前的值：`0x8`（十六进制）

4. **查看候选窗口**：
   ```
   行号    时间戳         PC         指令           寄存器读取
   37556   [242]         0x12025890 strb r1, [r0]  r0=0xe4fff2b1 r1=0x8
   49298   [433]         0x12025890 strb r1, [r0]  r0=0xe4fff1a8 r1=0x8
   1162698 [628]         0x12025890 strb r1, [r0]  r0=0x122802a6 r1=0x8
   1216188 [297]         0x12025890 strb r1, [r0]  r0=0x122802a1 r1=0x8
   ```

5. **选择目标候选**：
   - 点击不同候选时，寄存器面板会实时更新
   - 根据 `r0` 等其他寄存器的值确认正确的执行
   - 双击或点击"确定"开始追踪

6. **查看追踪结果**：
   - 值流面板显示完整的追踪链路
   - 双击任意行跳转到该指令

### 2. 前向污点分析

**场景**：追踪数据如何传播

**步骤**：

1. **在值流面板输入源污点**：
   ```
   寄存器：r0,r1
   或内存：0x8000
   ```

2. **点击"污点前向分析"**

3. **查看分析结果**：
   - 传播次数统计
   - 目标命中情况
   - 详细的传播路径

4. **双击结果跳转到具体指令**

### 3. 候选选择技巧

**为什么需要候选选择？**

在循环或重复执行的代码中，同一条指令可能执行多次，但每次的寄存器值不同：

```
# 同一个 PC，但执行了 4 次，r1 都是 0x8，但 r0 不同
行 37556:   r0=0xe4fff2b1 r1=0x8  ← 可能是你要找的
行 49298:   r0=0xe4fff1a8 r1=0x8
行 1162698: r0=0x122802a6 r1=0x8
行 1216188: r0=0x122802a1 r1=0x8
```

**如何快速识别？**

- ✅ **看行号**：唯一标识
- ✅ **看时间戳**：判断执行顺序
- ✅ **看其他寄存器**：通过 `r0` 等寄存器的值区分
- ✅ **实时联动**：点击候选时，寄存器面板会显示该时刻的所有寄存器

## 🎓 Python API

### 基础使用

```python
from trace_viewer.trace_parser import TraceParser

# 解析 trace 文件
parser = TraceParser()
parser.parse_file("trace.txt")

# 访问事件
print(f"总事件数: {len(parser.events)}")
ev = parser.events[0]
print(f"PC: 0x{ev.pc:08x}, 指令: {ev.asm}")
print(f"读取寄存器: {ev.reads}")
print(f"写入寄存器: {ev.writes}")
```

### 值流分析

```python
# 查找特定寄存器值的所有出现
candidates = parser.find_value_candidates('r1', 0x8)
print(f"找到 {len(candidates)} 个 r1=0x8 的事件")

# 反向追踪
hits = parser.taint_backward(
    start_idx=37556,
    target_reg='r1',
    same_call_only=False
)
print(f"反向追踪找到 {len(hits)} 个相关事件")
```

### 前向污点分析

```python
# 基础污点分析
hits = parser.taint_forward(
    start_idx=0,
    source_regs=['r0', 'r1'],
    enable_memory_taint=True
)

# 高级污点分析（带统计）
result = parser.advanced_taint_analysis(
    start_idx=0,
    source_regs=['r0'],
    target_regs=['r5'],
    enable_memory_taint=True
)

print(f"传播次数: {result['statistics']['register_propagations']}")
print(f"到达目标: {result['target_reached']}")
```

## 🔧 高级功能

### 内存写入对比

1. 在代码区选择两行
2. 右键选择"对比内存写入"
3. 查看字节级差异高亮

### 伪 C 代码导出

1. 在代码区选择多行
2. 右键选择"导出所选代码为伪C"
3. 获得可复现的 C 代码片段

### 寄存器状态复原

- 点击任意代码行
- 寄存器面板自动显示该时刻的寄存器状态
- 使用 LRU 缓存优化性能

## 🛠️ 系统要求

- Python ≥ 3.8
- PyQt5 ≥ 5.15.2
- 支持平台：Windows / macOS / Linux

## 📊 性能特点

- ✅ 支持超大 trace 文件（百万级事件）
- ✅ 后台线程处理，界面始终流畅
- ✅ 位图优化，内存占用减少 96%
- ✅ LRU 缓存，寄存器复原快速响应

## 📚 详细文档

- **[快速入门指南](docs/QUICK_START.md)** - 5分钟快速上手基础操作
- **[污点分析教程](docs/TAINT_ANALYSIS.md)** - 双模式污点分析完整指南
- **[增强污点分析](ENHANCED_TAINT_SUMMARY.md)** 🆕 - 字节级 + 标签系统 + 汇合点检测
- **[文档索引](docs/README.md)** - 所有文档汇总与导航

## 🐛 常见问题

### Q: 为什么需要手动输入寄存器值？

A: 因为代码面板只显示汇编指令，看不到每次执行的寄存器值。手动输入可以确保追踪的准确性。

### Q: 候选窗口为什么显示多个结果？

A: 因为同一条指令可能在循环中执行多次。通过行号、时间戳和其他寄存器值来区分。

### Q: 如何知道选哪个候选？

A: 点击不同候选时，主窗口的寄存器面板会实时更新，帮助你确认是否是目标执行。

### Q: 反向追踪和前向分析有什么区别？

A: 
- **反向追踪**：从某个值开始，往前找它是怎么来的
- **前向分析**：从某个值开始，往后看它传播到哪里去了

## 📝 版本历史

### v0.3.1 (2025-10-30)
- ✨ 右键追踪改为输入对话框，支持手动指定寄存器和值
- ✨ 候选窗口显示所有寄存器值，支持实时联动
- 🐛 修复值匹配逻辑，精确查找 PC+寄存器+值
- 🎨 移除冗余的"调用#"列，界面更简洁
- 📖 文档更新和整理

### v0.3.0 (2025-10-29)
- ✨ 新增扩展 ARM32 指令支持
- 🚀 位图优化，内存占用减少 96%
- ✅ 指令覆盖率达到 98%+
- 📖 完整的测试用例和文档

### v0.2.0
- ✨ 高级污点前向分析
- 🎯 目标导向分析
- 📊 详细统计信息

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

## 📄 许可证

MIT License

## 🔗 相关项目

- [Unidbg](https://github.com/zhkl0228/unidbg) - Android/iOS 模拟器框架

---

**Made with ❤️ for reverse engineering**
