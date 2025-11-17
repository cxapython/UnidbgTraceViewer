# UnidbgTraceViewer 用户指南

> 完整的使用教程 - 从入门到精通

## 📖 目录

- [快速入门](#快速入门)
- [污点分析详解](#污点分析详解)
- [增强功能](#增强功能)
- [常见问题](#常见问题)

---

## 🚀 快速入门

### 安装

```bash
pip install -e .
```

### 启动

```bash
# 方式1：命令行工具
trace-viewer trace.txt

# 方式2：Python 模块
python -m trace_viewer.app trace.txt

# 方式3：不带参数启动
trace-viewer
```

### 基础操作

1. **浏览 Trace**
   - 函数列表：左侧显示所有函数候选
   - 代码窗口：中间显示反汇编代码
   - 寄存器窗口：右侧显示当前行的寄存器状态

2. **简单污点分析**
   - 在代码窗口找到目标指令
   - 右键 → "值流追踪"
   - 输入源污点：`r0` 或 `0x8000`
   - 点击分析按钮

3. **快捷键**
   - `Ctrl + =` 放大字体
   - `Ctrl + -` 缩小字体

---

## 🎯 污点分析详解

### 核心概念

**两种模式，追踪方向相反**：

#### 反向追踪 - 追踪值的来源

```
目的: 某个值是怎么来的？
方向: 往前看 ⬆️

示例:
  [50]  mov r0, #4      ← 源头: 立即数
  [100] mov r1, r0      ← 传递
  [200] mov r3, r1      ← 目标: r1=4 是怎么来的？

用途:
✅ 理解算法如何计算某个值
✅ 逆向分析加密逻辑
✅ 追踪数据来源
```

#### 前向追踪 - 追踪值的传播

```
目的: 某个值传播到哪里去了？
方向: 往后看 ⬇️

示例:
  [100] ldr r0, [r5]    ← 污点源
  [200] add r1, r0, #1  ← 传播: r0 → r1
  [300] mov r2, r1      ← 传播: r1 → r2
  [400] str r2, [r3]    ← 传播: r2 → 内存

用途:
✅ 追踪敏感数据(密钥/输入)
✅ 检测数据泄露
✅ 理解输入如何影响输出
```

### 使用方法

#### 1. 反向追踪（追踪来源）

**GUI 操作**：
1. 找到目标指令（如 `mov r3, r1`）
2. 右键 → "反向追踪寄存器值来源"
3. 输入：
   - 寄存器：`r1`
   - 值：`0x8` （十六进制）
4. 如果有多个候选，选择正确的执行
5. 查看结果（往前的传播链）

**Python API**：
```python
from trace_viewer.trace_parser import TraceParser

parser = TraceParser()
parser.parse_file("trace.txt")

# 从事件1000反向追踪 r1=0x8 的来源
hits = parser.taint_backward(
    start_idx=1000,
    target_reg='r1',
    target_value=0x8
)

# 结果按时间正序排列
for idx in hits:
    event = parser.events[idx]
    print(f"[{idx}] {event.asm}")
```

#### 2. 前向追踪（追踪传播）

**GUI 操作**：
1. 找到输入点（如 `ldr r0, [r5]`）
2. 右键 → "值流追踪"
3. 输入：
   - 源寄存器：`r0`
   - 源内存：`0x8000` （可选）
4. 点击"污点前向分析"
5. 查看结果（往后的传播链）

**Python API**：
```python
# 基础前向追踪
hits = parser.taint_forward(
    start_idx=0,
    source_regs=['r0'],
    enable_memory_taint=True
)

print(f"污点传播到 {len(hits)} 个事件")
```

#### 3. 增强前向追踪（深度分析）

**GUI 操作**：
1. 勾选 ✅ **增强模式**
2. 勾选 ✅ **显示汇合点**
3. 选择策略：
   - **NORMAL** (推荐) - 平衡
   - **STRICT** - 严格，减少误报
   - **LOOSE** - 宽松，避免漏报
4. 输入源污点
5. 点击分析

**Python API**：
```python
from trace_viewer.enhanced_taint import EnhancedTaintAnalyzer, TaintPolicy

analyzer = EnhancedTaintAnalyzer(policy=TaintPolicy.NORMAL)

# 设置多个污点源
analyzer.add_source('reg', 'r0', 0)
analyzer.add_source('reg', 'r1', 0)

# 分析...
# 查看污点来源
sources = analyzer.get_taint_sources('r5')
print(f"r5 的污点来源: {sources}")

# 查看汇合点（关键计算点）
confluence = analyzer.get_confluence_points()
for idx, sources_list in confluence.items():
    print(f"事件 {idx}: 多个污点合并")
```

---

## ✨ 增强功能

### 字节级内存污点

**原实现**（地址级）:
```python
mem[0x1000] 被污染  # 整个地址
```

**增强版**（字节级）:
```python
mem[0x1000:0x1004] 被污染  # 精确到4字节
mem[0x1004] 干净             # 第5字节
```

**好处**: 更精确，减少误报

### 污点标签系统

追踪每个污点的完整信息：

```python
r5 的污点标签:
  - Taint(reg:r0@event_0, gen=0)    # 直接来自 r0
  - Taint(mem:0x8000@event_100, gen=2)  # 来自内存，传播2次
```

### 污点汇合点检测 ⭐

自动识别多个污点来源合并的位置：

```assembly
ldr r0, [mem1]      ; 污点源1
ldr r1, [mem2]      ; 污点源2
add r2, r0, r1      ; ⭐ 汇合点 - 关键计算！
```

**在 UI 中**:
- 汇合点会标记为 `⭐汇合点 (2源)`
- 高亮显示（浅黄色背景）
- 这些是算法的关键计算点

### 三种策略模式

| 策略 | 说明 | 适用场景 |
|------|------|---------|
| **STRICT** | 只追踪显式数据流<br>忽略条件分支影响 | 需要高精度<br>减少误报 |
| **NORMAL** | 含常见隐式流<br>包括条件分支 | 大多数场景<br>平衡（推荐）|
| **LOOSE** | 追踪所有可能路径<br>包括推测执行 | 需要全面覆盖<br>避免漏报 |

---

## 🔍 实用场景

### 场景1: 追踪加密密钥

```python
# 1. 找到密钥加载位置
# 假设密钥在 0x8000

# 2. 前向追踪密钥使用
analyzer = EnhancedTaintAnalyzer()
analyzer.add_source('mem', '0x8000', 0)

# 3. 分析后查看汇合点
confluence = analyzer.get_confluence_points()
# 汇合点 = 密钥与数据混合计算的位置 = 加密核心
```

### 场景2: 理解算法逻辑

```python
# 1. 从结果反向追踪
# 假设加密结果在 r5

# 2. 反向追踪
hits = parser.taint_backward(
    start_idx=1000,
    target_reg='r5',
    target_value=result_value
)

# 3. 查看计算过程
for idx in hits:
    print(parser.events[idx].asm)
# 输出: 完整的计算链，从输入到结果
```

### 场景3: 找算法关键点

```python
# 1. 设置多个输入
analyzer.add_source('reg', 'r0', 0)  # 输入1
analyzer.add_source('reg', 'r1', 0)  # 输入2

# 2. 分析
# ...

# 3. 查看汇合点
confluence = analyzer.get_confluence_points()
# 汇合点 = 输入混合的位置 = 算法核心
```

---

## 🐛 常见问题

### Q1: 为什么需要手动输入寄存器值？

**A**: 因为代码面板只显示汇编指令，看不到每次执行的寄存器值。手动输入可以确保追踪的准确性。

### Q2: 候选窗口为什么显示多个结果？

**A**: 因为同一条指令可能在循环中执行多次。通过行号、时间戳和其他寄存器值来区分不同执行。

点击不同候选时，主窗口的寄存器面板会实时更新，帮助你确认是否是目标执行。

### Q3: 反向追踪和前向分析有什么区别？

**A**: 
- **反向追踪**: 从某个值开始，往前找它是怎么来的 ⬆️
- **前向分析**: 从某个值开始，往后看它传播到哪里去了 ⬇️

两者是互补的，用于不同的分析场景。

### Q4: 污点分析没有结果怎么办？

**A**: 检查以下几点：
1. ✅ 是否启用了"内存污点"选项
2. ✅ 源污点输入是否正确
3. ✅ 是否勾选了"仅限同调用内"（如果跨函数则取消）
4. ✅ max_steps 是否太小

### Q5: 增强模式什么时候用？

**A**: 
- ✅ **需要追踪多个输入** - 找它们如何混合
- ✅ **需要找关键计算点** - 查看汇合点
- ✅ **需要精确内存追踪** - 字节级精度
- ✅ **复杂算法分析** - 需要污点来源信息

简单场景用基础模式就够了。

### Q6: 汇合点有什么用？

**A**: 汇合点 = 多个污点来源合并的位置 = **算法的关键计算点**

例如加密算法：
- 密钥是污点源1
- 明文是污点源2
- 汇合点 = 密钥和明文混合的位置 = **加密核心**

找到汇合点就找到了算法的关键。

### Q7: 如何导出结果？

**A**: 
1. 选中多行结果
2. 右键 → "导出伪C代码" 或 "导出Python代码"
3. 复制或保存到文件

---

## 🎓 最佳实践

### 1. 组合使用两种追踪

```
逆向加密算法流程:
1. 用前向追踪: 追踪密钥从哪来 → 找到读取位置
2. 用增强前向: 追踪密钥传播 → 找到加密计算点（汇合点）
3. 用反向追踪: 从加密结果反推 → 理解计算过程
```

### 2. 合理设置分析范围

```python
# 小范围快速测试
hits = parser.taint_forward(..., max_steps=10000)

# 确认后扩大范围
hits = parser.taint_forward(..., max_steps=200000)

# 限制在函数内
hits = parser.taint_forward(..., same_call_only=True)
```

### 3. 选择合适的策略

```python
# 第一次分析 - 用 NORMAL
analyzer = EnhancedTaintAnalyzer(policy=TaintPolicy.NORMAL)

# 结果太多 - 换 STRICT
analyzer = EnhancedTaintAnalyzer(policy=TaintPolicy.STRICT)

# 担心遗漏 - 用 LOOSE
analyzer = EnhancedTaintAnalyzer(policy=TaintPolicy.LOOSE)
```

---

## 📚 更多资源

- **项目主页**: [README.md](../README.md)
- **开发者文档**: [DEVELOPER_NOTES.md](DEVELOPER_NOTES.md)
- **示例代码**: [examples_enhanced_taint.py](../examples_enhanced_taint.py)

---

**祝你分析愉快！** 🎉

如有问题，欢迎提 Issue 或查看文档。

