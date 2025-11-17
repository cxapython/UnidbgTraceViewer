# 增强污点分析 - 快速指南

## 🎯 核心改进

专为 **Unidbg trace 文本文件**优化的污点分析，比 angr 更适合你的场景。

### 为什么不用 angr？

| angr | 你的场景 |
|------|---------|
| 分析二进制文件 | 分析文本 trace |
| 符号执行所有路径 | 已知具体执行路径 |
| 约束求解未知值 | 所有值已知 |
| **慢** | **快** |

**结论**: trace 分析用专用方案更好！

---

## ✨ 新功能

### 1. 字节级内存污点
```python
# 原来：整个地址
tainted_mem = {0x1000}

# 现在：字节精度
mem[0x1000:0x1004] 污染  # 4字节
mem[0x1004] 干净          # 第5字节
```

### 2. 污点标签（追踪来源）
```python
# 知道每个污点从哪来的
r5 的污点来源:
  - reg:r0 (事件 0)
  - mem:0x8000 (事件 100)
```

### 3. 污点汇合点（关键算法点）
```python
# 自动找到多个输入混合的位置
事件 300: add r4, r2, r3
  合并来源: reg:r0, reg:r1  ← 算法关键点！
```

### 4. 三种策略
- **STRICT**: 只追踪显式流（减少误报）
- **NORMAL**: 平衡（推荐）
- **LOOSE**: 追踪所有（避免漏报）

---

## 🚀 快速开始

### 基本使用

```python
from trace_viewer.trace_parser import TraceParser
from trace_viewer.enhanced_taint import EnhancedTaintAnalyzer

# 1. 解析trace
parser = TraceParser()
parser.parse_file("trace.txt")

# 2. 创建分析器
analyzer = EnhancedTaintAnalyzer()

# 3. 设置污点源
analyzer.add_source('reg', 'r0', 0)

# 4. 分析（遍历trace并传播污点）
for i, event in enumerate(parser.events):
    if 'add' in event.asm:
        analyzer.propagate_reg_to_reg(i, ['r0', 'r1'], 'r2')
    elif 'ldr' in event.asm:
        analyzer.propagate_mem_to_reg(i, event.effaddr, 4, 'r0')
    elif 'str' in event.asm:
        analyzer.propagate_reg_to_mem(i, 'r0', event.effaddr, 4)

# 5. 查询结果
if analyzer.is_reg_tainted('r5'):
    sources = analyzer.get_taint_sources('r5')
    print(f"r5 污染来源: {sources}")
```

### 运行示例

```bash
# 带trace文件
python trace_viewer/demo/enhanced_taint_demo.py your_trace.txt

# 模拟演示（不需要trace文件）
python trace_viewer/demo/enhanced_taint_demo.py
```

---

## 📊 实际应用

### 追踪加密密钥

```python
analyzer = EnhancedTaintAnalyzer()
analyzer.add_source('mem', '0x8000', 0)  # 密钥地址

# 分析后...
for reg in ['r0', 'r1', 'r2']:
    if analyzer.is_reg_tainted(reg):
        print(f"{reg} 包含密钥数据")
```

### 找到算法关键点

```python
# 设置多个输入
analyzer.add_source('reg', 'r0', 0)
analyzer.add_source('reg', 'r1', 0)

# 查找汇合点 = 算法核心计算
confluence = analyzer.get_confluence_points()
for idx, sources in confluence.items():
    print(f"关键计算点: 事件{idx}")
```

---

## 📚 完整文档

- **[详细文档](docs/ENHANCED_TAINT.md)** - 完整功能说明
- **[示例代码](trace_viewer/demo/enhanced_taint_demo.py)** - 可运行的示例

---

## 💡 对比总结

| 功能 | 原实现 | 增强版 |
|------|--------|--------|
| 内存污点 | 地址级 | **字节级** ✨ |
| 污点来源 | ❌ | **✅ 标签追踪** |
| 汇合点检测 | ❌ | **✅ 自动识别** |
| 传播链 | ❌ | **✅ 完整历史** |
| 策略配置 | 固定 | **✅ 3种模式** |

**结论**: 更精确、更强大、更适合 Unidbg trace！

