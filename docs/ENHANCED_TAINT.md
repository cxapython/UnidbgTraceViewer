# 增强版污点分析

针对 Unidbg trace 文件优化的污点分析系统。

## 🎯 为什么不用 angr？

很多人会问："为什么不用 angr 做污点分析？"

**关键区别**：
- **angr** 用于分析**二进制文件** - 需要符号执行、约束求解
- **你的场景** 分析**已执行的 trace** - 所有值都已知，路径已确定

```
angr                          你的场景
━━━━━━━━━━━━━━━━             ━━━━━━━━━━━━━━━━
输入: ELF/PE 二进制文件      输入: trace.txt 文本文件
分析: 所有可能路径            分析: 已执行的具体路径
技术: 符号执行 + 约束求解     技术: 具体值传播
速度: 慢（需要探索路径）      速度: 快（只跟一条路径）
```

**结论**: 对于 Unidbg trace，**专用污点分析更合适**，更快更准确。

---

## ✨ 增强功能

### 1. 字节级内存污点

**原实现**（地址级）:
```python
tainted_mem = {0x1000, 0x1004}  # 整个地址被污染
```

**增强版**（字节级）:
```python
# 精确到每个字节
mem[0x1000:0x1004] 被污染  # 4字节
mem[0x1004:0x1005] 干净     # 第5字节
```

**好处**:
- ✅ 更精确的内存污点追踪
- ✅ 支持部分字节覆盖
- ✅ 减少误报

### 2. 污点标签系统

**原实现**:
```python
tainted_regs = {'r0', 'r1'}  # 只知道被污染
```

**增强版**:
```python
# 每个污点都有标签，记录来源
r0 -> [Taint(reg:r0@event_0, gen=0)]
r1 -> [Taint(mem:0x8000@event_100, gen=2)]  # 来自内存，传播了2次
```

**好处**:
- ✅ 追踪污点来源
- ✅ 识别污点汇合点（多个来源合并）
- ✅ 区分不同污点流

### 3. 污点策略配置

**STRICT 模式**（严格）:
```python
analyzer = EnhancedTaintAnalyzer(policy=TaintPolicy.STRICT)
# 只追踪显式数据流: add r0, r1, r2
# 忽略隐式流: cmp/beq 等条件分支
```

**NORMAL 模式**（平衡）:
```python
analyzer = EnhancedTaintAnalyzer(policy=TaintPolicy.NORMAL)
# 追踪显式流 + 常见隐式流
# 适合大多数场景
```

**LOOSE 模式**（宽松）:
```python
analyzer = EnhancedTaintAnalyzer(policy=TaintPolicy.LOOSE)
# 追踪所有可能的污点路径
# 可能有误报，但不会漏报
```

### 4. 隐式流检测

**场景**:
```assembly
ldr r0, [r5]        ; r0 被污染
cmp r0, #0          ; 比较污染值
beq target          ; 分支依赖污染值
mov r1, #100        ; r1 被隐式污染（分支影响）
```

**增强版**:
```python
# 自动检测条件分支的隐式污点影响
analyzer.propagate_implicit_flow(event_idx, ['r0'])
```

### 5. 污点汇合点检测

**场景**:
```assembly
ldr r0, [mem1]      ; 污点源1
ldr r1, [mem2]      ; 污点源2
add r2, r0, r1      ; 污点汇合 ← 重要！
```

**增强版**:
```python
# 自动识别多个污点来源合并的位置
confluence = analyzer.get_confluence_points()
# {300: [[('reg', 'r0'), ('reg', 'r1')]]}
```

**用途**:
- 🔍 找到算法关键计算点
- 🔍 识别多输入混合位置
- 🔍 理解数据依赖关系

---

## 🚀 使用方法

### 基础使用

```python
from trace_viewer.trace_parser import TraceParser
from trace_viewer.enhanced_taint import EnhancedTaintAnalyzer, TaintPolicy

# 1. 解析trace
parser = TraceParser()
parser.parse_file("trace.txt")

# 2. 创建增强分析器
analyzer = EnhancedTaintAnalyzer(policy=TaintPolicy.NORMAL)

# 3. 设置污点源
analyzer.add_source('reg', 'r0', 0)           # 寄存器污点
analyzer.add_source('mem', '0x8000', 0)       # 内存污点

# 4. 遍历trace进行分析
for i, event in enumerate(parser.events):
    # 根据指令类型进行污点传播
    if event.asm.startswith('add'):
        src_regs = list(event.reads.keys())
        dst_reg = list(event.writes.keys())[0]
        analyzer.propagate_reg_to_reg(i, src_regs, dst_reg)
    
    elif event.asm.startswith('ldr'):
        dst_reg = list(event.writes.keys())[0]
        analyzer.propagate_mem_to_reg(i, event.effaddr, 4, dst_reg)
    
    elif event.asm.startswith('str'):
        src_reg = list(event.reads.keys())[0]
        analyzer.propagate_reg_to_mem(i, src_reg, event.effaddr, 4)

# 5. 查询结果
if analyzer.is_reg_tainted('r5'):
    sources = analyzer.get_taint_sources('r5')
    print(f"r5 的污点来源: {sources}")
```

### 查找污点来源

```python
# 查看某个寄存器的污点来源
sources = analyzer.get_taint_sources('r5')
for source_type, source_id, event_idx in sources:
    print(f"来源: {source_type}:{source_id} (事件 {event_idx})")

# 输出:
# 来源: reg:r0 (事件 0)
# 来源: mem:0x8000 (事件 100)
```

### 查找污点汇合点

```python
# 获取所有污点汇合点
confluence = analyzer.get_confluence_points()

for event_idx, sources_list in confluence.items():
    event = parser.events[event_idx]
    print(f"事件 {event_idx}: {event.asm}")
    
    for sources in sources_list:
        print(f"  合并来源: {sources}")

# 输出:
# 事件 300: add r2, r0, r1
#   合并来源: [('reg', 'r0'), ('reg', 'r1')]
```

### 追踪传播链

```python
# 获取某个寄存器的完整传播链
chain = analyzer.get_propagation_chain('r5')

for event_idx, desc in chain:
    event = parser.events[event_idx]
    print(f"[{event_idx}] {desc}: {event.asm}")

# 输出:
# [100] mem_to_reg:r0: ldr r0, [r5]
# [200] reg_to_reg:r1: mov r1, r0
# [300] reg_to_reg:r2: add r2, r1, #1
```

---

## 📊 与原实现对比

| 功能 | 原实现 | 增强版 |
|------|--------|--------|
| 内存污点粒度 | 地址级 | **字节级** |
| 污点来源追踪 | ❌ | **✅ 标签系统** |
| 隐式流检测 | 基础 | **✅ 可配置策略** |
| 污点汇合检测 | ❌ | **✅ 自动识别** |
| 传播链追踪 | ❌ | **✅ 完整历史** |
| 误报控制 | 固定 | **✅ 3种策略** |
| 性能 | 较快 | **快（专为trace优化）** |

---

## 🔧 高级功能

### 1. 部分位修改支持

```python
# ARM64 movk 指令只修改16位
analyzer.propagate_reg_to_reg(
    event_idx=100,
    src_regs=['x0'],
    dst_reg='x0',
    is_partial=True  # 保留原有污点
)
```

### 2. 自定义污点策略

```python
# 严格模式：减少误报
analyzer = EnhancedTaintAnalyzer(policy=TaintPolicy.STRICT)

# 宽松模式：避免漏报
analyzer = EnhancedTaintAnalyzer(policy=TaintPolicy.LOOSE)
```

### 3. 污点代数（Generation）

```python
# 查看污点传播了多少代
labels = analyzer.get_reg_labels('r5')
for label in labels:
    print(f"污点代数: {label.generation}")
    # generation=0: 直接来源
    # generation=1: 传播1次
    # generation=2: 传播2次
```

---

## 🎓 运行示例

```bash
# 运行完整示例
python trace_viewer/demo/enhanced_taint_demo.py your_trace.txt

# 运行模拟示例（不需要trace文件）
python trace_viewer/demo/enhanced_taint_demo.py
```

**示例输出**:
```
==================================================================
示例 1: 基础污点分析 - 字节级内存追踪
==================================================================
✓ 解析完成，共 120000 个事件
✓ 设置污点源: r0
✓ 分析完成，发现 523 个污点传播事件
✓ 污点汇合点: 15 个

前10个污点传播事件:
  [     0] 0x12023970: movs r1, #4
  [   100] 0x12023980: add r2, r1, #1
  [   200] 0x12023990: ldr r3, [r2]
  ...

污点汇合点（多个污点来源合并）:
  事件 300: add r4, r2, r3
    合并来源: reg:r0, reg:r1
```

---

## 💡 实用技巧

### 找到算法关键点

```python
# 1. 设置多个输入源
analyzer.add_source('reg', 'r0', 0)  # 输入1
analyzer.add_source('reg', 'r1', 0)  # 输入2

# 2. 运行分析
# ...

# 3. 查找汇合点 = 算法混合输入的位置
confluence = analyzer.get_confluence_points()
print(f"找到 {len(confluence)} 个关键计算点")
```

### 追踪加密密钥

```python
# 1. 设置密钥地址为污点源
analyzer.add_source('mem', '0x8000', 0)

# 2. 分析后查看哪些寄存器被污染
for reg in ['r0', 'r1', 'r2', 'r3']:
    if analyzer.is_reg_tainted(reg):
        sources = analyzer.get_taint_sources(reg)
        print(f"{reg} 包含密钥数据，来源: {sources}")
```

### 减少误报

```python
# 使用严格模式
analyzer = EnhancedTaintAnalyzer(policy=TaintPolicy.STRICT)

# 或者过滤低代数污点
labels = analyzer.get_reg_labels('r5')
direct_taints = [l for l in labels if l.generation <= 2]
if direct_taints:
    print("r5 受直接污点影响（高置信度）")
```

---

## 🔮 未来改进

1. **GUI 集成** - 在主界面显示污点汇合点和传播链
2. **污点可视化** - 生成污点流图
3. **性能优化** - 位图表示污点集合
4. **自动规则** - 根据trace自动识别传播规则

---

## 📚 相关文档

- [快速入门](QUICK_START.md)
- [原污点分析文档](TAINT_ANALYSIS.md)
- [示例代码](../trace_viewer/demo/enhanced_taint_demo.py)

---

**总结**: 这个增强版污点分析专为 Unidbg trace 优化，不需要 angr 的复杂符号执行，而是利用 trace 已有的具体值进行高效精确的污点追踪。

