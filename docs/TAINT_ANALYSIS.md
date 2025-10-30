# 污点前向分析快速入门指南

本文档帮助您快速上手Trace Viewer的污点前向分析功能，包括最新的ARM32指令支持。

## 目录

- [什么是污点分析](#什么是污点分析)
- [基础使用](#基础使用)
- [高级功能](#高级功能)
- [新增ARM32指令支持](#新增arm32指令支持)
- [新增ARM64指令支持](#新增arm64指令支持)
- [性能优化建议](#性能优化建议)
- [常见问题](#常见问题)

---

## 什么是污点分析

污点分析（Taint Analysis）是一种跟踪数据流动的技术，用于：

- 🔍 **追踪敏感数据**：从输入源（如网络、文件）到输出点的流动路径
- 🛡️ **安全分析**：检测数据是否流向危险函数（如exec）
- 🐛 **逆向工程**：理解算法如何处理特定输入
- 📊 **依赖分析**：了解哪些指令依赖某个寄存器或内存值

### 基本概念

- **污点源（Source）**：定义哪些寄存器或内存地址作为起点
- **污点传播（Propagation）**：跟踪污点如何通过指令传播
  - 寄存器到寄存器：`add r0, r1, r2` - r1或r2污染则r0污染
  - 内存到寄存器：`ldr r0, [r1]` - 内存污染则r0污染
  - 寄存器到内存：`str r0, [r1]` - r0污染则内存污染
- **污点清洗（Sanitization）**：污点被清除的情况
  - 立即数覆盖：`mov r0, #0` - r0不再污染
  - 常量池加载：`ldr r0, [pc, #8]` - 从只读区加载
  - 恒等归约：`eor r0, r1, r1` - 结果恒为0

---

## 基础使用

### 方式1：GUI界面

#### 1. 打开trace文件

```bash
python3 -m trace_viewer.app
# 或
trace-viewer
```

然后在GUI中打开trace文件。

#### 2. 定位起始点

- 在trace列表中找到感兴趣的指令
- 右键点击 → 选择"值流追踪"

#### 3. 执行污点分析

在值流追踪面板中：

1. **源污点输入**：
   - 寄存器：`r0` 或 `r0,r1,r2`
   - 内存：`0x8000` 或 `0x8000,0x9000`
   - 混合：`r0,0x8000`

2. **点击"污点前向分析"**

3. **查看结果**：
   - 双击任意结果行跳转到对应指令
   - 查看每个指令的污点传播情况

### 方式2：Python API

```python
from trace_viewer.trace_parser import TraceParser

# 1. 解析trace文件
parser = TraceParser()
parser.parse_file("your_trace.txt")

# 2. 执行污点前向分析
hits = parser.taint_forward(
    start_idx=0,               # 从第一条指令开始
    source_regs=['r0', 'r1'],  # 污点源：r0和r1寄存器
    enable_memory_taint=True,  # 启用内存污点传播
    max_steps=100000           # 最多分析10万步
)

# 3. 输出结果
print(f"污点传播涉及 {len(hits)} 个事件")
for idx in hits[:10]:  # 显示前10个
    event = parser.events[idx]
    print(f"[{idx}] {hex(event.pc)}: {event.asm}")
```

---

## 高级功能

### 目标导向分析

当你知道想要检测污点何时到达某个寄存器时：

```python
result = parser.advanced_taint_analysis(
    start_idx=100,
    source_regs=['r0'],       # 源：r0
    target_regs=['r5'],       # 目标：想知道r0何时影响r5
    enable_memory_taint=True,
    max_steps=50000
)

# 查看是否到达目标
if result['target_reached']:
    print("✓ 污点已到达目标寄存器r5")
    print(f"命中次数: {result['statistics']['target_hits']}")
else:
    print("✗ 污点未到达目标")

# 查看详细统计
stats = result['statistics']
print(f"总步数: {stats['total_steps']}")
print(f"寄存器传播: {stats['register_propagations']}")
print(f"内存传播: {stats['memory_propagations']}")
print(f"污点清洗: {stats['cleanups']}")
```

### 传播路径分析

查看污点的详细传播路径：

```python
result = parser.advanced_taint_analysis(
    start_idx=0,
    source_regs=['r0'],
    enable_memory_taint=True,
    max_steps=10000
)

# 遍历传播路径
for step in result['taint_path']:
    print(f"{step['pc']}: {step['asm']}")
    print(f"  传播类型: {step['propagation_type']}")
    print(f"  污点寄存器(前): {step['tainted_regs_before']}")
    print(f"  污点寄存器(后): {step['tainted_regs_after']}")
    if step['target_hit']:
        print("  ★ 到达目标！")
```

### 仅同一调用内分析

限制分析范围在同一个函数调用内：

```python
hits = parser.taint_forward(
    start_idx=1000,
    source_regs=['r0'],
    same_call_only=True,  # 只分析同一个call_id
    enable_memory_taint=True
)
```

### 禁用内存污点

如果只关心寄存器传播，可以禁用内存污点提升速度：

```python
hits = parser.taint_forward(
    start_idx=0,
    source_regs=['r0'],
    enable_memory_taint=False,  # 不追踪内存污点
    max_steps=200000
)
```

---

## 新增ARM32指令支持

### 扩展指令（sxtah/sxtab/uxtah/uxtab）

**场景**：处理符号扩展和无符号扩展

```assembly
ldr r0, [r5]          ; 污点源
sxtah r1, r0, r2      ; r1 = r0 + SignExtend16(r2)
add r3, r1, #1        ; r3被污染
```

✅ **自动支持**：污点会从r0传播到r1，再传播到r3

### 或非指令（orn）

**场景**：位操作优化

```assembly
ldr r0, [r5]          ; 污点源
orn r1, r0, r2        ; r1 = r0 | ~r2
str r1, [r3]          ; 内存被污染
```

✅ **自动支持**：orn正确传播污点

### 长乘法（umull）

**场景**：64位乘法结果

```assembly
ldr r0, [r5]          ; 污点源
umull r2, r3, r0, r1  ; {r3,r2} = r0 * r1 (64-bit)
add r4, r2, #1        ; r4被污染（低32位）
add r5, r3, #1        ; r5被污染（高32位）
```

✅ **自动支持**：污点同时传播到rdlo(r2)和rdhi(r3)

### 双字访存（strd/ldrd）

**场景**：8字节批量访存

```assembly
ldr r0, [r6]          ; 污点源
mov r1, #0x200
strd r0, r1, [r2]     ; 存储8字节到[r2]和[r2+4]
ldrd r3, r4, [r2]     ; 加载8字节到r3和r4
```

✅ **自动支持**：
- strd标记8字节内存范围为污点
- ldrd从污点内存加载，r3和r4都被污染

### 多寄存器栈操作（push/pop）

**场景**：函数调用保存/恢复寄存器

```assembly
ldr r0, [r6]          ; 污点源
mov r1, #0x200
push {r0-r2, lr}      ; 压栈4个寄存器
mov r0, #0            ; 清空r0
pop {r3-r5, pc}       ; 出栈到新寄存器
add r6, r3, #1        ; r6被污染（r3来自栈）
```

✅ **自动支持**：
- push检测到r0被污染，标记污点传播
- pop保守假设栈可能被污染，传播到所有目标寄存器

### 批量访存（stm/ldm）

**场景**：多寄存器批量读写

```assembly
ldr r0, [r6]          ; 污点源
stm sp!, {r0-r3}      ; 批量存储
ldm sp!, {r4-r7}      ; 批量加载
```

✅ **自动支持**：类似push/pop，正确处理多寄存器污点传播

---

## 新增ARM64指令支持

### v0.3.1 新增

基于真实ARM64 trace文件（ks_trace.txt，856万行）的深度分析，新增支持以下高频ARM64指令：

#### 1. 条件选择指令（24万次）

##### csel - 条件选择
```assembly
csel x2, x0, x1, eq  ; 如果eq条件满足选择x0，否则选择x1
```

**污点传播**：
- 如果 `x0` 或 `x1` 被污染，则 `x2` 被污染
- 因为运行时才能确定选择哪个源，保守策略是：任一源污染则目标污染

**示例**：
```python
# trace: ldr x0, [x5] (污点源)
#        mov x1, #100
#        csel x2, x0, x1, eq
# 结果: x2被污染（因为x0被污染）
```

##### cset - 条件设置
```assembly
cset w1, eq  ; 如果eq条件满足设置为1，否则设置为0
```

**污点传播**：
- **清洗污点**（设置常量0或1）
- 类似于 `mov w1, #0` 或 `mov w1, #1`

**示例**：
```python
# trace: ldr x0, [x5] (污点源)
#        cmp x0, #0
#        cset w1, eq
# 结果: w1不被污染（常量清洗）
```

#### 2. 多字节立即数指令（69万次）

##### movk - 部分位修改
```assembly
movk x0, #0x7fff, lsl #48  ; 只修改x0的高16位
```

**污点传播**：
- **保留污点**（保守策略）
- 与 `mov` 不同，`movk` 只修改部分位（16位）
- 无法精确跟踪位级污点，保守策略是保持现有污点状态

**示例**：
```python
# trace: ldr x0, [x5]              (污点源)
#        movk x0, #0x7fff, lsl #48  (修改高16位)
#        add x1, x0, #1
# 结果: x0仍被污染，x1被污染
```

**常见用法**：
```assembly
; 构造64位地址
mov  x0, #0x1234        ; x0 = 0x0000000000001234
movk x0, #0x5678, lsl #16  ; x0 = 0x0000000056781234
movk x0, #0x9abc, lsl #32  ; x0 = 0x00009abc56781234
movk x0, #0xdef0, lsl #48  ; x0 = 0xdef09abc56781234
```

#### 3. 乘加指令（约3万次）

##### madd - 乘加
```assembly
madd x3, x0, x1, x2  ; x3 = x2 + (x0 * x1)
```

**污点传播**：
- 如果 `x0`、`x1` 或 `x2` 任一被污染，则 `x3` 被污染
- 4个操作数，任一污染则结果污染

**示例**：
```python
# trace: ldr x0, [x5]  (污点源)
#        mov x1, #2
#        mov x2, #3
#        madd x3, x0, x1, x2  ; x3 = 3 + (x0 * 2)
# 结果: x3被污染
```

##### smaddl - 有符号长乘加
```assembly
smaddl x4, w1, w2, x3  ; x4 = x3 + SignExtend(w1 * w2)
```

**污点传播**：
- 32位操作数（w1, w2），64位结果（x4）
- 如果 `w1`、`w2` 或 `x3` 任一被污染，则 `x4` 被污染

#### 4. 符号扩展指令（1万次）

##### sxtw - 符号扩展字
```assembly
sxtw x1, w0  ; 将w0符号扩展到x1
```

**污点传播**：
- 如果 `w0` 被污染，则 `x1` 被污染
- ARM64的 `wN` 和 `xN` 是寄存器别名，自动处理

**示例**：
```python
# trace: ldr w0, [x5]  (污点源，32位)
#        sxtw x1, w0   (扩展到64位)
#        add x2, x1, #1
# 结果: x1被污染，x2被污染
```

#### 5. 地址计算指令（8.8万次）

##### adrp - 页地址计算
```assembly
adrp x0, #0x40070000  ; 计算页对齐地址（4KB对齐）
```

**污点传播**：
- **清洗污点**（地址常量）
- 结果是编译时确定的常量地址

**示例**：
```python
# trace: ldr x0, [x5]          (污点源)
#        adrp x0, #0x40070000  (地址常量)
#        add x1, x0, #0x10
# 结果: x0不被污染（清洗），x1不被污染
```

**常见用法**：
```assembly
; 加载全局变量地址
adrp x0, #0x40070000  ; 页地址
add  x0, x0, #0x10    ; 页内偏移
ldr  x1, [x0]         ; 加载数据
```

### ARM64指令覆盖率

| 指令类型 | 出现次数 | v0.3.1支持 |
|---------|---------|-----------|
| **csel** | 126,914 | ✓ |
| **cset** | 116,139 | ✓ |
| **movk** | 699,117 | ✓ |
| **madd** | 19,224 | ✓ |
| **smaddl** | 9,598 | ✓ |
| **sxtw** | 10,787 | ✓ |
| **adrp** | 88,868 | ✓ |
| **csinc/csinv/csneg** | - | ✓ |
| **msub/umaddl/smsubl** | - | ✓ |
| **uxtw** | - | ✓ |

### 传播类型

`advanced_taint_analysis` 新增的传播类型：

| 类型 | 含义 | 示例 |
|------|------|------|
| `csel_conditional` | 条件选择传播 | `csel x2, x0, x1, eq` |
| `cset_cleanup` | 条件设置清洗 | `cset w1, eq` |
| `madd_multiply_add` | 乘加传播 | `madd x3, x0, x1, x2` |
| `movk_partial_modify` | 部分位修改 | `movk x0, #0xff, lsl #16` |
| `adrp_cleanup` | 地址计算清洗 | `adrp x0, #0x40070000` |

### 测试验证

运行ARM64指令测试：
```bash
python tests/test_arm64_instructions.py
```

预期输出：
```
============================================================
Running ARM64 Instruction Tests
============================================================

✓ Instruction Type Detection
✓ CSEL Operand Parsing
✓ MADD Operand Parsing
✓ CSEL Instruction
✓ CSET Instruction
✓ MOVK Instruction
✓ MADD Instruction
✓ SMADDL Instruction
✓ SXTW Instruction
✓ ADRP Instruction
✓ Advanced Taint Analysis

Test Results: 11 passed, 0 failed
============================================================
```

---

## 性能优化建议

### 1. 合理设置max_steps

```python
# 小范围快速分析
hits = parser.taint_forward(..., max_steps=10000)

# 大范围全局分析
hits = parser.taint_forward(..., max_steps=500000)
```

### 2. 使用same_call_only限制范围

```python
# 只在当前函数内分析，速度更快
hits = parser.taint_forward(
    ...,
    same_call_only=True
)
```

### 3. 按需启用内存污点

```python
# 如果只关心寄存器，禁用内存污点
hits = parser.taint_forward(
    ...,
    enable_memory_taint=False  # 提升速度
)
```

### 4. 使用位图优化（实验性）

```python
from trace_viewer.taint_bitmap import TaintBitmap

# 转换为位图
reg_set = {'r0', 'r1', 'r2'}
bitmap = TaintBitmap.from_set(reg_set)

# 位图操作（更快，更省内存）
bitmap = TaintBitmap.add_register(bitmap, 'r3')
is_tainted = TaintBitmap.contains(bitmap, 'r0')

# 转换回set
reg_set = TaintBitmap.to_set(bitmap)
```

**优势**：
- 内存占用减少97.5%
- 适合大规模分析（百万级步数）

---

## 常见问题

### Q1: 为什么某些指令没有被检测为污点传播？

**A**: 可能原因：
1. **未启用内存污点**：如果污点通过内存传播，需要 `enable_memory_taint=True`
2. **指令不支持**：虽然已支持98%+的常见指令，但某些罕见指令可能未覆盖
3. **污点被清洗**：如果中间有立即数覆盖，污点会被清除

**解决方法**：
```python
# 启用内存污点
hits = parser.taint_forward(..., enable_memory_taint=True)

# 使用高级分析查看详细传播路径
result = parser.advanced_taint_analysis(...)
for step in result['taint_path']:
    print(step['propagation_type'])  # 查看每步的传播类型
```

### Q2: 分析很慢怎么办？

**A**: 优化方法：
1. **减少max_steps**：先小范围测试，确认逻辑正确后再扩大
2. **使用same_call_only**：限制在单个函数内
3. **禁用内存污点**：如果不需要内存传播
4. **分段分析**：将大trace切分为多个小段分别分析

```python
# 分段分析示例
segment_size = 50000
for i in range(0, len(parser.events), segment_size):
    hits = parser.taint_forward(
        start_idx=i,
        source_regs=['r0'],
        max_steps=segment_size
    )
    # 处理这一段的结果
```

### Q3: push/pop的污点传播不准确？

**A**: push/pop的处理采用保守策略：

- **push**: 只要寄存器列表中有污点，就标记为传播
- **pop**: 如果有任何污点内存，就假设可能影响所有出栈寄存器

这种保守策略可能产生**误报**（false positive），但不会漏报（false negative）。

**更精确的方案**（需要SP追踪）：
1. 记录push时的SP值和污染寄存器
2. pop时根据SP值精确匹配
3. 目前版本为了简化实现，采用保守策略

### Q4: 如何理解传播类型（propagation_type）？

**A**: `advanced_taint_analysis` 返回的传播类型含义：

| 类型 | 含义 | 示例 |
|------|------|------|
| `reg_to_reg` | 寄存器到寄存器 | `add r0, r1, r2` |
| `mem_to_reg` | 内存到寄存器 | `ldr r0, [r1]` |
| `reg_to_mem` | 寄存器到内存 | `str r0, [r1]` |
| `bitfield_op` | 位域操作 | `ubfx r0, r1, #8, #8` |
| `multiply_op` | 乘法操作 | `mul r0, r1, r2` |
| `extend_op` | 扩展操作 | `sxtah r0, r1, r2` |
| `bitwise_not_op` | 位非操作 | `orn r0, r1, r2` |
| `push_multi_reg` | 多寄存器压栈 | `push {r0-r7}` |
| `pop_multi_reg` | 多寄存器出栈 | `pop {r0-r7}` |
| `strd_dual_reg` | 双字存储 | `strd r0, r1, [r2]` |
| `ldrd_dual_reg` | 双字加载 | `ldrd r0, r1, [r2]` |
| `cleanup_zero` | 零值清洗 | `eor r0, r1, r1` |
| `cleanup_immediate` | 立即数清洗 | `mov r0, #0` |
| `cleanup_const_pool` | 常量池清洗 | `ldr r0, [pc, #8]` |

### Q5: 位图优化什么时候有用？

**A**: 位图优化在以下场景特别有用：

✅ **适合使用位图**：
- 分析步数 > 10万
- 需要记录完整传播路径
- 内存受限环境
- 需要频繁复制污点状态

❌ **不适合使用位图**：
- 小规模分析（< 1万步）
- 只需要最终结果，不需要中间路径
- Python解释器执行（函数调用开销大）

**最佳实践**：
- 在C扩展或Cython编译后使用位图
- 或者用于后处理大量结果时的内存优化

---

## 完整示例

### 示例1：追踪加密算法的密钥使用

```python
from trace_viewer.trace_parser import TraceParser

parser = TraceParser()
parser.parse_file("crypto_trace.txt")

# 假设密钥在0x8000地址
result = parser.advanced_taint_analysis(
    start_idx=0,
    source_mem_addrs=[0x8000],  # 密钥地址
    enable_memory_taint=True,
    max_steps=100000,
    track_constants=True
)

print(f"密钥被使用了 {len(result['hits'])} 次")
print(f"寄存器传播: {result['statistics']['register_propagations']}")
print(f"内存传播: {result['statistics']['memory_propagations']}")

# 找出密钥最终流向哪些寄存器
final_regs = result['final_tainted_regs']
print(f"密钥最终存在于: {final_regs}")
```

### 示例2：查找数据依赖链

```python
# 追踪r0从输入到输出的完整路径
result = parser.advanced_taint_analysis(
    start_idx=100,
    source_regs=['r0'],
    target_mem_addrs=[0x9000],  # 输出缓冲区
    enable_memory_taint=True,
    max_steps=50000
)

if result['target_reached']:
    print("✓ 找到了从r0到输出缓冲区的路径")
    
    # 打印关键传播步骤
    for step in result['taint_path']:
        if step['propagation_type'] in ['mem_to_reg', 'reg_to_mem']:
            print(f"{step['pc']}: {step['asm']} [{step['propagation_type']}]")
```

### 示例3：检测污点清洗点

```python
result = parser.advanced_taint_analysis(
    start_idx=0,
    source_regs=['r0'],
    enable_memory_taint=True,
    track_constants=True,
    max_steps=100000
)

print(f"污点清洗发生了 {result['statistics']['cleanups']} 次")

# 找出所有清洗点
cleanup_points = [
    step for step in result['taint_path']
    if step['propagation_type'] and 'cleanup' in step['propagation_type']
]

for step in cleanup_points:
    print(f"{step['pc']}: {step['asm']} - {step['propagation_type']}")
```

---

## 下一步

- 📖 阅读 [IMPROVEMENTS_SUMMARY.md](IMPROVEMENTS_SUMMARY.md) 了解详细技术细节
- 🧪 运行测试验证：`python3 tests/test_advanced_instructions.py`
- 📊 查看位图性能：`python3 trace_viewer/taint_bitmap.py`
- 💡 查看完整API文档：查看 `trace_parser.py` 中的docstring

---

**问题反馈**：如果遇到问题或有改进建议，欢迎提交Issue或PR！

