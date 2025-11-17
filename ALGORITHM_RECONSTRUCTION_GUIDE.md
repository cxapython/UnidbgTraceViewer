# 🎯 算法还原实战指南

> 如何使用 UnidbgTraceViewer 的增强功能还原trace中的算法代码

## 📚 目标读者

- 逆向工程师
- 安全研究人员
- 想要从trace文件还原算法实现的开发者

## 🎬 工作流程概览

```
加载trace → 定位关键函数 → 分析汇编指令 → 识别数据流 → 还原算法
    ↓            ↓              ↓              ↓            ↓
 文件菜单    函数列表       代码面板     寄存器+内存   伪代码编写
```

## 🔍 步骤1：加载并定位关键函数

### 1.1 加载trace文件
```
菜单 → 文件 → 打开 → 选择 .txt trace文件
```

### 1.2 浏览函数列表
- **左侧函数列表**显示所有识别的函数
- 点击函数名跳转到第一次执行
- 寻找可疑的函数名：
  - `encrypt`, `decrypt`, `sign`, `verify`
  - `md5`, `sha`, `aes`, `rsa`
  - `encode`, `decode`, `transform`

### 1.3 定位关键代码段
查找特征：
- 🔀 **循环**：反复跳转到同一地址（`blt #0x1000`）
- ⚡ **XOR操作**：`eor r0, r0, r2`（常见于加密）
- 📥📤 **内存读写**：连续的`ldr`和`str`
- 📏 **递增索引**：`add r4, r4, #1`

## 🔬 步骤2：分析代码面板的增强信息

### 2.1 查看操作类型图标

**示例trace片段**：
```
0100 | 📥 0x1000 | ldr r0, [r1, r4]  | r0=0x48←[0x7000] (r1=0x7000, r4=0x00)
0101 | 📥 0x1004 | ldr r2, [r5, r4]  | r2=0x0A←[0x8000] (r5=0x8000, r4=0x00)
0102 | ⚡ 0x1008 | eor r0, r0, r2    | r0=0x42 (r0=0x48, r2=0x0A)
0103 | 📤 0x100c | str r0, [r3, r4]  | →[0x9000] (r0=0x42, r3=0x9000, r4=0x00)
0104 | ➕ 0x1010 | add r4, r4, #1    | r4=0x01 (r4=0x00)
0105 | ⚖️ 0x1014 | cmp r4, #0x10     | (r4=0x01)
0106 | 🔀 0x1018 | blt #0x1000       | 
```

**快速分析**：
1. 📥 从`[r1+r4]`加载数据 → 输入缓冲区
2. 📥 从`[r5+r4]`加载密钥 → 密钥缓冲区
3. ⚡ XOR运算 → 加密操作
4. 📤 存储到`[r3+r4]` → 输出缓冲区
5. ➕ r4递增 → 循环索引
6. 🔀 循环跳转 → 处理16字节

**初步结论**：这是一个16字节的XOR加密循环！

### 2.2 内联寄存器值分析

关注箭头和括号：
- `r0=0x42` → 写入的值
- `←[0x7000]` → 从内存加载
- `→[0x9000]` → 存储到内存
- `(r1=0x7000, r4=0x00)` → 读取的寄存器值

**实战技巧**：
1. 追踪数据变换：`0x48 XOR 0x0A = 0x42`
2. 记录缓冲区地址：input=0x7000, key=0x8000, output=0x9000
3. 验证算法逻辑：XOR每个字节

## 📊 步骤3：利用智能寄存器面板

### 3.1 识别寄存器用途

**寄存器面板显示**：
```
寄存器 | 之前      | 之后      | 用途      | 趋势
-------|----------|----------|-----------|------
r0     | 0x48     | 0x42     | 📦 data0  | ↕     ← 数据值（频繁变化）
r1     | 0x7000   | 0x7000   | 📍 ptr1   | →     ← 输入指针（不变）
r2     | 0x0A     | 0x0A     | 🔑 key2   | →     ← 密钥（不变）
r3     | 0x9000   | 0x9000   | 📍 ptr3   | →     ← 输出指针（不变）
r4     | 0x00     | 0x01     | 📏 idx4   | ↗     ← 循环索引（递增）
r5     | 0x8000   | 0x8000   | 📍 ptr5   | →     ← 密钥指针（不变）
```

**分析结论**：
- `r1`, `r3`, `r5` = 指针（📍 + →）
- `r4` = 循环索引（📏 + ↗）
- `r2` = 密钥值（🔑 + →）
- `r0` = 中间数据（📦 + ↕）

### 3.2 确定变量命名

基于"用途"列的建议：
```c
uint8_t* input_ptr = (uint8_t*)r1;   // 📍 ptr1
uint8_t* key_ptr = (uint8_t*)r5;      // 📍 ptr5
uint8_t* output_ptr = (uint8_t*)r3;   // 📍 ptr3
int index = r4;                        // 📏 idx4
uint8_t key_byte = r2;                 // 🔑 key2
uint8_t data_byte = r0;                // 📦 data0
```

## 🧩 步骤4：检测循环结构

### 4.1 识别循环特征

**循环的标志**：
1. 📏 **索引寄存器递增**（↗）
2. ⚖️ **比较指令** `cmp r4, #0x10`
3. 🔀 **条件跳转** `blt #0x1000`（跳回循环开始）

**循环边界**：
- **起始PC**: `0x1000`（跳转目标）
- **结束PC**: `0x1018`（跳转指令）
- **索引范围**: `0 → 16`（从cmp指令得知）

### 4.2 循环体分析

循环体内的操作（`0x1000`到`0x1018`）：
```
ldr r0, [r1, r4]   ; 加载输入[index]
ldr r2, [r5, r4]   ; 加载密钥[index]
eor r0, r0, r2     ; XOR运算
str r0, [r3, r4]   ; 存储输出[index]
add r4, r4, #1     ; index++
cmp r4, #0x10      ; 比较
blt #0x1000        ; 循环
```

**对应伪代码**：
```c
for (int i = 0; i < 16; i++) {
    output[i] = input[i] ^ key[i];
}
```

## 🎨 步骤5：使用内存查看器验证

### 5.1 查看输入数据

从代码面板得知输入地址：`r1=0x7000`

**操作**：
1. 打开右侧"内存查看器"面板
2. 输入地址：`0x7000`
3. 长度设为：`256`
4. 点击"查看"

**预期看到**：
```
偏移    +0 +1 +2 +3 +4 +5 +6 +7  +8 +9 +A +B +C +D +E +F  ASCII
0000: 48 65 6C 6C 6F 20 57 6F  72 6C 64 21 00 00 00 00  Hello World!....
```
→ 输入是"Hello World!"

### 5.2 查看密钥数据

从代码面板得知密钥地址：`r5=0x8000`

**查看密钥**：
```
0000: 0A 0A 0A 0A 0A 0A 0A 0A  0A 0A 0A 0A 0A 0A 0A 0A  ................
```
→ 密钥是固定值`0x0A`

### 5.3 查看输出数据

从代码面板得知输出地址：`r3=0x9000`

**查看输出（勾选"对比模式"）**：
```
【执行前】
0000: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................

【执行后】
0000: 42 6F 66 66 65 2A 5D 65  78 66 6E 2B 00 00 00 00  Boffe*]exfn+....

变化统计: 12 字节变化 (75.0%)
```

### 5.4 验证算法

手动计算：
```python
input = "Hello World!"
key = 0x0A

for c in input:
    encrypted = ord(c) ^ key
    print(f"{c} (0x{ord(c):02x}) ^ 0x{key:02x} = 0x{encrypted:02x}")

# H (0x48) ^ 0x0A = 0x42 ✓
# e (0x65) ^ 0x0A = 0x6F ✓
# l (0x6C) ^ 0x0A = 0x66 ✓
# ...
```

**结论**：验证通过！这是简单的XOR加密。

## 📝 步骤6：编写还原代码

### 6.1 C语言版本

```c
/**
 * XOR加密函数
 * 从 trace 0x1000-0x1018 还原
 */
void xor_encrypt(uint8_t* input, uint8_t* output, uint8_t* key, size_t len) {
    for (size_t i = 0; i < len; i++) {
        uint8_t data = input[i];      // ldr r0, [r1, r4]
        uint8_t k = key[i];            // ldr r2, [r5, r4]
        uint8_t encrypted = data ^ k;  // eor r0, r0, r2
        output[i] = encrypted;         // str r0, [r3, r4]
        // i++;                        // add r4, r4, #1
    }
}

// 使用示例
uint8_t input[] = "Hello World!";
uint8_t key[16] = {0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A,
                   0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A};
uint8_t output[16];

xor_encrypt(input, output, key, 12);
```

### 6.2 Python版本

```python
def xor_encrypt(input_data: bytes, key: bytes) -> bytes:
    """
    XOR加密函数
    从 trace 0x1000-0x1018 还原
    """
    output = bytearray(len(input_data))
    
    for i in range(len(input_data)):
        data = input_data[i]      # ldr r0, [r1, r4]
        k = key[i % len(key)]     # ldr r2, [r5, r4]
        encrypted = data ^ k       # eor r0, r0, r2
        output[i] = encrypted      # str r0, [r3, r4]
    
    return bytes(output)

# 使用示例
input_data = b"Hello World!"
key = bytes([0x0A] * 16)
output = xor_encrypt(input_data, key)
print(output.hex())  # 426f66666e2a5d6578666e2b
```

### 6.3 Frida Hook脚本

```javascript
/**
 * Hook XOR加密函数
 * 基于 trace 0x1000-0x1018 分析
 */
Interceptor.attach(Module.findBaseAddress("libxxx.so").add(0x1000), {
    onEnter: function(args) {
        console.log("[XOR Encrypt] Called");
        
        // r1 = input pointer
        var input_ptr = this.context.r1;
        console.log("  Input:", hexdump(input_ptr, {length: 16}));
        
        // r5 = key pointer
        var key_ptr = this.context.r5;
        console.log("  Key:", hexdump(key_ptr, {length: 16}));
        
        // r3 = output pointer
        this.output_ptr = this.context.r3;
    },
    onLeave: function(retval) {
        console.log("  Output:", hexdump(this.output_ptr, {length: 16}));
    }
});
```

## 🎓 高级技巧

### 技巧1：使用污点追踪验证数据流

**目标**：验证输出确实来自输入和密钥

**操作**：
1. 在值流追踪面板输入：
   - 寄存器：`r0`（输出数据）
   - 值：`0x42`（加密后的值）
2. 点击"追踪来源"
3. 查看追踪结果：
   ```
   0x100c: str r0, [r3, r4]  → r0=0x42（写入）
   0x1008: eor r0, r0, r2    → r0=0x42（计算）
   0x1000: ldr r0, [r1, r4]  → r0=0x48（加载）
   ```

**验证**：`0x48 ^ 0x0A = 0x42` ✅

### 技巧2：对比多次循环迭代

**目的**：确认算法在每次迭代中的一致性

**方法**：
1. 记录第1次迭代（i=0）的指令和值
2. 跳转到第2次迭代（i=1）
3. 对比寄存器值的变化：
   - r4: `0x00 → 0x01` ✅（索引递增）
   - r0: `0x48 → 0x65` ✅（不同输入）
   - r2: `0x0A → 0x0A` ✅（密钥不变）

### 技巧3：识别复杂加密算法

**特征识别**：

| 算法 | 特征指令 | 循环次数 | 关键常数 |
|------|---------|---------|---------|
| XOR | `eor` | 任意 | 密钥字节 |
| AES | `aese`, `aesmc` | 10/12/14轮 | 轮密钥 |
| MD5 | 大量位操作 | 64次 | 魔数表 |
| Base64 | 查表、移位 | len/3 | 编码表 |
| TEA | `add`, `xor`, `lsl` | 32轮 | delta=0x9e3779b9 |

**查找方法**：
1. 在代码面板搜索特征指令
2. 统计循环次数（通过索引最大值）
3. 查找常数（🔑 图标的寄存器）

## 📚 实战案例

### 案例1：简单XOR加密
- **函数地址**: `0x1000`
- **算法**: `output[i] = input[i] ^ key[i]`
- **识别依据**: 单个`eor`指令 + 递增索引
- **还原时间**: 5分钟

### 案例2：TEA加密
- **函数地址**: `0x2000`
- **算法**: TEA (Tiny Encryption Algorithm)
- **识别依据**: 32轮循环 + delta常数`0x9e3779b9`
- **还原时间**: 30分钟

### 案例3：AES加密
- **函数地址**: `0x3000`
- **算法**: AES-128
- **识别依据**: `aese`指令 + 10轮 + 轮密钥扩展
- **还原时间**: 1小时

## 🐛 常见问题

### Q1: 看不到寄存器值？
**A**: 寄存器值只显示在当前行附近±5行，点击该行或滚动到该行即可。

### Q2: 内存查看器显示"暂不支持"？
**A**: 当前版本需要手动从代码面板获取内存数据，从`←[0x7000]`这样的提示中提取。

### Q3: 如何确定循环次数？
**A**: 查看比较指令 `cmp r4, #0x10`，立即数就是循环次数。

### Q4: 如何处理嵌套循环？
**A**: 识别多个递增索引寄存器（📏↗），分别追踪它们的变化范围。

### Q5: 如何区分输入和输出指针？
**A**: 
- 输入：先`ldr`（📥）后续被使用
- 输出：最后`str`（📤）写入

## 🎯 总结

### 工作流回顾

1. ✅ **加载trace** → 定位关键函数
2. ✅ **代码面板** → 查看图标识别操作类型
3. ✅ **寄存器面板** → 识别用途和趋势
4. ✅ **检测循环** → 确定索引和边界
5. ✅ **内存查看** → 验证数据变化
6. ✅ **编写代码** → 还原算法实现

### 关键技能

- 🎨 **视觉识别**：通过图标快速判断操作类型
- 🧠 **模式识别**：识别循环、指针、密钥等模式
- 🔍 **数据追踪**：从输入到输出完整追踪
- 📝 **代码映射**：汇编指令到高级语言的映射

### 继续学习

- 📖 阅读 `ENHANCED_UI_FEATURES.md` 了解所有功能
- 🧪 使用 `examples_enhanced_taint.py` 练习污点追踪
- 🎓 参考 `docs/USER_GUIDE.md` 学习高级技巧

---

**祝你逆向成功！** 🎉

如有问题，欢迎提Issue或PR。

