# 快速入门指南

5分钟快速上手 Trace Viewer！

## 安装

```bash
pip install -e .
```

## 启动

```bash
# 方式1：使用命令行工具
trace-viewer trace.txt

# 方式2：使用Python模块
python3 -m trace_viewer.app trace.txt

# 方式3：不带参数启动，在GUI中打开文件
trace-viewer
```

## 基础功能

### 1. 浏览Trace

- **函数列表**：左侧显示所有函数候选（分支目标）
- **代码窗口**：中间显示反汇编代码，可点击地址跳转
- **寄存器窗口**：右侧显示当前行的寄存器状态

### 2. 污点分析（简单）

1. 在代码窗口找到感兴趣的指令
2. 右键 → "值流追踪"
3. 在右侧面板输入源污点：`r0` 或 `0x8000`
4. 点击"污点前向分析"
5. 双击结果跳转到相关指令

### 3. 污点分析（高级）

1. 勾选"高级模式"
2. **源**：输入起始污点 `r0,r1`
3. **目标**：输入目标寄存器 `r5`（可选）
4. 启用选项：
   - ☑ 内存污点
   - ☑ 跟踪常量
5. 点击"污点前向分析"
6. 查看详细统计信息

## 快捷键

- `Ctrl + =` 放大字体
- `Ctrl + -` 缩小字体

## Python API 示例

```python
from trace_viewer.trace_parser import TraceParser

# 解析trace
parser = TraceParser()
parser.parse_file("trace.txt")

# 污点分析
hits = parser.taint_forward(
    start_idx=0,
    source_regs=['r0'],
    enable_memory_taint=True
)

print(f"发现 {len(hits)} 个污点传播事件")
```

## 常见问题

### Q: 大文件打开很慢？
A: 首次打开会建立索引，之后会使用缓存加速。

### Q: 污点分析没有结果？
A: 检查是否启用了"内存污点"选项，某些污点通过内存传播。

### Q: 如何导出结果？
A: 选中多行 → 右键 → "导出伪C代码"

## 下一步

- 详细的污点分析教程：[TAINT_ANALYSIS.md](TAINT_ANALYSIS.md)
- 版本改进说明：[IMPROVEMENTS.md](IMPROVEMENTS.md)
- 完整更新日志：[../CHANGELOG.md](../CHANGELOG.md)

