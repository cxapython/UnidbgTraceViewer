# UnidbgTraceViewer 文档

欢迎使用 UnidbgTraceViewer - 强大的 Unidbg Trace 分析与可视化工具！

## 📚 快速导航

### 新手入门
- **[快速入门指南](QUICK_START.md)** - 5分钟快速上手，了解基础操作
- **[污点分析教程](TAINT_ANALYSIS.md)** - 完整的污点分析功能说明

### 核心功能

#### 双模式污点分析
- **反向追踪** - 追踪值的来源（从结果反推输入）
- **前向追踪** - 追踪污点传播路径（从输入到结果）

#### ARM 指令支持
- ✅ ARM32 完整支持（98%+ 覆盖率）
- ✅ ARM64 完整支持（包括 csel/movk/madd 等）
- ✅ Thumb/Thumb-2 指令集

#### 高级特性
- 内存污点追踪（字节级精度）
- 寄存器状态复原与展示
- 交互式代码跳转与导航
- Python 伪代码导出

## 🚀 快速开始

### 安装
```bash
pip install -e .
```

### 启动
```bash
# 命令行启动
trace-viewer trace.txt

# Python模块启动
python -m trace_viewer.app trace.txt
```

### 基础使用
```python
from trace_viewer.trace_parser import TraceParser

parser = TraceParser()
parser.parse_file("trace.txt")

# 反向追踪：查找值的来源
hits = parser.taint_backward(start_idx=1000, target_reg='r0', target_value=0x1234)

# 前向追踪：查找污点传播
hits = parser.taint_forward(start_idx=0, source_regs=['r0'], enable_memory_taint=True)
```

## 📖 详细文档

- [快速入门指南](QUICK_START.md) - 基础操作与常用功能
- [污点分析教程](TAINT_ANALYSIS.md) - 双模式污点分析详解

## 🔧 技术特性

### 性能优化
- SQLite 缓存加速大文件加载
- 增量寄存器状态缓存
- 多线程后台解析
- 位图优化（内存占用 -96%）

### 测试覆盖
- ✅ ARM32 指令测试（9个测试用例）
- ✅ ARM64 指令测试（11个测试用例）
- ✅ 反向污点测试（3个测试用例）
- ✅ 100% 测试通过率

## 💡 常见问题

**Q: 大文件加载慢？**  
A: 首次打开会建立索引并缓存，后续打开会快速加载缓存。

**Q: 污点分析没结果？**  
A: 检查是否启用了"内存污点"选项，某些污点通过内存传播。

**Q: 如何导出分析结果？**  
A: 选中多行 → 右键 → "导出伪C代码"。

## 🤝 贡献与反馈

- 提交 Issue: 报告 bug 或提出建议
- Pull Request: 贡献代码改进
- 文档改进: 帮助完善文档

## 📄 许可证

本项目采用开源许可证发布。详见项目根目录 LICENSE 文件。

---

**需要帮助？** 查看 [污点分析教程](TAINT_ANALYSIS.md) 或在 Issues 中提问。
