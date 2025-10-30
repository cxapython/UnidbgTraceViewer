# 文档目录

欢迎使用 Trace Viewer 文档！

## 📚 文档分类

### 入门文档

- **[快速入门](QUICK_START.md)** - 5分钟快速上手指南
  - 安装和启动
  - 基础功能介绍
  - 简单示例

### 功能详解

- **[污点分析教程](TAINT_ANALYSIS.md)** - 完整的污点分析使用指南
  - 双模式污点分析（反向+前向）
  - 基础使用方法
  - 高级功能详解
  - ARM32/ARM64指令支持
  - 常见问题FAQ

### 最新功能

- **[双模式追踪](../DUAL_MODE_UPDATE.md)** - v0.3.2 反向+前向追踪
  - 反向污点分析（追踪值来源）
  - 前向污点分析（追踪污点传播）
  - 双模式UI使用说明
  - 右键菜单快捷追踪

- **[反向污点重构](../REFACTORING_SUMMARY.md)** - 反向追踪技术详解
  - 核心算法实现
  - 终止条件检测
  - 多候选选择
  - 性能优化

### 技术文档

- **[开发历史](DEVELOPMENT_HISTORY.md)** - 完整的开发与优化历史
  - v0.3.2: 反向污点分析与双模式追踪
  - v0.3.1: ARM64指令支持
  - v0.3.0: ARM32完整支持与性能优化
  - 性能提升数据
  - 后续优化计划

- **[改进总结](IMPROVEMENTS.md)** - v0.3.0 技术改进详解
  - 新增指令支持详情
  - 位图优化技术
  - 测试验证报告

- **[发布说明](RELEASE_NOTES_v0.3.0.md)** - v0.3.0 版本发布说明

### 其他文档

- **[更新日志](../CHANGELOG.md)** - 所有版本的更新历史

## 🎯 推荐阅读路径

### 新用户
1. [快速入门](QUICK_START.md) - 了解基础操作
2. [污点分析教程](TAINT_ANALYSIS.md) - 学习核心功能
3. [双模式追踪](../DUAL_MODE_UPDATE.md) - 掌握反向+前向追踪

### 进阶用户
1. [双模式追踪](../DUAL_MODE_UPDATE.md) - 深入理解双模式分析
2. [反向污点重构](../REFACTORING_SUMMARY.md) - 了解技术实现
3. [开发历史](DEVELOPMENT_HISTORY.md) - 查看完整优化记录

### 开发者
1. [反向污点重构](../REFACTORING_SUMMARY.md) - 理解反向追踪算法
2. [开发历史](DEVELOPMENT_HISTORY.md) - 了解所有版本改进
3. [改进总结](IMPROVEMENTS.md) - 查看技术细节

## 📖 快速链接

### 常见任务

- **如何追踪值的来源？** → [双模式追踪 - 反向追踪](../DUAL_MODE_UPDATE.md#1-反向追踪新增)
- **如何追踪污点传播？** → [双模式追踪 - 前向追踪](../DUAL_MODE_UPDATE.md#2-前向追踪保留)
- **支持哪些ARM指令？** → [污点分析教程 - 指令支持](TAINT_ANALYSIS.md)
- **性能优化建议？** → [开发历史 - 性能优化](DEVELOPMENT_HISTORY.md#v030-perf---大文件性能优化-2025-10-29)
- **遇到问题怎么办？** → [污点分析教程 - 常见问题](TAINT_ANALYSIS.md#常见问题)

### API 参考

所有API的详细文档都在源代码的docstring中：

- `TraceParser.taint_backward()` - 反向污点分析（值来源追踪）
- `TraceParser.taint_forward()` - 前向污点分析（污点传播）
- `TraceParser.find_value_candidates()` - 候选事件查找
- `TraceParser.advanced_taint_analysis()` - 高级污点分析
- `TaintBitmap` - 位图优化工具

## 🔄 版本说明

当前文档对应版本：**v0.3.2**

最新改进：
- 🆕 反向污点分析（追踪值来源）
- 🎨 双模式UI（反向+前向追踪）
- ✨ 多候选选择对话框
- 🎯 完善的终止条件检测

历史版本：
- v0.3.1: ARM64完整支持（98%+指令覆盖）
- v0.3.0: ARM32完整支持 + 性能优化（内存-96%）

查看 [完整更新日志](../CHANGELOG.md) 或 [开发历史](DEVELOPMENT_HISTORY.md)

## 💡 贡献文档

发现文档问题或有改进建议？欢迎：
- 提交 Issue
- 发起 Pull Request
- 联系维护者

---

**需要帮助？** 查看 [常见问题](TAINT_ANALYSIS.md#常见问题) 或提交 Issue

