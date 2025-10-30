# Unidbg Trace 可视化工具（Python 3.8 / PyQt5）

## 主要功能
- 三联动：函数列表 / 代码窗口 / 寄存器窗口（始终显示全部寄存器）
- 代码行前缀：时间戳 + PC 地址，便于定位第几次运行
- 值流追踪：
  - 寄存器/地址/范围检索；作用域（全局/调用#/PC范围）
  - 值匹配（执行前/执行后/任意）与“追踪值路径”（倒排索引，链路快速）
  - 右键“指定值追踪”：在代码区选择寄存器并填写值（如 `0xfffffffb`）直接得到链路
- 内存写入对比：`str*/ldr*` 有效地址的前后字节差异视图

## 启动
```bash
python3.8 -m trace_viewer.app /path/to/fanqie_trace.txt
```

## 解析说明
- 行格式：`[ts][module 0xOFF] [ENC] 0xPC: "ASM" rX=0x.. => rY=0x..`
- 自动索引：PC→事件列表；分支目标→函数候选；读/写寄存器→倒排索引
- 快照：每 N 行保存寄存器快照，加速复原
- 有效地址：支持 `[rB]` / `[rB,#imm]` / `[rB,rX,lsl #s]`

## 快捷键
- Ctrl+= / Ctrl+-：调整代码字体

## 目录
- `trace_viewer/trace_parser.py`：解析/索引/倒排/快速链路
- `trace_viewer/app.py`：GUI 主程序与右键追踪
- `trace_viewer/value_flow.py`：值流面板与导出
- `trace_viewer/mem_diff.py`：内存差异视图


