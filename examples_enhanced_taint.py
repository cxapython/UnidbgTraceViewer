#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
增强污点分析使用示例

展示如何使用 EnhancedTaintAnalyzer 进行更精确的污点追踪
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../..'))

from trace_viewer.trace_parser import TraceParser
from trace_viewer.enhanced_taint import (
    EnhancedTaintAnalyzer, 
    TaintPolicy,
    TaintLabel
)


def demo_basic_taint(trace_file: str):
    """基础污点分析示例"""
    print("=" * 70)
    print("示例 1: 基础污点分析 - 字节级内存追踪")
    print("=" * 70)
    
    parser = TraceParser()
    print(f"正在解析 trace 文件: {trace_file}")
    parser.parse_file(trace_file)
    print(f"✓ 解析完成，共 {len(parser.events)} 个事件\n")
    
    # 创建增强分析器
    analyzer = EnhancedTaintAnalyzer(policy=TaintPolicy.NORMAL)
    
    # 设置污点源：假设 r0 是我们关心的输入
    analyzer.add_source('reg', 'r0', 0)
    print("✓ 设置污点源: r0")
    
    # 遍历 trace 进行污点传播
    hits = []
    for i, event in enumerate(parser.events[:10000]):  # 分析前10000个事件
        propagated = False
        
        # 处理不同类型的指令
        asm = event.asm.lower()
        
        # 1. 算术/逻辑运算: add/sub/and/orr/eor/mov 等
        if any(asm.startswith(op) for op in ['add ', 'sub ', 'and ', 'orr ', 'eor ', 'mov ']):
            # 解析源寄存器和目标寄存器
            src_regs = list(event.reads.keys())
            dst_regs = list(event.writes.keys())
            
            if dst_regs:
                dst = dst_regs[0]
                is_partial = 'movk' in asm  # ARM64 movk 只修改部分位
                propagated = analyzer.propagate_reg_to_reg(i, src_regs, dst, is_partial)
        
        # 2. 加载指令: ldr/ldrb/ldrh
        elif asm.startswith('ldr'):
            if event.effaddr is not None and event.writes:
                dst_reg = list(event.writes.keys())[0]
                mem_size = event.mem_width or 4
                propagated = analyzer.propagate_mem_to_reg(i, event.effaddr, mem_size, dst_reg)
        
        # 3. 存储指令: str/strb/strh
        elif asm.startswith('str'):
            if event.effaddr is not None and event.reads:
                src_reg = list(event.reads.keys())[0]
                mem_size = event.mem_width or 4
                propagated = analyzer.propagate_reg_to_mem(i, src_reg, event.effaddr, mem_size)
        
        # 4. 条件分支: 检测隐式流
        elif any(asm.startswith(op) for op in ['cmp ', 'tst ', 'b.eq', 'b.ne']):
            cond_regs = list(event.reads.keys())
            analyzer.propagate_implicit_flow(i, cond_regs)
        
        if propagated:
            hits.append(i)
    
    print(f"\n✓ 分析完成，发现 {len(hits)} 个污点传播事件")
    print(f"✓ 污点汇合点: {len(analyzer.get_confluence_points())} 个")
    
    # 显示前10个污点传播
    print("\n前10个污点传播事件:")
    for idx in hits[:10]:
        event = parser.events[idx]
        print(f"  [{idx:6d}] 0x{event.pc:08x}: {event.asm}")
    
    # 显示污点汇合点
    confluence = analyzer.get_confluence_points()
    if confluence:
        print(f"\n污点汇合点（多个污点来源合并）:")
        for event_idx, sources_list in list(confluence.items())[:3]:
            event = parser.events[event_idx]
            print(f"  事件 {event_idx}: {event.asm}")
            for sources in sources_list:
                source_ids = [f"{t}:{s}" for t, s in sources]
                print(f"    合并来源: {', '.join(source_ids)}")


def demo_taint_labels(trace_file: str):
    """污点标签追踪示例"""
    print("\n" + "=" * 70)
    print("示例 2: 污点标签系统 - 追踪污点来源")
    print("=" * 70)
    
    analyzer = EnhancedTaintAnalyzer()
    
    # 设置多个污点源
    analyzer.add_source('reg', 'r0', 0)
    analyzer.add_source('reg', 'r1', 0)
    analyzer.add_source('mem', '0x8000', 0)
    print("✓ 设置多个污点源: r0, r1, mem[0x8000]")
    
    # 模拟一些污点传播（简化示例）
    analyzer.propagate_reg_to_reg(100, ['r0'], 'r2')
    analyzer.propagate_reg_to_reg(200, ['r1'], 'r3')
    analyzer.propagate_reg_to_reg(300, ['r2', 'r3'], 'r4')  # 污点汇合
    
    print("\n✓ 模拟污点传播链:")
    print("  事件 100: r0 -> r2")
    print("  事件 200: r1 -> r3")
    print("  事件 300: r2 + r3 -> r4 (汇合点)")
    
    # 查看 r4 的污点来源
    sources = analyzer.get_taint_sources('r4')
    print(f"\n✓ r4 的污点来源:")
    for source_type, source_id, event_idx in sources:
        print(f"  - {source_type}:{source_id} (来自事件 {event_idx})")
    
    # 查看传播链
    chain = analyzer.get_propagation_chain('r4')
    print(f"\n✓ r4 的传播链 (共 {len(chain)} 步):")
    for event_idx, desc in chain:
        print(f"  事件 {event_idx}: {desc}")


def demo_policy_comparison(trace_file: str):
    """不同策略对比示例"""
    print("\n" + "=" * 70)
    print("示例 3: 污点策略对比 - STRICT vs NORMAL vs LOOSE")
    print("=" * 70)
    
    parser = TraceParser()
    parser.parse_file(trace_file)
    
    policies = [TaintPolicy.STRICT, TaintPolicy.NORMAL, TaintPolicy.LOOSE]
    results = {}
    
    for policy in policies:
        analyzer = EnhancedTaintAnalyzer(policy=policy)
        analyzer.add_source('reg', 'r0', 0)
        
        hits = 0
        for i, event in enumerate(parser.events[:5000]):
            asm = event.asm.lower()
            
            # 显式数据流
            if asm.startswith(('add ', 'mov ')) and event.reads and event.writes:
                src_regs = list(event.reads.keys())
                dst_reg = list(event.writes.keys())[0]
                if analyzer.propagate_reg_to_reg(i, src_regs, dst_reg):
                    hits += 1
            
            # 隐式流（条件分支）
            if asm.startswith(('cmp ', 'beq ', 'bne ')):
                if policy != TaintPolicy.STRICT:
                    cond_regs = list(event.reads.keys())
                    analyzer.propagate_implicit_flow(i, cond_regs)
                    if any(analyzer.is_reg_tainted(r) for r in cond_regs):
                        hits += 1
        
        results[policy.value] = hits
    
    print("\n✓ 不同策略检测到的污点传播:")
    for policy_name, hit_count in results.items():
        print(f"  {policy_name:10s}: {hit_count:5d} 个事件")
    
    print("\n说明:")
    print("  - STRICT : 只追踪显式数据流（最精确，可能漏报）")
    print("  - NORMAL : 包含常见隐式流（平衡）")
    print("  - LOOSE  : 包含所有可能路径（最全面，可能误报）")


def demo_byte_level_memory(trace_file: str):
    """字节级内存污点示例"""
    print("\n" + "=" * 70)
    print("示例 4: 字节级内存污点 - 精确追踪内存访问")
    print("=" * 70)
    
    analyzer = EnhancedTaintAnalyzer()
    
    # 模拟：r0 污染，然后存储到内存
    analyzer.add_source('reg', 'r0', 0)
    
    # 假设在事件100，r0 的值被存储到 0x1000
    mem_addr = 0x1000
    analyzer.propagate_reg_to_mem(100, 'r0', mem_addr, 4)
    
    print(f"✓ 模拟: r0 (污染) -> 存储到内存 [0x{mem_addr:x}] (4字节)")
    
    # 检查不同范围的污点状态
    test_ranges = [
        (0x1000, 4, "完整范围"),
        (0x1000, 1, "第1字节"),
        (0x1002, 1, "第3字节"),
        (0x1004, 1, "超出范围"),
        (0x0FFF, 2, "跨边界")
    ]
    
    print(f"\n✓ 字节级污点检测:")
    for addr, size, desc in test_ranges:
        is_tainted = analyzer.mem_taints.is_tainted(addr, size)
        status = "✓ 污染" if is_tainted else "✗ 干净"
        print(f"  [0x{addr:04x}, {size}字节] {desc:12s} : {status}")
    
    print("\n说明: 字节级追踪可以精确识别哪些字节被污染")


def main():
    """主函数"""
    if len(sys.argv) < 2:
        print("用法: python enhanced_taint_demo.py <trace文件>")
        print("\n如果没有trace文件，将运行模拟示例（不需要实际文件）\n")
        
        # 运行不需要实际trace文件的示例
        print("=" * 70)
        print("运行模拟示例（不需要trace文件）")
        print("=" * 70)
        
        demo_taint_labels("")
        demo_byte_level_memory("")
        
        print("\n" + "=" * 70)
        print("提示: 使用实际trace文件可以运行完整示例:")
        print("  python enhanced_taint_demo.py your_trace.txt")
        print("=" * 70)
        return
    
    trace_file = sys.argv[1]
    
    if not os.path.exists(trace_file):
        print(f"错误: 文件不存在: {trace_file}")
        return 1
    
    try:
        demo_basic_taint(trace_file)
        demo_taint_labels(trace_file)
        demo_policy_comparison(trace_file)
        demo_byte_level_memory(trace_file)
        
        print("\n" + "=" * 70)
        print("✓ 所有示例运行完成!")
        print("=" * 70)
        
    except Exception as e:
        print(f"\n✗ 错误: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == '__main__':
    sys.exit(main())

