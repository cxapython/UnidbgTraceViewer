#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试反向污点分析功能

验证要点：
1. taint_backward 方法能正确反向追踪值的来源
2. 结果按行号递减排序（最早的来源在前）
3. 正确识别终止条件（立即数、常量池等）
4. 候选查找功能正常工作
"""

import sys
import os

# 添加项目根目录到路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from trace_viewer.trace_parser import TraceParser, TraceEvent


def test_basic_backward_taint():
    """测试基本的反向污点分析"""
    print("=" * 60)
    print("测试1: 基本反向污点分析")
    print("=" * 60)
    
    # 创建模拟事件
    events = []
    
    # 事件0: movs r1, #4  (源头：立即数)
    ev0 = TraceEvent(
        line_no=100,
        timestamp='[1000]',
        module='libtest.so',
        module_offset='0x100',
        encoding='0x2104',
        pc=0x12023970,
        asm="movs r1, #4",
        raw='',
        writes={'r1': 4},
        reads={},
        call_id=1
    )
    events.append(ev0)
    
    # 事件1: add r2, r1, #1
    ev1 = TraceEvent(
        line_no=101,
        timestamp='[1001]',
        module='libtest.so',
        module_offset='0x102',
        encoding='0x1c49',
        pc=0x12023972,
        asm="add r2, r1, #1",
        raw='',
        writes={'r2': 5},
        reads={'r1': 4},
        call_id=1
    )
    events.append(ev1)
    
    # 事件2: mov r3, r1  (目标事件)
    ev2 = TraceEvent(
        line_no=102,
        timestamp='[1002]',
        module='libtest.so',
        module_offset='0x104',
        encoding='0x0b46',
        pc=0x12023974,
        asm="mov r3, r1",
        raw='',
        writes={'r3': 4},
        reads={'r1': 4},
        call_id=1
    )
    events.append(ev2)
    
    # 创建parser并注入事件
    parser = TraceParser()
    parser.events = events
    
    # 手动构建索引
    for idx, ev in enumerate(events):
        # 构建PC索引
        if ev.pc not in parser.addr_index:
            parser.addr_index[ev.pc] = []
        parser.addr_index[ev.pc].append(idx)
        
        # 构建寄存器读写索引
        for reg in ev.reads.keys():
            if reg not in parser.reg_read_index:
                parser.reg_read_index[reg] = []
            parser.reg_read_index[reg].append(idx)
        
        for reg in ev.writes.keys():
            if reg not in parser.reg_write_index:
                parser.reg_write_index[reg] = []
            parser.reg_write_index[reg].append(idx)
    
    # 从事件2反向追踪 r1=4 的来源
    print(f"从事件2 (行{ev2.line_no}) 反向追踪 r1=4 的来源...")
    hits = parser.taint_backward(start_idx=2, target_reg='r1', target_value=4)
    
    print(f"命中 {len(hits)} 个事件:")
    for idx in hits:
        ev = parser.events[idx]
        print(f"  行{ev.line_no}: {ev.asm}")
    
    # 验证1: 结果不为空
    assert len(hits) > 0, "反向追踪应该找到至少一个事件"
    
    # 验证2: 结果按行号递减排序（最早的在前）
    line_nos = [parser.events[idx].line_no for idx in hits]
    assert line_nos == sorted(line_nos), f"结果应按行号递增排序，实际: {line_nos}"
    
    # 验证3: 应该包含源头（事件0: movs r1, #4）
    assert 0 in hits, "应该找到源头事件 'movs r1, #4'"
    
    # 验证4: 应该包含目标事件（事件2）
    assert 2 in hits, "应该包含起点事件"
    
    print("✓ 测试通过！")
    return True


def test_find_value_candidates():
    """测试候选查找功能"""
    print("\n" + "=" * 60)
    print("测试2: 候选查找功能")
    print("=" * 60)
    
    # 创建多个相同指令的事件（模拟循环）
    events = []
    for i in range(5):
        ev = TraceEvent(
            line_no=200 + i * 10,
            timestamp=f"[{1000 + i}]",
            module='libtest.so',
            module_offset=f'0x{200+i:x}',
            encoding='0x2104',
            pc=0x12023980,
            asm="movs r1, #4",
            raw='',
            writes={'r1': 4},
            reads={},
            call_id=1
        )
        events.append(ev)
    
    parser = TraceParser()
    parser.events = events
    
    # 手动构建索引
    for idx, ev in enumerate(events):
        if ev.pc not in parser.addr_index:
            parser.addr_index[ev.pc] = []
        parser.addr_index[ev.pc].append(idx)
        for reg in ev.reads.keys():
            if reg not in parser.reg_read_index:
                parser.reg_read_index[reg] = []
            parser.reg_read_index[reg].append(idx)
        for reg in ev.writes.keys():
            if reg not in parser.reg_write_index:
                parser.reg_write_index[reg] = []
            parser.reg_write_index[reg].append(idx)
    
    # 查找所有 r1=4 的候选
    print("查找所有 r1=0x4 的候选...")
    candidates = parser.find_value_candidates('r1', 0x4)
    
    print(f"找到 {len(candidates)} 个候选:")
    for idx, ev in candidates:
        print(f"  行{ev.line_no} (时间戳{ev.timestamp}): {ev.asm}")
    
    # 验证
    assert len(candidates) == 5, f"应该找到5个候选，实际找到 {len(candidates)}"
    
    # 验证候选按索引排序
    indices = [idx for idx, _ in candidates]
    assert indices == sorted(indices), "候选应按索引排序"
    
    print("✓ 测试通过！")
    return True


def test_termination_detection():
    """测试终止条件检测"""
    print("\n" + "=" * 60)
    print("测试3: 终止条件检测")
    print("=" * 60)
    
    events = []
    
    # 立即数写入
    ev0 = TraceEvent(
        line_no=300,
        timestamp='[2000]',
        module='libtest.so',
        module_offset='0x300',
        encoding='0x2010',
        pc=0x12023990,
        asm="mov r1, #0x10",
        raw='',
        writes={'r1': 0x10},
        reads={},
        call_id=1
    )
    events.append(ev0)
    
    # 清零写入
    ev1 = TraceEvent(
        line_no=301,
        timestamp='[2001]',
        module='libtest.so',
        module_offset='0x302',
        encoding='0x4052',
        pc=0x12023992,
        asm="eor r2, r2, r2",
        raw='',
        writes={'r2': 0},
        reads={'r2': 5},  # 读取寄存器
        call_id=1
    )
    events.append(ev1)
    
    parser = TraceParser()
    parser.events = events
    
    # 手动构建索引
    for idx, ev in enumerate(events):
        if ev.pc not in parser.addr_index:
            parser.addr_index[ev.pc] = []
        parser.addr_index[ev.pc].append(idx)
        for reg in ev.reads.keys():
            if reg not in parser.reg_read_index:
                parser.reg_read_index[reg] = []
            parser.reg_read_index[reg].append(idx)
        for reg in ev.writes.keys():
            if reg not in parser.reg_write_index:
                parser.reg_write_index[reg] = []
            parser.reg_write_index[reg].append(idx)
    
    # 检测立即数
    print("检测立即数写入...")
    term0 = parser._check_backward_termination(0, 'r1')
    print(f"  事件0: {term0}")
    assert term0 and '立即数' in term0, f"应识别为立即数，实际: {term0}"
    
    # 检测清零
    print("检测清零操作...")
    term1 = parser._check_backward_termination(1, 'r2')
    print(f"  事件1: {term1}")
    assert term1 and '立即数' in term1, f"应识别为立即数(清零)，实际: {term1}"
    
    print("✓ 测试通过！")
    return True


def main():
    """运行所有测试"""
    print("开始测试反向污点分析功能...\n")
    
    try:
        test_basic_backward_taint()
        test_find_value_candidates()
        test_termination_detection()
        
        print("\n" + "=" * 60)
        print("✅ 所有测试通过！")
        print("=" * 60)
        return 0
    except AssertionError as e:
        print(f"\n❌ 测试失败: {e}")
        return 1
    except Exception as e:
        print(f"\n❌ 测试出错: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())

