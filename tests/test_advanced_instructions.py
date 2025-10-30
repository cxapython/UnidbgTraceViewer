"""测试高级ARM32指令的污点分析支持

测试覆盖的指令：
- sxtah: 符号扩展半字并加法
- orn: 或非运算
- umull: 无符号长乘法
- strd/ldrd: 双字存储/加载
- push/pop: 多寄存器栈操作
- stm/ldm: 多寄存器批量访存
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from trace_viewer.trace_parser import TraceParser, TraceEvent


def create_mock_trace_event(line_no, pc, asm, reads=None, writes=None):
    """创建模拟的TraceEvent"""
    return TraceEvent(
        line_no=line_no,
        timestamp="00:00:00",
        module="libtest.so",
        module_offset="0x1000",
        encoding="12345678",
        pc=pc,
        asm=asm,
        raw=f"[00:00:00] {hex(pc)}: \"{asm}\"",
        reads=reads or {},
        writes=writes or {}
    )


def test_sxtah_instruction():
    """测试sxtah指令（符号扩展半字并加法）"""
    parser = TraceParser()
    
    # 模拟trace: 
    # ldr r0, [r5]  ; 污点源（从污点内存加载）
    # sxtah r1, r0, r2  ; r1 = r0 + SignExtend16(r2)
    # mov r3, r1
    
    parser.events = [
        create_mock_trace_event(1, 0x1000, "ldr r0, [r5]", reads={'r5': 0x8000}, writes={'r0': 0x1234}),
        create_mock_trace_event(2, 0x1004, "sxtah r1, r0, r2", reads={'r0': 0x1234, 'r2': 0x5678}, writes={'r1': 0x6000}),
        create_mock_trace_event(3, 0x1008, "mov r3, r1", reads={'r1': 0x6000}, writes={'r3': 0x6000}),
    ]
    
    parser.events[0].effaddr = 0x8000
    
    # 从内存地址0x8000作为污点源进行前向分析
    hits = parser.taint_forward(start_idx=0, source_mem_addrs=[0x8000], enable_memory_taint=True)
    
    # 验证：ldr加载污点、sxtah传播、mov传播都应被检测
    assert len(hits) >= 2, f"Expected at least 2 hits for sxtah propagation, got {len(hits)}: {hits}"
    assert 0 in hits, "ldr should load taint from memory"
    assert 1 in hits, "sxtah instruction should be in taint path"
    print("✓ sxtah instruction test passed")


def test_orn_instruction():
    """测试orn指令（或非运算）"""
    parser = TraceParser()
    
    # 模拟trace:
    # ldr r0, [r5]  ; 污点源
    # orn r1, r0, r2  ; r1 = r0 | ~r2
    # add r3, r1, #1
    
    parser.events = [
        create_mock_trace_event(1, 0x1000, "ldr r0, [r5]", reads={'r5': 0x8000}, writes={'r0': 0xFF}),
        create_mock_trace_event(2, 0x1004, "orn r1, r0, r2", reads={'r0': 0xFF, 'r2': 0x0F}, writes={'r1': 0xF0}),
        create_mock_trace_event(3, 0x1008, "add r3, r1, #1", reads={'r1': 0xF0}, writes={'r3': 0xF1}),
    ]
    
    parser.events[0].effaddr = 0x8000
    
    hits = parser.taint_forward(start_idx=0, source_mem_addrs=[0x8000], enable_memory_taint=True)
    
    # orn应该传播污点
    assert 0 in hits, "ldr should load taint"
    assert 1 in hits, "orn instruction should propagate taint"
    assert 2 in hits, "subsequent add should also be tainted"
    print("✓ orn instruction test passed")


def test_umull_instruction():
    """测试umull指令（无符号长乘法）"""
    parser = TraceParser()
    
    # 模拟trace:
    # ldr r0, [r5]  ; 污点源
    # umull r2, r3, r0, r1  ; {r3,r2} = r0 * r1 (64-bit result)
    # add r4, r2, #1
    # add r5, r3, #1
    
    parser.events = [
        create_mock_trace_event(1, 0x1000, "ldr r0, [r5]", reads={'r5': 0x8000}, writes={'r0': 0x1000}),
        create_mock_trace_event(2, 0x1004, "umull r2, r3, r0, r1", 
                               reads={'r0': 0x1000, 'r1': 0x2000}, 
                               writes={'r2': 0x00000000, 'r3': 0x00002000}),
        create_mock_trace_event(3, 0x1008, "add r4, r2, #1", reads={'r2': 0x0}, writes={'r4': 0x1}),
        create_mock_trace_event(4, 0x100C, "add r5, r3, #1", reads={'r3': 0x2000}, writes={'r5': 0x2001}),
    ]
    
    parser.events[0].effaddr = 0x8000
    
    hits = parser.taint_forward(start_idx=0, source_mem_addrs=[0x8000], enable_memory_taint=True)
    
    # umull应该将污点传播到r2和r3两个寄存器
    assert 0 in hits, "ldr should load taint"
    assert 1 in hits, "umull should propagate taint"
    assert 2 in hits, "r2 should be tainted (low part)"
    assert 3 in hits, "r3 should be tainted (high part)"
    print("✓ umull instruction test passed")


def test_strd_ldrd_instructions():
    """测试strd/ldrd指令（双字存储/加载）"""
    parser = TraceParser()
    
    # 模拟trace:
    # ldr r0, [r6]  ; 污点源
    # mov r1, #0x200
    # strd r0, r1, [r2]  ; 存储8字节
    # ldrd r3, r4, [r2]  ; 加载8字节
    # add r5, r3, #1
    
    parser.events = [
        create_mock_trace_event(1, 0x1000, "ldr r0, [r6]", reads={'r6': 0x9000}, writes={'r0': 0x100}),
        create_mock_trace_event(2, 0x1004, "mov r1, #0x200", reads={}, writes={'r1': 0x200}),
        create_mock_trace_event(3, 0x1008, "strd r0, r1, [r2]", 
                               reads={'r0': 0x100, 'r1': 0x200, 'r2': 0x8000}, writes={}),
        create_mock_trace_event(4, 0x100C, "ldrd r3, r4, [r2]", 
                               reads={'r2': 0x8000}, writes={'r3': 0x100, 'r4': 0x200}),
        create_mock_trace_event(5, 0x1010, "add r5, r3, #1", reads={'r3': 0x100}, writes={'r5': 0x101}),
    ]
    
    # 预计算有效地址
    parser.events[0].effaddr = 0x9000
    parser.events[2].effaddr = 0x8000
    parser.events[3].effaddr = 0x8000
    
    hits = parser.taint_forward(start_idx=0, source_mem_addrs=[0x9000], enable_memory_taint=True)
    
    # 验证污点通过内存传播
    assert 0 in hits, "ldr should load taint"
    assert 2 in hits, "strd should propagate taint to memory"
    assert 3 in hits, "ldrd should load taint from memory"
    assert 4 in hits, "subsequent operations should be tainted"
    print("✓ strd/ldrd instruction test passed")


def test_push_pop_instructions():
    """测试push/pop指令（多寄存器栈操作）"""
    parser = TraceParser()
    
    # 模拟trace:
    # ldr r0, [r6]  ; 污点源
    # mov r1, #0x200
    # push {r0-r2, lr}  ; 压栈
    # mov r0, #0  ; 清空r0
    # pop {r3-r5, pc}  ; 出栈
    # add r6, r3, #1
    
    parser.events = [
        create_mock_trace_event(1, 0x1000, "ldr r0, [r6]", reads={'r6': 0x9000}, writes={'r0': 0x100}),
        create_mock_trace_event(2, 0x1004, "mov r1, #0x200", reads={}, writes={'r1': 0x200}),
        create_mock_trace_event(3, 0x1008, "push {r0-r2, lr}", 
                               reads={'r0': 0x100, 'r1': 0x200, 'r2': 0x300, 'lr': 0x9000}, writes={}),
        create_mock_trace_event(4, 0x100C, "mov r0, #0", reads={}, writes={'r0': 0}),
        create_mock_trace_event(5, 0x1010, "pop {r3-r5, pc}", 
                               reads={}, writes={'r3': 0x100, 'r4': 0x200, 'r5': 0x300, 'pc': 0x9000}),
        create_mock_trace_event(6, 0x1014, "add r6, r3, #1", reads={'r3': 0x100}, writes={'r6': 0x101}),
    ]
    
    parser.events[0].effaddr = 0x9000
    
    hits = parser.taint_forward(start_idx=0, source_mem_addrs=[0x9000], enable_memory_taint=True)
    
    # push应该检测到污点，pop应该传播污点到新寄存器
    assert 0 in hits, "ldr should load taint"
    assert 2 in hits, "push should detect tainted register"
    # pop保守处理，如果有污点内存则传播
    assert 4 in hits, "pop should propagate taint from memory"
    print("✓ push/pop instruction test passed")


def test_register_list_parsing():
    """测试寄存器列表解析功能"""
    parser = TraceParser()
    
    # 测试单个寄存器
    regs = parser._parse_register_list("push {r0}")
    assert regs == ['r0'], f"Expected ['r0'], got {regs}"
    
    # 测试范围
    regs = parser._parse_register_list("push {r0-r3}")
    assert regs == ['r0', 'r1', 'r2', 'r3'], f"Expected ['r0', 'r1', 'r2', 'r3'], got {regs}"
    
    # 测试混合
    regs = parser._parse_register_list("push {r0-r2, lr}")
    assert 'r0' in regs and 'r1' in regs and 'r2' in regs and 'lr' in regs, \
        f"Expected r0-r2 and lr, got {regs}"
    
    # 测试复杂情况
    regs = parser._parse_register_list("stm sp!, {r4-r7, r9}")
    assert 'r4' in regs and 'r5' in regs and 'r6' in regs and 'r7' in regs and 'r9' in regs, \
        f"Expected r4-r7 and r9, got {regs}"
    
    print("✓ register list parsing test passed")


def test_dual_register_parsing():
    """测试双寄存器解析功能"""
    parser = TraceParser()
    
    # 测试strd
    reg1, reg2 = parser._parse_dual_regs("strd r0, r1, [r2]")
    assert reg1 == 'r0' and reg2 == 'r1', f"Expected ('r0', 'r1'), got ({reg1}, {reg2})"
    
    # 测试ldrd
    reg1, reg2 = parser._parse_dual_regs("ldrd r3, r4, [r5, #8]")
    assert reg1 == 'r3' and reg2 == 'r4', f"Expected ('r3', 'r4'), got ({reg1}, {reg2})"
    
    print("✓ dual register parsing test passed")


def test_advanced_taint_with_new_instructions():
    """测试高级污点分析对新指令的统计"""
    parser = TraceParser()
    
    # 创建包含多种新指令的trace
    parser.events = [
        create_mock_trace_event(1, 0x1000, "ldr r0, [r6]", reads={'r6': 0x9000}, writes={'r0': 0x100}),
        create_mock_trace_event(2, 0x1004, "sxtah r1, r0, r2", reads={'r0': 0x100, 'r2': 0x50}, writes={'r1': 0x150}),
        create_mock_trace_event(3, 0x1008, "orn r2, r1, r3", reads={'r1': 0x150, 'r3': 0x0F}, writes={'r2': 0xF0}),
        create_mock_trace_event(4, 0x100C, "umull r4, r5, r2, r3", 
                               reads={'r2': 0xF0, 'r3': 0x10}, 
                               writes={'r4': 0xF00, 'r5': 0x0}),
    ]
    
    parser.events[0].effaddr = 0x9000
    
    result = parser.advanced_taint_analysis(
        start_idx=0,
        source_mem_addrs=[0x9000],
        enable_memory_taint=True
    )
    
    # 检查结果
    assert len(result['hits']) >= 3, f"Expected at least 3 hits, got {len(result['hits'])}"
    assert result['statistics']['total_steps'] >= 4, "Should analyze all events"
    # 至少应该有一次内存传播（ldr从污点内存加载）
    assert result['statistics']['memory_propagations'] > 0 or result['statistics']['register_propagations'] > 0, \
        f"Should have propagations, got stats: {result['statistics']}"
    
    # 检查传播类型标注
    propagation_types = [step['propagation_type'] for step in result['taint_path'] if step['propagation_type']]
    assert len(propagation_types) > 0, f"Should have at least one propagation type, got {propagation_types}"
    assert 'extend_op' in propagation_types or 'bitwise_not_op' in propagation_types or 'reg_to_reg' in propagation_types or 'mem_to_reg' in propagation_types, \
        f"Should detect operations, got {propagation_types}"
    
    print("✓ advanced taint analysis with new instructions test passed")


def test_instruction_type_detection():
    """测试指令类型检测函数"""
    parser = TraceParser()
    
    # 测试扩展指令
    assert parser._is_extend_op("sxtah r0, r1, r2") == True
    assert parser._is_extend_op("sxtab r0, r1, r2") == True
    assert parser._is_extend_op("uxtah r0, r1, r2") == True
    assert parser._is_extend_op("add r0, r1, r2") == False
    
    # 测试位非指令
    assert parser._is_bitwise_not_op("orn r0, r1, r2") == True
    assert parser._is_bitwise_not_op("bic r0, r1, r2") == True
    assert parser._is_bitwise_not_op("mvn r0, r1") == True
    assert parser._is_bitwise_not_op("orr r0, r1, r2") == False
    
    # 测试多寄存器指令
    assert parser._is_multi_register_load_store("push {r0-r7}") == True
    assert parser._is_multi_register_load_store("pop {r0, r1}") == True
    assert parser._is_multi_register_load_store("ldm r0, {r1-r4}") == True
    assert parser._is_multi_register_load_store("stm r0!, {r1-r4}") == True
    assert parser._is_multi_register_load_store("strd r0, r1, [r2]") == True
    assert parser._is_multi_register_load_store("ldrd r0, r1, [r2]") == True
    assert parser._is_multi_register_load_store("ldr r0, [r1]") == False
    
    print("✓ instruction type detection test passed")


def run_all_tests():
    """运行所有测试"""
    print("\n" + "="*60)
    print("Running Advanced ARM32 Instruction Tests")
    print("="*60 + "\n")
    
    tests = [
        ("Register List Parsing", test_register_list_parsing),
        ("Dual Register Parsing", test_dual_register_parsing),
        ("Instruction Type Detection", test_instruction_type_detection),
        ("SXTAH Instruction", test_sxtah_instruction),
        ("ORN Instruction", test_orn_instruction),
        ("UMULL Instruction", test_umull_instruction),
        ("STRD/LDRD Instructions", test_strd_ldrd_instructions),
        ("PUSH/POP Instructions", test_push_pop_instructions),
        ("Advanced Taint Analysis", test_advanced_taint_with_new_instructions),
    ]
    
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        try:
            print(f"\nRunning: {test_name}")
            test_func()
            passed += 1
        except AssertionError as e:
            print(f"✗ {test_name} FAILED: {e}")
            failed += 1
        except Exception as e:
            print(f"✗ {test_name} ERROR: {e}")
            failed += 1
    
    print("\n" + "="*60)
    print(f"Test Results: {passed} passed, {failed} failed")
    print("="*60 + "\n")
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)

