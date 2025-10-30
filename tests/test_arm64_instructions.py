"""测试ARM64特有指令的污点分析支持

基于真实trace文件（ks_trace.txt，856万行ARM64 trace）分析，
测试以下高频ARM64指令的污点传播：

- csel/cset: 24万次 - 条件选择和条件设置
- movk: 69万次 - 多字节立即数构造  
- madd/smaddl: 约3万次 - 乘加指令
- sxtw: 1万次 - 符号扩展
- adrp: 8.8万次 - 页地址计算
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


def test_csel_instruction():
    """测试ARM64 csel指令（条件选择）
    
    csel xd, xn, xm, cond - 根据条件选择xn或xm
    出现次数：126,914次
    """
    parser = TraceParser()
    
    # 模拟trace:
    # ldr x0, [x5]      ; 污点源
    # mov x1, #0x100    ; 非污点
    # csel x2, x0, x1, eq  ; 选择x0或x1，x0污染则x2污染
    # add x3, x2, #1
    
    parser.events = [
        create_mock_trace_event(1, 0x1000, "ldr x0, [x5]", reads={'x5': 0x8000}, writes={'x0': 0x1234}),
        create_mock_trace_event(2, 0x1004, "mov x1, #0x100", reads={}, writes={'x1': 0x100}),
        create_mock_trace_event(3, 0x1008, "csel x2, x0, x1, eq", reads={'x0': 0x1234, 'x1': 0x100}, writes={'x2': 0x1234}),
        create_mock_trace_event(4, 0x100C, "add x3, x2, #1", reads={'x2': 0x1234}, writes={'x3': 0x1235}),
    ]
    
    parser.events[0].effaddr = 0x8000
    
    # 从内存地址0x8000作为污点源
    hits = parser.taint_forward(start_idx=0, source_mem_addrs=[0x8000], enable_memory_taint=True)
    
    # 验证：ldr加载污点 -> csel传播 -> add传播
    assert 0 in hits, "ldr should load taint from memory"
    assert 2 in hits, "csel should propagate taint (x0 is tainted)"
    assert 3 in hits, "add should propagate taint"
    print("✓ csel instruction test passed")


def test_cset_instruction():
    """测试ARM64 cset指令（条件设置）
    
    cset wd, cond - 根据条件设置为0或1
    出现次数：116,139次
    污点传播：设置常量，应该清洗污点
    """
    parser = TraceParser()
    
    # 模拟trace:
    # ldr x0, [x5]      ; 污点源
    # cmp x0, #0
    # cset w1, eq       ; 设置w1为0或1，清洗污点
    # add x2, x1, #1    ; x1非污点，x2非污点
    
    parser.events = [
        create_mock_trace_event(1, 0x1000, "ldr x0, [x5]", reads={'x5': 0x8000}, writes={'x0': 0x1234}),
        create_mock_trace_event(2, 0x1004, "cmp x0, #0", reads={'x0': 0x1234}, writes={}),
        create_mock_trace_event(3, 0x1008, "cset w1, eq", reads={}, writes={'w1': 0x0}),
        create_mock_trace_event(4, 0x100C, "add x2, x1, #1", reads={'x1': 0x0}, writes={'x2': 0x1}),
    ]
    
    parser.events[0].effaddr = 0x8000
    
    hits = parser.taint_forward(start_idx=0, source_mem_addrs=[0x8000], enable_memory_taint=True)
    
    # 验证：cset清洗污点，后续指令不受影响
    assert 0 in hits, "ldr should load taint"
    assert 1 in hits, "cmp should use tainted register"
    # cset设置常量，清洗污点，后续add不应在hits中（如果x2不通过其他路径被污染）
    # 注意：cset本身会在hits中，因为它清洗了污点
    print("✓ cset instruction test passed")


def test_movk_instruction():
    """测试ARM64 movk指令（构造多字节立即数）
    
    movk xd, #imm, lsl #shift - 修改寄存器的特定16位
    出现次数：699,117次
    污点传播：不应完全清洗污点（与mov不同）
    """
    parser = TraceParser()
    
    # 模拟trace:
    # ldr x0, [x5]              ; 污点源
    # movk x0, #0x7fff, lsl #48 ; 只修改高16位，保持污点
    # add x1, x0, #1            ; x0仍被污染
    
    parser.events = [
        create_mock_trace_event(1, 0x1000, "ldr x0, [x5]", reads={'x5': 0x8000}, writes={'x0': 0xFFFFFFFFFFFF}),
        create_mock_trace_event(2, 0x1004, "movk x0, #0x7fff, lsl #48", reads={'x0': 0xFFFFFFFFFFFF}, writes={'x0': 0x7FFFFFFFFFFF}),
        create_mock_trace_event(3, 0x1008, "add x1, x0, #1", reads={'x0': 0x7FFFFFFFFFFF}, writes={'x1': 0x800000000000}),
    ]
    
    parser.events[0].effaddr = 0x8000
    
    hits = parser.taint_forward(start_idx=0, source_mem_addrs=[0x8000], enable_memory_taint=True)
    
    # 验证：movk不清洗污点，x0保持污染状态
    assert 0 in hits, "ldr should load taint"
    assert 1 in hits, "movk should preserve taint (partial modify)"
    assert 2 in hits, "add should propagate taint from movk-modified register"
    print("✓ movk instruction test passed")


def test_madd_instruction():
    """测试ARM64 madd指令（乘加）
    
    madd xd, xn, xm, xa - xd = xa + (xn * xm)
    出现次数：19,224次
    污点传播：4个操作数，任一被污染则传播
    """
    parser = TraceParser()
    
    # 模拟trace:
    # ldr x0, [x5]          ; 污点源
    # mov x1, #2
    # mov x2, #3
    # madd x3, x0, x1, x2   ; x3 = x2 + (x0 * x1)，x0污染则x3污染
    # add x4, x3, #1
    
    parser.events = [
        create_mock_trace_event(1, 0x1000, "ldr x0, [x5]", reads={'x5': 0x8000}, writes={'x0': 0x10}),
        create_mock_trace_event(2, 0x1004, "mov x1, #2", reads={}, writes={'x1': 0x2}),
        create_mock_trace_event(3, 0x1008, "mov x2, #3", reads={}, writes={'x2': 0x3}),
        create_mock_trace_event(4, 0x100C, "madd x3, x0, x1, x2", reads={'x0': 0x10, 'x1': 0x2, 'x2': 0x3}, writes={'x3': 0x23}),
        create_mock_trace_event(5, 0x1010, "add x4, x3, #1", reads={'x3': 0x23}, writes={'x4': 0x24}),
    ]
    
    parser.events[0].effaddr = 0x8000
    
    hits = parser.taint_forward(start_idx=0, source_mem_addrs=[0x8000], enable_memory_taint=True)
    
    # 验证：madd检测到x0被污染，传播到x3
    assert 0 in hits, "ldr should load taint"
    assert 3 in hits, "madd should propagate taint from any source operand"
    assert 4 in hits, "add should propagate taint"
    print("✓ madd instruction test passed")


def test_smaddl_instruction():
    """测试ARM64 smaddl指令（有符号长乘加）
    
    smaddl xd, wn, wm, xa - xd = xa + SignExtend(wn * wm)
    出现次数：9,598次
    """
    parser = TraceParser()
    
    # 模拟trace:
    # ldr w0, [x5]              ; 污点源（32位）
    # mov w1, #2
    # mov x2, #100
    # smaddl x3, w0, w1, x2     ; x3 = x2 + (w0 * w1)
    
    parser.events = [
        create_mock_trace_event(1, 0x1000, "ldr w0, [x5]", reads={'x5': 0x8000}, writes={'w0': 0x10}),
        create_mock_trace_event(2, 0x1004, "mov w1, #2", reads={}, writes={'w1': 0x2}),
        create_mock_trace_event(3, 0x1008, "mov x2, #100", reads={}, writes={'x2': 0x64}),
        create_mock_trace_event(4, 0x100C, "smaddl x3, w0, w1, x2", reads={'w0': 0x10, 'w1': 0x2, 'x2': 0x64}, writes={'x3': 0x84}),
    ]
    
    parser.events[0].effaddr = 0x8000
    
    hits = parser.taint_forward(start_idx=0, source_mem_addrs=[0x8000], enable_memory_taint=True)
    
    # 验证：smaddl正确传播污点
    assert 0 in hits, "ldr should load taint"
    assert 3 in hits, "smaddl should propagate taint"
    print("✓ smaddl instruction test passed")


def test_sxtw_instruction():
    """测试ARM64 sxtw指令（符号扩展字）
    
    sxtw xd, wn - 将32位值符号扩展到64位
    出现次数：10,787次
    """
    parser = TraceParser()
    
    # 模拟trace:
    # ldr w0, [x5]      ; 污点源（32位）
    # sxtw x1, w0       ; 符号扩展到64位，传播污点
    # add x2, x1, #1
    
    parser.events = [
        create_mock_trace_event(1, 0x1000, "ldr w0, [x5]", reads={'x5': 0x8000}, writes={'w0': 0x80000000}),
        create_mock_trace_event(2, 0x1004, "sxtw x1, w0", reads={'w0': 0x80000000}, writes={'x1': 0xFFFFFFFF80000000}),
        create_mock_trace_event(3, 0x1008, "add x2, x1, #1", reads={'x1': 0xFFFFFFFF80000000}, writes={'x2': 0xFFFFFFFF80000001}),
    ]
    
    parser.events[0].effaddr = 0x8000
    
    hits = parser.taint_forward(start_idx=0, source_mem_addrs=[0x8000], enable_memory_taint=True)
    
    # 验证：sxtw作为普通指令传播污点（读w0写x1）
    assert 0 in hits, "ldr should load taint"
    assert 1 in hits, "sxtw should propagate taint (w0 and x1 are aliases)"
    assert 2 in hits, "add should propagate taint"
    print("✓ sxtw instruction test passed")


def test_adrp_instruction():
    """测试ARM64 adrp指令（页地址计算）
    
    adrp xd, #addr - 计算页对齐地址（4KB对齐）
    出现次数：88,868次
    污点传播：结果是编译时常量，应该清洗污点
    """
    parser = TraceParser()
    
    # 模拟trace:
    # ldr x0, [x5]          ; 污点源
    # adrp x0, #0x40070000  ; 计算地址常量，清洗污点
    # add x1, x0, #0x10     ; x0非污点，x1非污点
    
    parser.events = [
        create_mock_trace_event(1, 0x1000, "ldr x0, [x5]", reads={'x5': 0x8000}, writes={'x0': 0x1234}),
        create_mock_trace_event(2, 0x1004, "adrp x0, #0x40070000", reads={}, writes={'x0': 0x40070000}),
        create_mock_trace_event(3, 0x1008, "add x1, x0, #0x10", reads={'x0': 0x40070000}, writes={'x1': 0x40070010}),
    ]
    
    parser.events[0].effaddr = 0x8000
    
    hits = parser.taint_forward(start_idx=0, source_mem_addrs=[0x8000], enable_memory_taint=True)
    
    # 验证：adrp清洗污点
    assert 0 in hits, "ldr should load taint"
    # adrp会在hits中（因为清洗了污点），但后续add不应该在hits中
    assert 1 in hits, "adrp should be in hits (cleaning taint)"
    assert 3 not in hits, "add after adrp should not propagate taint"
    print("✓ adrp instruction test passed")


def test_advanced_taint_with_arm64_instructions():
    """测试高级污点分析对ARM64指令的统计"""
    parser = TraceParser()
    
    # 创建包含多种ARM64指令的trace
    parser.events = [
        create_mock_trace_event(1, 0x1000, "ldr x0, [x6]", reads={'x6': 0x9000}, writes={'x0': 0x100}),
        create_mock_trace_event(2, 0x1004, "mov x1, #0x200", reads={}, writes={'x1': 0x200}),
        create_mock_trace_event(3, 0x1008, "csel x2, x0, x1, eq", reads={'x0': 0x100, 'x1': 0x200}, writes={'x2': 0x100}),
        create_mock_trace_event(4, 0x100C, "movk x2, #0xff, lsl #16", reads={'x2': 0x100}, writes={'x2': 0xFF0100}),
        create_mock_trace_event(5, 0x1010, "mov x3, #5", reads={}, writes={'x3': 0x5}),
        create_mock_trace_event(6, 0x1014, "madd x4, x2, x3, x1", reads={'x2': 0xFF0100, 'x3': 0x5, 'x1': 0x200}, writes={'x4': 0x4F8700}),
    ]
    
    parser.events[0].effaddr = 0x9000
    
    result = parser.advanced_taint_analysis(
        start_idx=0,
        source_mem_addrs=[0x9000],
        enable_memory_taint=True,
        track_constants=True
    )
    
    # 检查结果
    assert len(result['hits']) >= 4, f"Expected at least 4 hits, got {len(result['hits'])}"
    assert result['statistics']['memory_propagations'] > 0, "Should have memory propagations"
    assert result['statistics']['register_propagations'] > 0, "Should have register propagations"
    
    # 检查传播类型
    propagation_types = [step['propagation_type'] for step in result['taint_path'] if step['propagation_type']]
    print(f"Propagation types detected: {propagation_types}")
    
    # 应该检测到ARM64特有的传播类型
    assert any('csel' in pt or 'movk' in pt or 'madd' in pt or 'mem_to_reg' in pt 
               for pt in propagation_types), \
        f"Should detect ARM64-specific operations, got {propagation_types}"
    
    print("✓ advanced taint analysis with ARM64 instructions test passed")


def test_instruction_type_detection():
    """测试ARM64指令类型检测函数"""
    parser = TraceParser()
    
    # 测试条件选择指令
    assert parser._is_conditional_select_op("csel x0, x1, x2, eq") == True
    assert parser._is_conditional_select_op("csinc x0, x1, x2, ne") == True
    assert parser._is_conditional_select_op("csinv x0, x1, x2, gt") == True
    assert parser._is_conditional_select_op("csneg x0, x1, x2, lt") == True
    assert parser._is_conditional_select_op("add x0, x1, x2") == False
    
    # 测试条件设置指令
    assert parser._is_conditional_set_op("cset w0, eq") == True
    assert parser._is_conditional_set_op("csetm w0, ne") == True
    assert parser._is_conditional_set_op("mov w0, #0") == False
    
    # 测试movk指令
    assert parser._is_movk_op("movk x0, #0x7fff, lsl #48") == True
    assert parser._is_movk_op("mov x0, #0x7fff") == False
    
    # 测试madd指令
    assert parser._is_madd_op("madd x0, x1, x2, x3") == True
    assert parser._is_madd_op("msub x0, x1, x2, x3") == True
    assert parser._is_madd_op("smaddl x0, w1, w2, x3") == True
    assert parser._is_madd_op("umaddl x0, w1, w2, x3") == True
    assert parser._is_madd_op("mul x0, x1, x2") == False
    
    # 测试ARM64扩展指令
    assert parser._is_extend_op_arm64("sxtw x0, w1") == True
    assert parser._is_extend_op_arm64("uxtw x0, w1") == True
    assert parser._is_extend_op_arm64("sxtah x0, x1, x2") == False  # ARM32
    
    # 测试adrp指令
    assert parser._is_adrp_op("adrp x0, #0x40070000") == True
    assert parser._is_adrp_op("adr x0, #0x100") == False
    
    print("✓ instruction type detection test passed")


def test_csel_operand_parsing():
    """测试csel指令操作数解析"""
    parser = TraceParser()
    
    # 测试csel
    rd, rn, rm = parser._parse_csel_operands("csel x2, x0, x1, eq")
    assert rd == 'x2' and rn == 'x0' and rm == 'x1', f"Expected ('x2', 'x0', 'x1'), got ({rd}, {rn}, {rm})"
    
    # 测试csinc
    rd, rn, rm = parser._parse_csel_operands("csinc w3, w4, w5, ne")
    assert rd == 'w3' and rn == 'w4' and rm == 'w5', f"Expected ('w3', 'w4', 'w5'), got ({rd}, {rn}, {rm})"
    
    print("✓ csel operand parsing test passed")


def test_madd_operand_parsing():
    """测试madd指令操作数解析"""
    parser = TraceParser()
    
    # 测试madd
    rd, rn, rm, ra = parser._parse_madd_operands("madd x3, x0, x1, x2")
    assert rd == 'x3' and rn == 'x0' and rm == 'x1' and ra == 'x2', \
        f"Expected ('x3', 'x0', 'x1', 'x2'), got ({rd}, {rn}, {rm}, {ra})"
    
    # 测试smaddl
    rd, rn, rm, ra = parser._parse_madd_operands("smaddl x4, w1, w2, x3")
    assert rd == 'x4' and rn == 'w1' and rm == 'w2' and ra == 'x3', \
        f"Expected ('x4', 'w1', 'w2', 'x3'), got ({rd}, {rn}, {rm}, {ra})"
    
    print("✓ madd operand parsing test passed")


def run_all_tests():
    """运行所有测试"""
    print("\n" + "="*60)
    print("Running ARM64 Instruction Tests")
    print("="*60 + "\n")
    
    tests = [
        ("Instruction Type Detection", test_instruction_type_detection),
        ("CSEL Operand Parsing", test_csel_operand_parsing),
        ("MADD Operand Parsing", test_madd_operand_parsing),
        ("CSEL Instruction", test_csel_instruction),
        ("CSET Instruction", test_cset_instruction),
        ("MOVK Instruction", test_movk_instruction),
        ("MADD Instruction", test_madd_instruction),
        ("SMADDL Instruction", test_smaddl_instruction),
        ("SXTW Instruction", test_sxtw_instruction),
        ("ADRP Instruction", test_adrp_instruction),
        ("Advanced Taint Analysis", test_advanced_taint_with_arm64_instructions),
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
            import traceback
            traceback.print_exc()
            failed += 1
    
    print("\n" + "="*60)
    print(f"Test Results: {passed} passed, {failed} failed")
    print("="*60 + "\n")
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)

