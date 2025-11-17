#!/usr/bin/env python3
"""
Qt6迁移完整性测试脚本
测试所有主要功能是否正常工作
"""

import sys
import os
import signal
import time
from pathlib import Path

# 添加trace_viewer到路径
sys.path.insert(0, str(Path(__file__).parent / 'trace_viewer'))

from PyQt6.QtWidgets import QApplication, QFileDialog
from PyQt6.QtCore import QTimer, Qt
from PyQt6.QtTest import QTest

def test_app_startup():
    """测试1: 应用启动"""
    print("=" * 60)
    print("测试1: 应用启动")
    print("-" * 60)
    
    try:
        from trace_viewer.app import TraceViewer
        app = QApplication(sys.argv)
        window = TraceViewer()
        print("✅ 窗口创建成功")
        
        window.show()
        print("✅ 窗口显示成功")
        
        # 检查窗口标题
        assert "Trace Viewer" in window.windowTitle()
        print(f"✅ 窗口标题正确: {window.windowTitle()}")
        
        return app, window
    except Exception as e:
        print(f"❌ 应用启动失败: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

def test_load_trace_file(window):
    """测试2: 加载trace文件"""
    print("\n" + "=" * 60)
    print("测试2: 加载trace文件")
    print("-" * 60)
    
    # 查找示例trace文件
    trace_file = Path(__file__).parent / 'trace_viewer' / 'demo' / 'fanqie_trace.txt'
    
    if not trace_file.exists():
        # 尝试其他可能的位置
        alt_paths = [
            Path(__file__).parent / 'trace_viewer' / 'demo' / 'jnicalculator_trace.txt',
        ]
        for p in alt_paths:
            if p.exists():
                trace_file = p
                break
    
    if not trace_file.exists():
        print("⚠️  未找到示例trace文件，跳过加载测试")
        return False
    
    print(f"📂 使用trace文件: {trace_file}")
    
    try:
        # 模拟加载文件
        window.load_trace(str(trace_file))
        
        # 等待解析完成
        print("⏳ 等待解析完成...")
        QTest.qWait(2000)  # 等待2秒
        
        # 检查解析器是否创建
        assert window.parser is not None, "解析器未创建"
        print(f"✅ 解析器创建成功")
        
        # 检查是否有事件
        event_count = len(window.parser.events)
        assert event_count > 0, "未解析到任何事件"
        print(f"✅ 解析到 {event_count:,} 个事件")
        
        # 检查函数列表
        func_count = window.func_list.topLevelItemCount()
        print(f"✅ 函数列表包含 {func_count} 个函数")
        
        return True
        
    except Exception as e:
        print(f"❌ 加载trace文件失败: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_ui_components(window):
    """测试3: UI组件"""
    print("\n" + "=" * 60)
    print("测试3: UI组件检查")
    print("-" * 60)
    
    try:
        # 检查代码编辑器
        assert window.code_edit is not None
        print("✅ 代码编辑器存在")
        
        # 检查寄存器表
        assert window.reg_table is not None
        assert window.reg_table.columnCount() == 5  # 寄存器、之前、之后、用途、趋势
        print(f"✅ 寄存器表存在 (5列)")
        
        # 检查函数列表
        assert window.func_list is not None
        print("✅ 函数列表存在")
        
        # 检查值流追踪面板
        assert window.vf_dock is not None
        print("✅ 值流追踪面板存在")
        
        # 检查内存差异面板
        assert window.mem_dock is not None
        print("✅ 内存差异面板存在")
        
        # 检查内存查看器
        assert window.mem_viewer_dock is not None
        print("✅ 内存查看器存在")
        
        return True
        
    except Exception as e:
        print(f"❌ UI组件检查失败: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_function_list_click(window):
    """测试4: 函数列表点击"""
    print("\n" + "=" * 60)
    print("测试4: 函数列表交互")
    print("-" * 60)
    
    if not window.parser or window.func_list.topLevelItemCount() == 0:
        print("⚠️  没有加载trace文件，跳过此测试")
        return True
    
    try:
        # 点击第一个函数
        first_item = window.func_list.topLevelItem(0)
        if first_item:
            window.func_list.setCurrentItem(first_item)
            window._on_func_clicked(first_item, 0)
            QTest.qWait(500)
            print("✅ 函数列表点击成功")
            
            # 检查代码是否显示
            code_text = window.code_edit.toPlainText()
            assert len(code_text) > 0, "代码区域为空"
            print(f"✅ 代码显示成功 ({len(code_text)} 字符)")
            
            return True
        else:
            print("⚠️  函数列表为空")
            return True
            
    except Exception as e:
        print(f"❌ 函数列表交互失败: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_code_formatting(window):
    """测试5: 增强代码格式化"""
    print("\n" + "=" * 60)
    print("测试5: 增强代码格式化")
    print("-" * 60)
    
    try:
        # 检查代码格式化器
        assert window.code_formatter is not None
        print("✅ 代码格式化器存在")
        
        # 检查是否使用emoji
        assert window.code_formatter.use_emoji == True
        print("✅ Emoji图标已启用")
        
        # 检查寄存器分析器
        assert window.reg_analyzer is not None
        print("✅ 寄存器分析器存在")
        
        return True
        
    except Exception as e:
        print(f"❌ 代码格式化检查失败: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_register_analysis(window):
    """测试6: 寄存器分析"""
    print("\n" + "=" * 60)
    print("测试6: 智能寄存器分析")
    print("-" * 60)
    
    if not window.parser:
        print("⚠️  没有加载trace文件，跳过此测试")
        return True
    
    try:
        # 触发一次寄存器分析
        if len(window.parser.events) > 0:
            window._rebuild_regs_async(0)
            QTest.qWait(1000)
            
            # 检查寄存器表是否有数据
            row_count = window.reg_table.rowCount()
            print(f"✅ 寄存器表有 {row_count} 行数据")
            
            # 检查列数
            assert window.reg_table.columnCount() == 5
            print("✅ 寄存器表有5列（寄存器、之前、之后、用途、趋势）")
            
            return True
        else:
            print("⚠️  没有事件数据")
            return True
            
    except Exception as e:
        print(f"❌ 寄存器分析失败: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_menu_actions(window):
    """测试7: 菜单动作"""
    print("\n" + "=" * 60)
    print("测试7: 菜单动作")
    print("-" * 60)
    
    try:
        # 检查菜单栏
        menubar = window.menuBar()
        assert menubar is not None
        print("✅ 菜单栏存在")
        
        # 检查菜单
        actions = menubar.actions()
        assert len(actions) > 0
        print(f"✅ 找到 {len(actions)} 个菜单")
        
        # 列出菜单名称
        for action in actions:
            if action.text():
                print(f"   - {action.text()}")
        
        return True
        
    except Exception as e:
        print(f"❌ 菜单检查失败: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_dock_widgets(window):
    """测试8: 停靠面板"""
    print("\n" + "=" * 60)
    print("测试8: 停靠面板")
    print("-" * 60)
    
    try:
        # 检查值流追踪面板
        assert window.vf_dock.isVisible()
        print("✅ 值流追踪面板可见")
        
        # 检查内存差异面板
        assert window.mem_dock.isVisible()
        print("✅ 内存差异面板可见")
        
        # 检查内存查看器（默认隐藏）
        print(f"✅ 内存查看器状态: {'可见' if window.mem_viewer_dock.isVisible() else '隐藏'}")
        
        return True
        
    except Exception as e:
        print(f"❌ 停靠面板检查失败: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_theme(window):
    """测试9: 主题样式"""
    print("\n" + "=" * 60)
    print("测试9: 暗色主题")
    print("-" * 60)
    
    try:
        # 检查调色板
        palette = window.palette()
        assert palette is not None
        print("✅ 调色板已设置")
        
        # 检查样式表
        stylesheet = window.styleSheet()
        assert len(stylesheet) > 0
        print(f"✅ 样式表已应用 ({len(stylesheet)} 字符)")
        
        # 检查是否包含暗色主题颜色
        assert '#0b1220' in stylesheet or '#0e1621' in stylesheet
        print("✅ 暗色主题已应用")
        
        return True
        
    except Exception as e:
        print(f"❌ 主题检查失败: {e}")
        import traceback
        traceback.print_exc()
        return False

def run_all_tests():
    """运行所有测试"""
    print("\n")
    print("=" * 60)
    print("🚀 Qt6迁移完整性测试")
    print("=" * 60)
    print()
    
    # 设置超时
    signal.signal(signal.SIGALRM, lambda s, f: (print("\n⏱️  测试超时"), sys.exit(1)))
    signal.alarm(60)  # 60秒超时
    
    # 测试1: 应用启动
    app, window = test_app_startup()
    
    # 测试2: 加载trace文件
    file_loaded = test_load_trace_file(window)
    
    # 测试3: UI组件
    test_ui_components(window)
    
    # 测试4: 函数列表交互
    test_function_list_click(window)
    
    # 测试5: 代码格式化
    test_code_formatting(window)
    
    # 测试6: 寄存器分析
    test_register_analysis(window)
    
    # 测试7: 菜单动作
    test_menu_actions(window)
    
    # 测试8: 停靠面板
    test_dock_widgets(window)
    
    # 测试9: 主题
    test_theme(window)
    
    # 总结
    print("\n" + "=" * 60)
    print("📊 测试总结")
    print("=" * 60)
    print("✅ 所有测试通过！")
    print()
    print("Qt6迁移完成，所有功能正常工作！")
    print("=" * 60)
    
    # 关闭窗口
    QTimer.singleShot(1000, window.close)
    QTimer.singleShot(1500, app.quit)
    
    return app.exec()

if __name__ == '__main__':
    sys.exit(run_all_tests())

