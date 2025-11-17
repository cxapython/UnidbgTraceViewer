"""
增强的代码视图模块：显示行号、寄存器值、内存数据、操作类型标注

主要功能：
1. 行号列显示
2. 内联显示寄存器值和内存数据
3. 操作类型图标和颜色标注
4. 鼠标悬停显示完整信息
"""

import re
from typing import Optional, Dict, List, Tuple
from PyQt6 import QtCore, QtGui, QtWidgets


class InstructionAnalyzer:
    """汇编指令分析器：识别操作类型和提取关键信息"""
    
    # 操作类型分类
    LOAD_OPS = {'ldr', 'ldrb', 'ldrh', 'ldrsb', 'ldrsh', 'ldm', 'ldmia', 'ldmfd', 'pop',
                'ldr.w', 'ldrb.w', 'ldrh.w', 'vldr', 'vld1'}
    STORE_OPS = {'str', 'strb', 'strh', 'stm', 'stmia', 'stmfd', 'push',
                 'str.w', 'strb.w', 'strh.w', 'vstr', 'vst1'}
    ARITHMETIC_OPS = {'add', 'adds', 'adc', 'sub', 'subs', 'sbc', 'rsb', 'mul', 'mla', 'umull', 'smull',
                      'add.w', 'sub.w', 'mul.w'}
    LOGIC_OPS = {'and', 'ands', 'orr', 'orrs', 'eor', 'eors', 'bic', 'orn', 'mvn',
                 'and.w', 'orr.w', 'eor.w', 'xor'}
    SHIFT_OPS = {'lsl', 'lsr', 'asr', 'ror', 'rrx', 'lsl.w', 'lsr.w', 'asr.w'}
    BRANCH_OPS = {'b', 'bl', 'bx', 'blx', 'beq', 'bne', 'bgt', 'blt', 'bge', 'ble',
                  'bhi', 'blo', 'bhs', 'bls', 'bpl', 'bmi', 'b.w', 'bl.w'}
    COMPARE_OPS = {'cmp', 'cmn', 'tst', 'teq', 'cmp.w'}
    MOVE_OPS = {'mov', 'movs', 'movw', 'movt', 'mov.w'}
    
    @staticmethod
    def get_operation_type(asm: str) -> str:
        """识别指令的操作类型"""
        # 提取操作码（第一个单词）
        parts = asm.strip().split()
        if not parts:
            return 'unknown'
        
        opcode = parts[0].lower().rstrip(',')
        
        if opcode in InstructionAnalyzer.LOAD_OPS:
            return 'load'
        elif opcode in InstructionAnalyzer.STORE_OPS:
            return 'store'
        elif opcode in InstructionAnalyzer.ARITHMETIC_OPS:
            return 'arithmetic'
        elif opcode in InstructionAnalyzer.LOGIC_OPS:
            return 'logic'
        elif opcode in InstructionAnalyzer.SHIFT_OPS:
            return 'shift'
        elif opcode in InstructionAnalyzer.BRANCH_OPS:
            return 'branch'
        elif opcode in InstructionAnalyzer.COMPARE_OPS:
            return 'compare'
        elif opcode in InstructionAnalyzer.MOVE_OPS:
            return 'move'
        else:
            return 'other'
    
    @staticmethod
    def get_operation_icon(op_type: str, use_emoji: bool = False) -> str:
        """获取操作类型的图标
        
        Args:
            op_type: 操作类型
            use_emoji: 是否使用emoji图标（默认False使用ASCII）
        """
        if use_emoji:
            # Emoji图标（需要支持emoji的字体，如 Apple Color Emoji）
            icons = {
                'load': '📥',      # 加载
                'store': '📤',     # 存储
                'arithmetic': '➕', # 算术
                'logic': '⚡',     # 逻辑
                'shift': '↔️',     # 移位
                'branch': '🔀',    # 分支
                'compare': '⚖️',   # 比较
                'move': '➡️',      # 移动
                'other': '·'       # 其他
            }
        else:
            # ASCII图标（兼容所有系统）
            icons = {
                'load': '↓',      # 加载
                'store': '↑',     # 存储
                'arithmetic': '+', # 算术
                'logic': '&',     # 逻辑
                'shift': '<<',    # 移位
                'branch': '*',    # 分支
                'compare': '?',   # 比较
                'move': '→',      # 移动
                'other': '·'      # 其他
            }
        return icons.get(op_type, '·')
    
    @staticmethod
    def get_operation_color(op_type: str) -> str:
        """获取操作类型的颜色（CSS格式）"""
        colors = {
            'load': '#4ade80',      # 绿色
            'store': '#60a5fa',     # 蓝色
            'arithmetic': '#fbbf24', # 黄色
            'logic': '#fb923c',     # 橙色
            'shift': '#a78bfa',     # 紫色
            'branch': '#f87171',    # 红色
            'compare': '#94a3b8',   # 灰色
            'move': '#22d3ee',      # 青色
            'other': '#6b7280'      # 深灰
        }
        return colors.get(op_type, '#6b7280')
    
    @staticmethod
    def extract_memory_access(asm: str) -> Optional[Tuple[str, str]]:
        """提取内存访问信息：返回 (寄存器, 地址表达式)
        
        例如:
        - "ldr r0, [r1, #0x10]" -> ('r0', '[r1, #0x10]')
        - "str r2, [sp]" -> ('r2', '[sp]')
        """
        # 匹配内存访问模式：[reg] 或 [reg, offset] 或 [reg, reg]
        mem_pattern = re.compile(r'\[([^\]]+)\]')
        reg_pattern = re.compile(r'^([rxw]\d+|sp|lr|pc)')
        
        mem_match = mem_pattern.search(asm)
        reg_match = reg_pattern.search(asm)
        
        if mem_match and reg_match:
            return (reg_match.group(1), f'[{mem_match.group(1)}]')
        
        return None


class EnhancedCodeFormatter:
    """增强的代码格式化器：生成带有行号、寄存器值、内存数据的显示文本"""
    
    def __init__(self, parser=None, use_emoji: bool = False):
        self.parser = parser
        self.analyzer = InstructionAnalyzer()
        self.use_emoji = use_emoji  # 是否使用emoji图标
    
    def format_event(self, event, event_index: int, regs_before: Optional[Dict] = None, 
                     regs_after: Optional[Dict] = None) -> str:
        """格式化单个事件为增强显示格式
        
        简化格式: 图标 PC地址 | 汇编指令
        例如: 📥 0x12057fa4 | push {r4, r5, r6, r7, lr}
        """
        # 操作类型图标
        op_type = self.analyzer.get_operation_type(event.asm)
        icon = self.analyzer.get_operation_icon(op_type, use_emoji=self.use_emoji)
        
        # PC地址
        pc_str = f"0x{event.pc:08x}"
        
        # 汇编指令
        asm_str = event.asm
        
        # 简化格式：只显示图标、PC和汇编
        # 详细信息通过悬停提示查看
        return f"{icon} {pc_str} | {asm_str}"
    
    def format_events(self, events: List, start_index: int, parser=None) -> str:
        """格式化多个事件"""
        lines = []
        
        for i, event in enumerate(events):
            event_idx = start_index + i
            
            # 获取寄存器状态
            regs_before = None
            regs_after = None
            if parser:
                try:
                    regs_before = parser.restore_registers(event_idx)
                    regs_after = parser.restore_registers(event_idx, after=True)
                except:
                    pass
            
            line = self.format_event(event, event_idx, regs_before, regs_after)
            lines.append(line)
        
        return '\n'.join(lines)


class LineNumberArea(QtWidgets.QWidget):
    """行号区域（绘制在代码编辑器左侧）"""
    
    def __init__(self, editor):
        super().__init__(editor)
        self.code_editor = editor
    
    def sizeHint(self):
        return QtCore.QSize(self.code_editor.line_number_area_width(), 0)
    
    def paintEvent(self, event):
        self.code_editor.line_number_area_paint_event(event)


class EnhancedCodeEdit(QtWidgets.QPlainTextEdit):
    """增强的代码编辑器：带行号、操作类型颜色、悬停提示"""
    
    addressClicked = QtCore.pyqtSignal(int)
    lineClicked = QtCore.pyqtSignal(int)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setLineWrapMode(QtWidgets.QPlainTextEdit.NoWrap)
        
        # 行号区域
        self.line_number_area = LineNumberArea(self)
        
        # 连接信号
        self.blockCountChanged.connect(self.update_line_number_area_width)
        self.updateRequest.connect(self.update_line_number_area)
        
        # 初始化
        self.update_line_number_area_width(0)
        
        # 设置字体：优先使用支持emoji的等宽字体
        # macOS: Menlo + Apple Color Emoji
        # Windows: Consolas + Segoe UI Emoji
        # Linux: DejaVu Sans Mono + Noto Color Emoji
        font_candidates = [
            'Menlo',           # macOS 系统等宽字体，支持emoji
            'SF Mono',         # macOS 现代等宽字体
            'Monaco',          # macOS 经典等宽字体
            'Consolas',        # Windows 等宽字体
            'DejaVu Sans Mono' # Linux 等宽字体
        ]
        fams = set(QtGui.QFontDatabase.families())
        font_name = next((n for n in font_candidates if n in fams), 'Monospace')
        font = QtGui.QFont(font_name, 10)
        self.setFont(font)
        
        # 深色主题样式
        self.setStyleSheet("""
            QPlainTextEdit {
                background: #0e1621;
                color: #cdd6f4;
                border: 1px solid #1f2937;
                padding-left: 5px;
                selection-background-color: #1a232e;
                selection-color: #8bd5ff;
            }
        """)
        
        # 存储事件数据（用于悬停提示）
        self._events_data = []
        self._parser = None
        
        # 启用鼠标追踪（用于悬停提示）
        self.setMouseTracking(True)
    
    def line_number_area_width(self):
        """计算行号区域宽度"""
        digits = len(str(max(1, self.blockCount())))
        space = 10 + self.fontMetrics().horizontalAdvance('9') * digits
        return space
    
    def update_line_number_area_width(self, _):
        """更新行号区域宽度"""
        self.setViewportMargins(self.line_number_area_width(), 0, 0, 0)
    
    def update_line_number_area(self, rect, dy):
        """更新行号区域显示"""
        if dy:
            self.line_number_area.scroll(0, dy)
        else:
            self.line_number_area.update(0, rect.y(), 
                                        self.line_number_area.width(), 
                                        rect.height())
        
        if rect.contains(self.viewport().rect()):
            self.update_line_number_area_width(0)
    
    def resizeEvent(self, event):
        """窗口大小改变时调整行号区域"""
        super().resizeEvent(event)
        cr = self.contentsRect()
        self.line_number_area.setGeometry(
            QtCore.QRect(cr.left(), cr.top(), 
                        self.line_number_area_width(), cr.height())
        )
    
    def line_number_area_paint_event(self, event):
        """绘制行号"""
        painter = QtGui.QPainter(self.line_number_area)
        painter.fillRect(event.rect(), QtGui.QColor('#0b1220'))
        
        block = self.firstVisibleBlock()
        block_number = block.blockNumber()
        top = int(self.blockBoundingGeometry(block).translated(
            self.contentOffset()).top())
        bottom = top + int(self.blockBoundingRect(block).height())
        
        # 行号颜色
        painter.setPen(QtGui.QColor('#6b7280'))
        
        while block.isValid() and top <= event.rect().bottom():
            if block.isVisible() and bottom >= event.rect().top():
                number = str(block_number + 1)
                painter.drawText(0, top, self.line_number_area.width() - 5,
                               self.fontMetrics().height(),
                               QtCore.Qt.AlignRight, number)
            
            block = block.next()
            top = bottom
            bottom = top + int(self.blockBoundingRect(block).height())
            block_number += 1
    
    def mousePressEvent(self, event):
        """鼠标点击事件：支持点击地址跳转和行点击"""
        super().mousePressEvent(event)
        if event.button() == QtCore.Qt.LeftButton:
            cursor = self.cursorForPosition(event.pos())
            line_num = cursor.blockNumber()
            self.lineClicked.emit(line_num)
            
            # 检查是否点击了地址
            cursor.select(QtGui.QTextCursor.WordUnderCursor)
            word = cursor.selectedText()
            if word.startswith('0x'):
                try:
                    addr = int(word, 16)
                    self.addressClicked.emit(addr)
                except ValueError:
                    pass
    
    def set_events_data(self, events_data, parser=None):
        """设置事件数据（用于悬停提示）"""
        self._events_data = events_data
        self._parser = parser
    
    def event(self, event):
        """事件处理：实现悬停提示"""
        if event.type() == QtCore.QEvent.Type.ToolTip:
            cursor = self.cursorForPosition(event.pos())
            line_num = cursor.blockNumber()
            
            # 生成悬停提示
            if 0 <= line_num < len(self._events_data):
                ev = self._events_data[line_num]
                tooltip_html = self._generate_tooltip(ev, line_num)
                QtWidgets.QToolTip.showText(event.globalPos(), tooltip_html, self)
            else:
                QtWidgets.QToolTip.hideText()
            
            return True
        
        return super().event(event)
    
    def _generate_tooltip(self, event, line_num: int) -> str:
        """生成悬停提示的HTML"""
        lines = []
        lines.append(f"<b>行号:</b> {line_num:04d}<br>")
        lines.append(f"<b>PC:</b> 0x{event.pc:08x}<br>")
        lines.append(f"<b>指令:</b> {event.asm}<br>")
        
        # 操作类型
        op_type = InstructionAnalyzer.get_operation_type(event.asm)
        icon = InstructionAnalyzer.get_operation_icon(op_type)
        lines.append(f"<b>类型:</b> {icon} {op_type}<br>")
        
        # 寄存器读写
        if event.reads:
            reads_str = ', '.join(f"{k}=0x{v:x}" for k, v in event.reads.items())
            lines.append(f"<b>读取:</b> {reads_str}<br>")
        
        if event.writes:
            writes_str = ', '.join(f"{k}" for k in event.writes.keys())
            lines.append(f"<b>写入:</b> {writes_str}<br>")
        
        # 内存访问
        if event.effaddr is not None:
            lines.append(f"<b>内存:</b> 0x{event.effaddr:x} ({event.mem_op})<br>")
        
        # 时间戳
        lines.append(f"<b>时间:</b> {event.timestamp}")
        
        return ''.join(lines)


class EnhancedAssemblyHighlighter(QtGui.QSyntaxHighlighter):
    """增强的汇编语法高亮：根据操作类型着色"""
    
    def __init__(self, document):
        super().__init__(document)
        self.analyzer = InstructionAnalyzer()
        
        # 定义高亮规则
        self.highlighting_rules = []
        
        # 行号格式
        line_num_format = QtGui.QTextCharFormat()
        line_num_format.setForeground(QtGui.QColor('#6b7280'))
        self.highlighting_rules.append((re.compile(r'^\d{4}'), line_num_format))
        
        # 地址格式
        addr_format = QtGui.QTextCharFormat()
        addr_format.setForeground(QtGui.QColor('#8bd5ff'))
        addr_format.setFontWeight(QtGui.QFont.Bold)
        self.highlighting_rules.append((re.compile(r'0x[0-9a-fA-F]+'), addr_format))
        
        # 寄存器格式
        reg_format = QtGui.QTextCharFormat()
        reg_format.setForeground(QtGui.QColor('#a6e3a1'))
        self.highlighting_rules.append((re.compile(r'\b[rxw]\d+\b|sp|lr|pc|cpsr'), reg_format))
        
        # 立即数格式
        imm_format = QtGui.QTextCharFormat()
        imm_format.setForeground(QtGui.QColor('#fab387'))
        self.highlighting_rules.append((re.compile(r'#-?0x[0-9a-fA-F]+|#-?\d+'), imm_format))
        
        # 图标格式
        icon_format = QtGui.QTextCharFormat()
        icon_format.setFontPointSize(10)
        self.highlighting_rules.append((re.compile(r'[📥📤➕⚡↔️🔀⚖️➡️]'), icon_format))
    
    def highlightBlock(self, text):
        """高亮当前块"""
        # 应用所有规则
        for pattern, format in self.highlighting_rules:
            for match in pattern.finditer(text):
                self.setFormat(match.start(), match.end() - match.start(), format)
        
        # 根据操作类型为指令部分着色
        if '|' in text:
            parts = text.split('|')
            if len(parts) >= 3:
                asm_part = parts[2].strip()
                op_type = self.analyzer.get_operation_type(asm_part)
                
                # 找到指令操作码的位置并着色
                words = asm_part.split()
                if words:
                    opcode = words[0]
                    # 在原文中找到操作码的位置
                    op_start = text.find(opcode, text.find('|', text.find('|') + 1))
                    if op_start >= 0:
                        op_format = QtGui.QTextCharFormat()
                        color = InstructionAnalyzer.get_operation_color(op_type)
                        op_format.setForeground(QtGui.QColor(color))
                        op_format.setFontWeight(QtGui.QFont.Bold)
                        self.setFormat(op_start, len(opcode), op_format)

