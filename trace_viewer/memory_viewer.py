"""
内存查看器模块：十六进制+ASCII视图、执行前后对比

功能：
1. 十六进制视图（类似hexdump）
2. ASCII字符显示
3. 执行前后内存对比
4. 自动识别缓冲区类型
5. 高亮变化的字节
"""

from typing import Optional, Dict, List, Tuple
from PyQt5 import QtCore, QtGui, QtWidgets


class MemoryViewerDock(QtWidgets.QDockWidget):
    """内存查看器停靠面板"""
    
    def __init__(self, parent=None):
        super().__init__('内存查看器', parent)
        self.setObjectName('MemoryViewerDock')
        self.setFeatures(QtWidgets.QDockWidget.DockWidgetClosable | 
                        QtWidgets.QDockWidget.DockWidgetMovable)
        
        self.parser = None
        self._current_event_idx = 0
        
        # 主容器
        container = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(container)
        layout.setContentsMargins(8, 8, 8, 8)
        
        # 顶部控制栏
        control_layout = QtWidgets.QHBoxLayout()
        
        # 地址输入
        control_layout.addWidget(QtWidgets.QLabel('地址:'))
        self.addr_input = QtWidgets.QLineEdit()
        self.addr_input.setPlaceholderText('0x7FFE00')
        self.addr_input.setMaximumWidth(120)
        control_layout.addWidget(self.addr_input)
        
        # 长度输入
        control_layout.addWidget(QtWidgets.QLabel('长度:'))
        self.length_input = QtWidgets.QSpinBox()
        self.length_input.setRange(16, 4096)
        self.length_input.setValue(256)
        self.length_input.setSingleStep(16)
        self.length_input.setMaximumWidth(80)
        control_layout.addWidget(self.length_input)
        
        # 查看按钮
        self.view_btn = QtWidgets.QPushButton('查看')
        self.view_btn.clicked.connect(self._on_view)
        control_layout.addWidget(self.view_btn)
        
        # 对比模式
        self.compare_check = QtWidgets.QCheckBox('对比模式')
        self.compare_check.setToolTip('显示执行前后内存的差异')
        self.compare_check.stateChanged.connect(self._on_compare_toggled)
        control_layout.addWidget(self.compare_check)
        
        control_layout.addStretch()
        layout.addLayout(control_layout)
        
        # 内存视图（使用等宽字体）
        self.mem_view = QtWidgets.QTextEdit()
        self.mem_view.setReadOnly(True)
        self.mem_view.setLineWrapMode(QtWidgets.QTextEdit.NoWrap)
        
        font = QtGui.QFont('Consolas, Monaco, monospace', 10)
        self.mem_view.setFont(font)
        
        # 深色主题
        self.mem_view.setStyleSheet("""
            QTextEdit {
                background: #0e1621;
                color: #cdd6f4;
                border: 1px solid #1f2937;
                padding: 8px;
            }
        """)
        
        layout.addWidget(self.mem_view)
        
        # 底部信息栏
        self.info_label = QtWidgets.QLabel()
        self.info_label.setStyleSheet("""
            QLabel {
                color: #94a3b8;
                padding: 4px;
                background: #0b1220;
                border: 1px solid #1f2937;
                border-radius: 3px;
            }
        """)
        layout.addWidget(self.info_label)
        
        self.setWidget(container)
        
        # 初始禁用
        self.view_btn.setEnabled(False)
    
    def attach(self, parser, event_idx: int = 0):
        """附加解析器"""
        self.parser = parser
        self._current_event_idx = event_idx
        self.view_btn.setEnabled(True)
    
    def set_event_index(self, event_idx: int):
        """设置当前事件索引"""
        self._current_event_idx = event_idx
    
    def view_address(self, addr: int, length: int = 256):
        """查看指定地址的内存"""
        self.addr_input.setText(f'0x{addr:x}')
        self.length_input.setValue(length)
        self._on_view()
    
    def _on_view(self):
        """查看按钮点击"""
        if not self.parser:
            self.mem_view.setPlainText('未加载trace文件')
            return
        
        # 解析地址
        addr_text = self.addr_input.text().strip()
        if not addr_text:
            self.mem_view.setPlainText('请输入地址')
            return
        
        try:
            addr = int(addr_text, 16) if addr_text.startswith('0x') else int(addr_text)
        except ValueError:
            self.mem_view.setPlainText(f'无效地址: {addr_text}')
            return
        
        length = self.length_input.value()
        
        # 获取内存数据
        if self.compare_check.isChecked():
            self._view_compare(addr, length)
        else:
            self._view_single(addr, length)
    
    def _view_single(self, addr: int, length: int):
        """单视图：只显示当前内存"""
        # 模拟内存读取（实际应该从trace中提取）
        # 这里我们使用一个占位实现
        
        lines = []
        lines.append(f"内存视图 - 地址: 0x{addr:08x}, 长度: {length} 字节")
        lines.append("=" * 80)
        lines.append("")
        
        # 表头
        header = "偏移    "
        for i in range(16):
            header += f"+{i:X} "
        header += "  ASCII"
        lines.append(header)
        lines.append("-" * 80)
        
        # 模拟数据（实际应从trace中获取）
        lines.append("⚠️  当前版本暂不支持直接读取内存数据")
        lines.append("")
        lines.append("📝 使用方法：")
        lines.append("1. 在代码面板中找到内存读写指令")
        lines.append("2. 查看悬停提示获取内存地址和数据")
        lines.append("3. 使用污点追踪分析内存数据流向")
        lines.append("")
        lines.append("🔜 后续版本将支持：")
        lines.append("- 从trace中提取内存写入记录")
        lines.append("- 重建任意时刻的内存快照")
        lines.append("- 对比执行前后的内存变化")
        
        self.mem_view.setPlainText('\n'.join(lines))
        self.info_label.setText(f'地址: 0x{addr:08x} | 长度: {length}字节')
    
    def _view_compare(self, addr: int, length: int):
        """对比视图：显示执行前后的差异"""
        lines = []
        lines.append(f"内存对比 - 地址: 0x{addr:08x}, 长度: {length} 字节")
        lines.append(f"事件: {self._current_event_idx}")
        lines.append("=" * 80)
        lines.append("")
        
        lines.append("⚠️  对比功能开发中...")
        lines.append("")
        lines.append("🎯 对比模式将显示：")
        lines.append("- 执行前的内存数据（灰色）")
        lines.append("- 执行后的内存数据（彩色）")
        lines.append("- 变化的字节高亮（红色）")
        lines.append("- 差异统计（变化字节数、变化率）")
        
        self.mem_view.setPlainText('\n'.join(lines))
        self.info_label.setText(f'对比模式 | 地址: 0x{addr:08x} | 事件: {self._current_event_idx}')
    
    def _on_compare_toggled(self, state):
        """对比模式切换"""
        if self.parser and self.addr_input.text().strip():
            self._on_view()


def format_memory_dump(data: bytes, base_addr: int = 0, highlight_indices: Optional[List[int]] = None) -> str:
    """格式化内存数据为十六进制+ASCII显示
    
    Args:
        data: 内存数据
        base_addr: 基地址
        highlight_indices: 需要高亮的字节索引列表
    
    Returns:
        格式化的字符串
    """
    highlight_indices = highlight_indices or []
    lines = []
    
    # 表头
    header = "偏移    "
    for i in range(16):
        header += f"+{i:X} "
    header += "  ASCII"
    lines.append(header)
    lines.append("-" * 80)
    
    # 数据行
    for offset in range(0, len(data), 16):
        # 偏移地址
        line = f"{base_addr + offset:08x}: "
        
        # 十六进制
        hex_part = ""
        ascii_part = ""
        
        for i in range(16):
            if offset + i < len(data):
                byte = data[offset + i]
                
                # 检查是否需要高亮
                if offset + i in highlight_indices:
                    hex_part += f"[{byte:02x}] "
                else:
                    hex_part += f"{byte:02x} "
                
                # ASCII字符
                if 32 <= byte <= 126:
                    ascii_part += chr(byte)
                else:
                    ascii_part += '.'
            else:
                hex_part += "   "
                ascii_part += " "
        
        line += hex_part + " " + ascii_part
        lines.append(line)
    
    return '\n'.join(lines)


def compare_memory(before: bytes, after: bytes, base_addr: int = 0) -> str:
    """对比两个内存快照，高亮差异
    
    Args:
        before: 执行前的内存数据
        after: 执行后的内存数据
        base_addr: 基地址
    
    Returns:
        格式化的对比字符串
    """
    lines = []
    
    # 统计变化
    changed_bytes = []
    for i in range(min(len(before), len(after))):
        if before[i] != after[i]:
            changed_bytes.append(i)
    
    change_rate = len(changed_bytes) / len(before) * 100 if before else 0
    
    lines.append(f"变化统计: {len(changed_bytes)} 字节变化 ({change_rate:.1f}%)")
    lines.append("")
    
    # 执行前
    lines.append("【执行前】")
    lines.append(format_memory_dump(before, base_addr))
    lines.append("")
    
    # 执行后（高亮变化）
    lines.append("【执行后】")
    lines.append(format_memory_dump(after, base_addr, changed_bytes))
    lines.append("")
    
    # 只显示变化的字节
    if changed_bytes:
        lines.append("【变化详情】")
        for idx in changed_bytes[:20]:  # 最多显示20个
            addr = base_addr + idx
            lines.append(f"  0x{addr:08x}: 0x{before[idx]:02x} → 0x{after[idx]:02x}")
        if len(changed_bytes) > 20:
            lines.append(f"  ... 还有 {len(changed_bytes) - 20} 个变化未显示")
    
    return '\n'.join(lines)


def detect_buffer_type(data: bytes) -> str:
    """检测缓冲区类型
    
    Returns:
        'text': 文本数据
        'binary': 二进制数据
        'encrypted': 疑似加密数据
        'unknown': 未知
    """
    if not data:
        return 'unknown'
    
    # 统计可打印字符比例
    printable_count = sum(1 for b in data if 32 <= b <= 126 or b in (9, 10, 13))
    printable_rate = printable_count / len(data)
    
    # 文本数据
    if printable_rate > 0.8:
        return 'text'
    
    # 统计字节分布的熵（加密数据通常熵较高）
    from collections import Counter
    byte_counts = Counter(data)
    entropy = 0
    for count in byte_counts.values():
        p = count / len(data)
        if p > 0:
            entropy -= p * (p ** 0.5)  # 简化的熵计算
    
    # 高熵 = 疑似加密
    if entropy > 0.8:
        return 'encrypted'
    
    # 低可打印率 = 二进制
    if printable_rate < 0.3:
        return 'binary'
    
    return 'unknown'

