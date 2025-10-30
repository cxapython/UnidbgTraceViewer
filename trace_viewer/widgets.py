import re
from PyQt5 import QtCore, QtGui, QtWidgets


class ClickableCodeEdit(QtWidgets.QPlainTextEdit):
    """代码窗口：支持点击跳转地址（如 0x12025890）。"""

    addressClicked = QtCore.pyqtSignal(int)
    lineClicked = QtCore.pyqtSignal(int)  # 代码窗口被点击的行号（0-based）

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        # 字体候选（按可用性降级）
        candidates = ['JetBrains Mono', 'Menlo', 'Monaco', 'Consolas', 'Courier New']
        fams = set(QtGui.QFontDatabase().families())
        font_name = next((n for n in candidates if n in fams), 'Monospace')
        self.setFont(QtGui.QFont(font_name, 12))
        self._addr_re = re.compile(r"0x[0-9a-fA-F]+")
        # 支持复制
        self.setContextMenuPolicy(QtCore.Qt.DefaultContextMenu)
        # 文档边距，避免文本贴边
        self.document().setDocumentMargin(12)
        # 记录按下位置，用于区分点击与拖拽选择
        self._press_pos = None

    def mousePressEvent(self, e: QtGui.QMouseEvent) -> None:
        if e.button() == QtCore.Qt.LeftButton:
            self._press_pos = e.pos()
        else:
            self._press_pos = None
        super().mousePressEvent(e)

    def mouseReleaseEvent(self, e: QtGui.QMouseEvent) -> None:
        super().mouseReleaseEvent(e)
        # 仅在左键点击、无拖拽、且当前没有文本选择时，才触发行点击与地址解析，避免复制被打断
        if e.button() != QtCore.Qt.LeftButton:
            return
        tc = self.textCursor()
        if tc.hasSelection():
            return
        try:
            if self._press_pos is not None:
                moved = (self._press_pos - e.pos()).manhattanLength()
                if moved >= QtWidgets.QApplication.startDragDistance():
                    return
        except Exception:
            return
        cursor = self.cursorForPosition(e.pos())
        cursor.select(QtGui.QTextCursor.LineUnderCursor)
        line_text = cursor.selectedText()
        # 行点击信号（用于联动寄存器前/后视图）
        self.lineClicked.emit(cursor.blockNumber())
        for m in self._addr_re.finditer(line_text):
            try:
                addr = int(m.group(0), 16)
            except ValueError:
                continue
            # 发射信号，外部根据地址跳转
            self.addressClicked.emit(addr)
            break


class AssemblyHighlighter(QtGui.QSyntaxHighlighter):
    """汇编语法高亮（简版），增强可读性与可点击视觉提示。"""

    def __init__(self, parent: QtGui.QTextDocument) -> None:
        super().__init__(parent)
        # 颜色方案（接近专业逆向工具风格）
        self.c_opcode = QtGui.QColor('#f0c674')   # 指令助记符（黄）
        self.c_reg = QtGui.QColor('#c5a5c5')      # 寄存器（紫）
        self.c_addr = QtGui.QColor('#8bd5ff')     # 地址/立即数（蓝青）
        self.c_comment = QtGui.QColor('#7f8c98')  # 注释（灰蓝）

        self.f_opcode = QtGui.QTextCharFormat()
        self.f_opcode.setForeground(self.c_opcode)
        self.f_opcode.setFontWeight(QtGui.QFont.Bold)

        self.f_reg = QtGui.QTextCharFormat()
        self.f_reg.setForeground(self.c_reg)

        self.f_addr = QtGui.QTextCharFormat()
        self.f_addr.setForeground(self.c_addr)

        self.f_comment = QtGui.QTextCharFormat()
        self.f_comment.setForeground(self.c_comment)

        # 正则规则
        # 前缀含时间戳与PC地址，指令出现在冒号后
        self.re_opcode = re.compile(r":\s*([a-z]{2,6})(?=\s|$)")
        self.re_reg = re.compile(r"\b(r(?:1[0-5]|[0-9])|x(?:[12][0-9]|3[01]|[0-9])|sp|lr|pc|cpsr)\b",
                                 re.IGNORECASE)
        self.re_addr = re.compile(r"\b0x[0-9a-fA-F]+\b|#[0-9a-fA-Fx]+")
        self.re_comment = re.compile(r"[;#].*$")

    def highlightBlock(self, text: str) -> None:
        # 注释优先
        m = self.re_comment.search(text)
        if m:
            self.setFormat(m.start(), m.end() - m.start(), self.f_comment)

        # 助记符
        m = self.re_opcode.search(text)
        if m:
            self.setFormat(m.start(1), m.end(1) - m.start(1), self.f_opcode)

        # 地址/立即数
        for m in self.re_addr.finditer(text):
            self.setFormat(m.start(), m.end() - m.start(), self.f_addr)

        # 寄存器
        for m in self.re_reg.finditer(text):
            self.setFormat(m.start(), m.end() - m.start(), self.f_reg)


