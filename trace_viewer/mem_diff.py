from typing import Optional, Tuple
from PyQt5 import QtCore, QtGui, QtWidgets


class MemoryDiffDock(QtWidgets.QDockWidget):
    """内存前后值对比（基于指令有效地址与寄存器值推断）。"""

    def __init__(self, parent=None):
        super().__init__('内存写入对比', parent)
        self.setObjectName('MemoryDiffDock')
        self.setFeatures(QtWidgets.QDockWidget.DockWidgetClosable | QtWidgets.QDockWidget.DockWidgetMovable)

        container = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(container)
        layout.setContentsMargins(6, 6, 6, 6)

        self.info = QtWidgets.QLabel('地址: -    宽度: -    类型: -')
        # 使用 QTextBrowser 以支持 setHtml/富文本渲染
        self.view = QtWidgets.QTextBrowser()
        self.view.setOpenExternalLinks(False)
        self.view.setOpenLinks(False)
        self.view.setFont(QtGui.QFont('Menlo', 12))

        layout.addWidget(self.info)
        layout.addWidget(self.view)
        self.setWidget(container)

        self.parser = None
        self.eval_effaddr_cb = None

    def attach(self, parser, eval_effaddr_cb) -> None:
        self.parser = parser
        self.eval_effaddr_cb = eval_effaddr_cb

    def update_for_event(self, event_index: int) -> None:
        if not self.parser or self.eval_effaddr_cb is None:
            return
        if event_index < 0 or event_index >= len(self.parser.events):
            return
        ev = self.parser.events[event_index]
        asm = ev.asm.lower()

        addr = self.eval_effaddr_cb(event_index)
        if addr is None:
            self.info.setText('地址: -    宽度: -    类型: -')
            self.view.setPlainText('')
            return

        w, op_type, after_bytes = self._current_value_bytes(event_index)
        before_bytes = self._last_store_before(event_index, addr, w)

        self.info.setText(f'地址: 0x{addr:08x}    宽度: {w}    类型: {op_type}')
        self._render_bytes(before_bytes, after_bytes)

    def _current_value_bytes(self, idx: int) -> Tuple[int, str, Optional[bytes]]:
        """推断当前事件写入/读取的宽度与值（对 store 取寄存器源值，对 load 仅展示已知/未知）。"""
        ev = self.parser.events[idx]
        asm = ev.asm.lower()
        width = 4
        op_type = 'read'
        if asm.startswith('strb'):
            width = 1
            op_type = 'write'
        elif asm.startswith('strh'):
            width = 2
            op_type = 'write'
        elif asm.startswith('str'):
            width = 4
            op_type = 'write'
        elif asm.startswith('ldrb'):
            width = 1
            op_type = 'read'
        elif asm.startswith('ldrh'):
            width = 2
            op_type = 'read'
        elif asm.startswith('ldr'):
            width = 4
            op_type = 'read'

        if op_type == 'write':
            # 解析源寄存器（第一个操作数）
            try:
                inside = ev.asm.split(' ', 1)[1]
                src = inside.split(',', 1)[0].strip()
            except Exception:
                src = ''
            val = None
            if src:
                src_l = src.lower()
                # 对于 store，寄存器值通常出现在 reads 中
                if src_l in ev.reads:
                    val = ev.reads[src_l]
            if val is None:
                return width, op_type, None
            b = val.to_bytes(4, byteorder='little', signed=False)[:width]
            return width, op_type, b
        return width, op_type, None

    def _last_store_before(self, idx: int, addr: int, width: int) -> Optional[bytes]:
        # 向前查找最近一次对该地址的 store
        for j in range(idx - 1, -1, -1):
            ev = self.parser.events[j]
            asm = ev.asm.lower()
            if not asm.startswith('str'):
                continue
            eff = self.eval_effaddr_cb(j)
            if eff != addr:
                continue
            wj, _, vb = self._current_value_bytes(j)
            if vb is None:
                continue
            # 以当前宽度裁剪
            return vb[:width]
        return None

    def _render_bytes(self, before: Optional[bytes], after: Optional[bytes]) -> None:
        # 渲染为彩色十六进制：不一致字节高亮，未知用 ??
        def fmt_line(label: str, data: Optional[bytes], cmp_with: Optional[bytes]) -> str:
            if data is None:
                return f"{label}: (未知)"
            parts = []
            for i, b in enumerate(data):
                if cmp_with is not None and i < len(cmp_with or b'') and cmp_with[i] != b:
                    parts.append(f"<span style='color:#a6f4c5;background:#143d2b'> {b:02X} </span>")
                else:
                    parts.append(f"<span style='color:#cdd6f4'> {b:02X} </span>")
            return f"{label}:" + ''.join(parts)

        html = [
            "<pre style='font-family:Menlo,Monaco,Consolas; font-size:12px; color:#cdd6f4'>",
            fmt_line('之前', before, after),
            '<br/>',
            fmt_line('之后', after, before),
            "</pre>",
        ]
        self.view.setHtml(''.join(html))


