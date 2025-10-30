from PyQt5 import QtCore


class RegsWorker(QtCore.QThread):
    """后台复原寄存器，防止 UI 卡顿。"""

    finishedWithIndex = QtCore.pyqtSignal(dict, dict, int)

    def __init__(self, parser: 'TraceParser', ev_idx: int, parent=None) -> None:
        super().__init__(parent)
        self._parser = parser
        self._ev_idx = ev_idx

    def run(self) -> None:
        try:
            before = self._parser.reconstruct_regs_at(self._ev_idx - 1) if self._ev_idx > 0 else {}
            after = self._parser.reconstruct_regs_at(self._ev_idx)
        except Exception:
            before, after = {}, {}
        if not self.isInterruptionRequested():
            self.finishedWithIndex.emit(before, after, self._ev_idx)


class ParserWorker(QtCore.QThread):
    """后台解析线程，避免主线程卡顿。"""

    finished = QtCore.pyqtSignal(object, str)
    progress = QtCore.pyqtSignal(int)

    def __init__(self, path: str) -> None:
        super().__init__()
        self._path = path

    def run(self) -> None:
        # 局部导入避免主线程启动开销
        try:
            from .trace_parser import TraceParser  # type: ignore
        except Exception:
            from trace_parser import TraceParser  # type: ignore
        parser = TraceParser(checkpoint_interval=2000)
        try:
            parser.parse_file(self._path, progress_cb=lambda p: self.progress.emit(p))
        except Exception:
            # 兜底：避免进度异常导致线程崩溃
            parser.parse_file(self._path)
        self.finished.emit(parser, self._path)


