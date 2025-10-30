from PyQt5 import QtCore, QtWidgets


def busy(self, on: bool) -> None:
    """统一管理忙碌光标，避免不成对 restore 导致卡顿光标。"""
    try:
        if on:
            self._busy_count = max(0, getattr(self, '_busy_count', 0)) + 1
            QtWidgets.QApplication.setOverrideCursor(QtCore.Qt.WaitCursor)
        else:
            if getattr(self, '_busy_count', 0) > 0:
                self._busy_count -= 1
                QtWidgets.QApplication.restoreOverrideCursor()
    except Exception:
        pass


