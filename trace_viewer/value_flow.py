import re
import time
from typing import List, Tuple, Optional, Dict
from collections import OrderedDict
from PyQt6 import QtCore, QtGui, QtWidgets


class ValueFlowDock(QtWidgets.QDockWidget):
    """值流追踪面板：支持按寄存器或内存地址检索读写事件。"""

    jumpToEvent = QtCore.pyqtSignal(int)  # 发出事件索引，外部负责跳转

    # 提前放置占位，避免构造期间方法未解析导致的属性缺失
    def _on_export_python(self) -> None:  # will be overridden below
        pass

    def __init__(self, parent=None):
        super().__init__('值流追踪（反向+前向）', parent)
        self.setObjectName('ValueFlowDock')
        self.setFeatures(QtWidgets.QDockWidget.DockWidgetFeature.DockWidgetClosable | QtWidgets.QDockWidget.DockWidgetFeature.DockWidgetMovable)

        container = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(container)
        layout.setContentsMargins(6, 6, 6, 6)

        # === 反向追踪：追踪值的来源（往前找）===
        backward_group = QtWidgets.QGroupBox('反向追踪（追踪值来源）')
        backward_layout = QtWidgets.QVBoxLayout()
        
        backward_form = QtWidgets.QHBoxLayout()
        backward_form.addWidget(QtWidgets.QLabel('寄存器:'))
        self.input_edit = QtWidgets.QLineEdit()
        self.input_edit.setPlaceholderText('如 r1')
        backward_form.addWidget(self.input_edit)
        
        backward_form.addWidget(QtWidgets.QLabel('值:'))
        self.value_edit = QtWidgets.QLineEdit()
        self.value_edit.setPlaceholderText('如 0x4')
        backward_form.addWidget(self.value_edit)
        
        self.btn_trace_backward = QtWidgets.QPushButton('追踪来源')
        self.btn_trace_backward.setToolTip('反向追踪该寄存器值的来源（往前/向上查找）')
        self.btn_trace_backward.clicked.connect(self._on_trace_backward)
        self.btn_trace_backward.setEnabled(False)
        backward_form.addWidget(self.btn_trace_backward)
        
        backward_layout.addLayout(backward_form)
        backward_group.setLayout(backward_layout)
        layout.addWidget(backward_group)
        
        # === 前向追踪：污点传播分析（往后找）===
        forward_group = QtWidgets.QGroupBox('前向追踪（污点传播分析）')
        forward_layout = QtWidgets.QVBoxLayout()
        
        forward_form = QtWidgets.QHBoxLayout()
        forward_form.addWidget(QtWidgets.QLabel('源寄存器:'))
        self.taint_regs_edit = QtWidgets.QLineEdit()
        self.taint_regs_edit.setPlaceholderText('如 r0,r1')
        forward_form.addWidget(self.taint_regs_edit)
        
        forward_form.addWidget(QtWidgets.QLabel('源内存:'))
        self.taint_mem_edit = QtWidgets.QLineEdit()
        self.taint_mem_edit.setPlaceholderText('如 0x123,0x456')
        forward_form.addWidget(self.taint_mem_edit)
        
        self.btn_taint_forward = QtWidgets.QPushButton('污点前向分析')
        self.btn_taint_forward.setToolTip('从源污点向后追踪其传播路径')
        self.btn_taint_forward.clicked.connect(self._on_forward)
        self.btn_taint_forward.setEnabled(False)
        forward_form.addWidget(self.btn_taint_forward)
        
        forward_layout.addLayout(forward_form)
        
        # 增强功能选项
        enhanced_row = QtWidgets.QHBoxLayout()
        self.use_enhanced_chk = QtWidgets.QCheckBox('增强模式')
        self.use_enhanced_chk.setToolTip('启用字节级内存追踪、污点标签系统和汇合点检测')
        self.use_enhanced_chk.setChecked(False)
        enhanced_row.addWidget(self.use_enhanced_chk)
        
        self.show_confluence_chk = QtWidgets.QCheckBox('显示汇合点')
        self.show_confluence_chk.setToolTip('高亮显示多个污点来源合并的关键计算点')
        self.show_confluence_chk.setChecked(True)
        self.show_confluence_chk.setEnabled(False)
        enhanced_row.addWidget(self.show_confluence_chk)
        
        self.use_enhanced_chk.toggled.connect(self.show_confluence_chk.setEnabled)
        
        enhanced_row.addWidget(QtWidgets.QLabel('策略:'))
        self.taint_policy_combo = QtWidgets.QComboBox()
        self.taint_policy_combo.addItems(['NORMAL (推荐)', 'STRICT (严格)', 'LOOSE (宽松)'])
        self.taint_policy_combo.setToolTip(
            'STRICT: 只追踪显式数据流（减少误报）\n'
            'NORMAL: 含常见隐式流（平衡，推荐）\n'
            'LOOSE: 追踪所有可能路径（避免漏报）'
        )
        self.taint_policy_combo.setEnabled(False)
        enhanced_row.addWidget(self.taint_policy_combo)
        self.use_enhanced_chk.toggled.connect(self.taint_policy_combo.setEnabled)
        
        enhanced_row.addStretch(1)
        forward_layout.addLayout(enhanced_row)
        
        forward_group.setLayout(forward_layout)
        layout.addWidget(forward_group)
        
        # === 通用选项 ===
        options_row = QtWidgets.QHBoxLayout()
        self.samecall_chk = QtWidgets.QCheckBox('仅限同调用内')
        self.samecall_chk.setChecked(False)
        self.samecall_chk.setToolTip('勾选后仅在同一函数调用内追踪，不跨越函数边界')
        options_row.addWidget(self.samecall_chk)
        options_row.addStretch(1)
        layout.addLayout(options_row)

        # === 结果列表 ===
        self.list = QtWidgets.QTreeWidget()
        self.list.setHeaderLabels(['行号', 'PC', '方向', '标记', '表达式/指令', '之前', '之后', '调用#', '低8位变化', '位运算摘要'])
        self.list.setColumnWidth(0, 80)
        self.list.setColumnWidth(1, 110)
        self.list.setColumnWidth(3, 90)  # 标记列略宽，容纳"源头·立即数"
        self.list.setColumnWidth(4, 110)
        self.list.setColumnWidth(5, 110)
        self.list.setColumnWidth(6, 70)
        self.list.setColumnWidth(7, 100)
        self.list.setColumnWidth(8, 150)
        self.list.itemDoubleClicked.connect(self._on_double)
        self.list.itemClicked.connect(self._on_click)
        self._last_jump_ts = 0.0  # 节流

        # 右键菜单
        self.list.setContextMenuPolicy(QtCore.Qt.ContextMenuPolicy.CustomContextMenu)
        self.list.customContextMenuRequested.connect(self._on_list_context)
        layout.addWidget(self.list)

        # === 导出按钮 ===
        btns = QtWidgets.QHBoxLayout()
        self.btn_export_c = QtWidgets.QPushButton('导出伪C代码')
        self.btn_export_c.clicked.connect(self._on_export_c)
        self.btn_export_py = QtWidgets.QPushButton('导出Python代码')
        self.btn_export_py.clicked.connect(self._on_export_py)
        btns.addStretch(1)
        btns.addWidget(self.btn_export_c)
        btns.addWidget(self.btn_export_py)
        layout.addLayout(btns)

        self.setWidget(container)

        # 外部注入：parser
        self.parser = None
        self.eval_effaddr_cb = None  # 保留兼容性，但已不使用

        # 按钮启用状态
        self.input_edit.textChanged.connect(self._update_trace_btn_state)
        self.value_edit.textChanged.connect(self._update_trace_btn_state)
        self.taint_regs_edit.textChanged.connect(self._update_trace_btn_state)
        self.taint_mem_edit.textChanged.connect(self._update_trace_btn_state)

        # 异步 Worker
        self._backward_worker: Optional['BackwardTaintWorker'] = None
        self._backward_req_id: int = 0
        self._taint_worker: Optional['TaintWorker'] = None

    def set_font_point_size(self, point_size: int) -> None:
        """统一调整面板内主要控件的字体大小，用于与代码区同步缩放。"""
        try:
            # 列表与表头
            f = self.list.font()
            f.setPointSize(point_size)
            self.list.setFont(f)
            try:
                hf = self.list.header().font()
                hf.setPointSize(point_size)
                self.list.header().setFont(hf)
            except Exception:
                pass
            # 表单/按钮
            for w in [self.input_edit, self.value_edit, self.btn_trace_backward, 
                     self.taint_regs_edit, self.taint_mem_edit, self.btn_taint_forward,
                     self.btn_export_c, self.btn_export_py]:
                wf = w.font()
                wf.setPointSize(point_size)
                w.setFont(wf)
        except Exception:
            pass

    def attach(self, parser, eval_effaddr_cb) -> None:
        self.parser = parser
        # 内存对比已禁用，这里保留接口但不使用 eval_effaddr_cb
        self.eval_effaddr_cb = eval_effaddr_cb

    def _find_anchor_event_index(self) -> Optional[int]:
        """尽量从主窗口获取“当前代码区锚点”的事件索引。

        说明：
        - ValueFlowDock 的 parent 可能是 QDockWidget/中间容器，不一定直接是 MainWindow；
        - 历史上曾使用 `_get_current_event_index`，但当前主窗口对外接口是 `current_event_index()`；
        - 这里做父链遍历，找到任意提供上述接口的对象即可。
        """
        # 1) 沿 parent() 链向上找
        w = self
        while w is not None:
            try:
                if hasattr(w, 'current_event_index'):
                    idx = w.current_event_index()  # type: ignore[attr-defined]
                    if isinstance(idx, int):
                        return idx
                if hasattr(w, '_get_current_event_index'):
                    idx = w._get_current_event_index()  # type: ignore[attr-defined]
                    if isinstance(idx, int):
                        return idx
            except Exception:
                pass
            try:
                w = w.parent()  # type: ignore[assignment]
            except Exception:
                break
        # 2) 兜底：尝试 activeWindow（有些平台 parent 链不稳定）
        try:
            aw = QtWidgets.QApplication.activeWindow()
            if aw is not None and hasattr(aw, 'current_event_index'):
                idx = aw.current_event_index()  # type: ignore[attr-defined]
                if isinstance(idx, int):
                    return idx
        except Exception:
            pass
        return None

    def _on_trace_backward(self, anchor_idx: Optional[int] = None, exact_mode: bool = False) -> None:
        """反向追踪值来源的主入口
        
        Args:
            anchor_idx: 锚点事件索引。
            exact_mode: 精确模式。如果为True，直接以anchor_idx为起点追踪，不查找其他候选；
                       如果为False，基于该事件的PC地址（汇编指令）查找候选，如果多次执行则弹出选择对话框。
        """
        if not self.parser:
            return
        
        reg = (self.input_edit.text() or '').strip().lower()
        val_txt = (self.value_edit.text() or '').strip().lower()
        
        if not reg or not val_txt:
            QtWidgets.QMessageBox.information(self, '提示', '请同时输入寄存器名和值')
            return
        
        try:
            match_val = int(val_txt, 16) if val_txt.startswith('0x') else int(val_txt, 16)
        except Exception:
            QtWidgets.QMessageBox.warning(self, '值格式错误', '请输入十六进制值，例如 0x4 或 4')
            return
        
        # 如果没有提供锚点，尝试从主窗口获取当前代码区锚点
        if anchor_idx is None:
            anchor_idx = self._find_anchor_event_index()
        
        # 精确模式：直接使用锚点作为起点，不查找其他候选
        if exact_mode and anchor_idx is not None and 0 <= anchor_idx < len(self.parser.events):
            start_idx = anchor_idx
        # 非精确模式：查找候选
        elif anchor_idx is not None and 0 <= anchor_idx < len(self.parser.events):
            anchor_ev = self.parser.events[anchor_idx]
            anchor_pc = anchor_ev.pc
            
            # 查找所有执行该PC地址且寄存器值匹配的事件
            candidates = []
            if anchor_pc in self.parser.addr_index:
                pc_candidates = self.parser.addr_index[anchor_pc]
                # 过滤出包含目标寄存器且值匹配的事件
                for idx in pc_candidates:
                    ev = self.parser.events[idx]
                    # 检查读取的寄存器
                    for r, v in ev.reads.items():
                        if r.lower() == reg and (v & 0xFFFFFFFF) == match_val:
                            candidates.append((idx, ev))
                            break
                    else:
                        # 如果读取中没找到，检查写入的寄存器（写入前的值）
                        # 注意：这里需要检查的是执行前的值，不是写入后的值
                        # 所以我们只检查 reads，不检查 writes
                        pass
            
            if not candidates:
                QtWidgets.QMessageBox.information(
                    self, 
                    '未找到', 
                    f'未找到 PC=0x{anchor_pc:08x} 且 {reg}={val_txt} 的匹配事件\n\n'
                    f'提示：请确认该寄存器在此指令执行前的值是否为 {val_txt}'
                )
                return
            
            # 若有多个候选，弹出对话框让用户选择
            # 注意：即使只有一个候选，如果用户明确输入了值，也应该让用户确认
            start_idx = self._select_candidate_dialog(candidates, reg, match_val)
            if start_idx is None:
                return  # 用户取消
        else:
            # 没有锚点，使用原有逻辑：查找所有匹配 reg=value 的事件
            # 仅关注“执行前”的值（reads）：避免把“执行后写入产生的同值”也当作候选，导致误选/跑偏
            candidates = self.parser.find_value_candidates(reg, match_val, side='执行前')
            
            if not candidates:
                # 诊断信息：检查索引是否存在
                has_reg_index = reg in self.parser.reg_read_index or reg in self.parser.reg_write_index
                total_r1_reads = len(self.parser.reg_read_index.get(reg, []))
                total_r1_writes = len(self.parser.reg_write_index.get(reg, []))
                
                msg = f'未找到 {reg}={val_txt} 的匹配事件\n\n'
                msg += f'诊断信息：\n'
                msg += f'- 寄存器索引存在: {has_reg_index}\n'
                msg += f'- {reg} 读取次数: {total_r1_reads}\n'
                msg += f'- {reg} 写入次数: {total_r1_writes}\n'
                msg += f'- 查找值: 0x{match_val:x} ({match_val})\n'
                
                QtWidgets.QMessageBox.information(self, '未找到', msg)
                return
            
            # 若有多个候选，弹出对话框让用户选择
            if len(candidates) == 1:
                start_idx = candidates[0][0]
            else:
                start_idx = self._select_candidate_dialog(candidates, reg, match_val)
                if start_idx is None:
                    return  # 用户取消
        
        # 启动反向追踪
        same_call = bool(self.samecall_chk.isChecked())
        self._backward_req_id += 1
        req_id = self._backward_req_id
        
        self._set_busy(True)
        try:
            if self._backward_worker and self._backward_worker.isRunning():
                self._backward_worker.requestInterruption()
                self._backward_worker.wait(150)
        except Exception:
            pass
        
        self._backward_worker = BackwardTaintWorker(self.parser, reg, start_idx, match_val, same_call, req_id)
        self._backward_worker.finishedWithBackwardResults.connect(self._on_backward_ready)
        self._backward_worker.start()

    def _select_candidate_dialog(self, candidates: List[Tuple[int, 'TraceEvent']], reg: str, value: int) -> Optional[int]:
        """弹出对话框让用户从多个候选中选择追踪起点
        
        增强功能：
        - 显示所有寄存器的值（读取和写入）
        - 选择时联动更新主窗口的寄存器面板
        - 默认选中第一个候选
        """
        dlg = QtWidgets.QDialog(self)
        dlg.setWindowTitle(f'选择追踪起点（找到 {len(candidates)} 个 {reg}=0x{value:x} 的匹配位置）')
        lay = QtWidgets.QVBoxLayout(dlg)
        
        # 提示信息
        hint = QtWidgets.QLabel('提示：选择不同行时，主窗口的寄存器面板会实时更新，帮助您识别正确的执行点')
        hint.setStyleSheet('color: #8bd5ff; padding: 5px;')
        lay.addWidget(hint)
        
        tv = QtWidgets.QTreeWidget()
        # 显示行号、时间戳、PC、指令和寄存器读取信息
        tv.setHeaderLabels(['行号', '时间戳', 'PC', '指令', '寄存器读取'])
        tv.setColumnWidth(0, 80)
        tv.setColumnWidth(1, 100)
        tv.setColumnWidth(2, 110)
        tv.setColumnWidth(3, 250)
        tv.setColumnWidth(4, 350)  # 寄存器读取列（加宽以显示更多寄存器）
        
        for idx, ev in candidates:
            # 构建寄存器读取信息（显示所有读取的寄存器）
            regs_info = []
            for r, v in sorted(ev.reads.items()):
                regs_info.append(f"{r}=0x{v:x}")
            regs_str = ' '.join(regs_info) if regs_info else '(无)'
            
            item = QtWidgets.QTreeWidgetItem([
                str(ev.line_no),
                f"[{ev.timestamp}]",
                f"0x{ev.pc:08x}",
                ev.asm,
                regs_str
            ])
            item.setData(0, QtCore.Qt.ItemDataRole.UserRole, idx)
            tv.addTopLevelItem(item)
        
        # 默认选中第一个
        if tv.topLevelItemCount() > 0:
            tv.setCurrentItem(tv.topLevelItem(0))
        
        # 选择改变时，更新主窗口寄存器面板
        def _on_selection_changed():
            cur = tv.currentItem()
            if cur and self.parent():
                try:
                    idx = cur.data(0, QtCore.Qt.ItemDataRole.UserRole)
                    main_window = self.parent()
                    # 调用主窗口的寄存器复原方法
                    if hasattr(main_window, '_rebuild_regs_async'):
                        main_window._rebuild_regs_async(idx)
                except Exception as e:
                    pass
        
        tv.itemSelectionChanged.connect(_on_selection_changed)
        
        # 初始化：显示第一个候选的寄存器
        if candidates:
            _on_selection_changed()
        
        # 双击确认
        def _on_double(it, col):
            dlg._sel = it.data(0, QtCore.Qt.ItemDataRole.UserRole)
            dlg.accept()
        tv.itemDoubleClicked.connect(_on_double)
        lay.addWidget(tv)
        
        # 按钮
        btns = QtWidgets.QHBoxLayout()
        okb = QtWidgets.QPushButton('确定')
        cancel = QtWidgets.QPushButton('取消')
        
        def _on_ok():
            cur = tv.currentItem()
            if cur:
                dlg._sel = cur.data(0, QtCore.Qt.ItemDataRole.UserRole)
                dlg.accept()
        
        okb.clicked.connect(_on_ok)
        cancel.clicked.connect(dlg.reject)
        btns.addStretch(1)
        btns.addWidget(okb)
        btns.addWidget(cancel)
        lay.addLayout(btns)
        
        dlg.resize(1000, 500)
        dlg._sel = None
        
        if dlg.exec() == QtWidgets.QDialog.DialogCode.Accepted:
            return dlg._sel
        return None

    def _on_backward_ready(self, hits: List[int], reg: str, req_id: int) -> None:
        """处理反向追踪结果"""
        if req_id != self._backward_req_id:
            return  # 过期请求
        
        self._set_busy(False)
        
        if not hits:
            QtWidgets.QMessageBox.information(self, '反向追踪', '未找到值的来源路径')
            return
        
        # 渲染结果列表（hits已经是降序：最早的在前）
        self._render_backward_results(reg, hits)
        
        # 跳转到第一个事件（最早的来源）
        if hits:
            self.jumpToEvent.emit(hits[0])

    def _render_backward_results(self, reg: str, indices: List[int]) -> None:
        """渲染反向追踪结果到列表（降序排列）"""
        self.list.setUpdatesEnabled(False)
        try:
            self.list.clear()
            for idx in indices:
                ev = self.parser.events[idx]
                
                # 获取寄存器前后值
                before = ev.reads.get(reg)
                after = ev.writes.get(reg)
                if before is None or after is None:
                    fb, fa, _ = self._fallback_before_after(idx, reg)
                    if before is None:
                        before = fb
                    if after is None:
                        after = fa
                
                # 判断方向
                rw = 'W' if reg in ev.writes else ('R' if reg in ev.reads else '')
                
                # 获取标记（包含终止原因）
                tag = self._classify_tag(reg, idx)
                term_reason = None  # 初始化，避免 UnboundLocalError
                # 增强标记：检查终止条件
                if reg in ev.writes:
                    term_reason = self.parser._check_backward_termination(idx, reg)
                    if term_reason:
                        tag = term_reason
                
                # 构建列表项
                item = QtWidgets.QTreeWidgetItem([
                    str(ev.line_no), 
                    f"0x{ev.pc:08x}", 
                    rw, 
                    tag, 
                    ev.asm,
                    '' if before is None else f"0x{before:08x}",
                    '' if after is None else f"0x{after:08x}",
                    str(getattr(ev, 'call_id', 0)),
                    self._fmt_low8(reg, idx), 
                    self._fmt_c_summary(ev.asm)
                ])
                item.setData(0, QtCore.Qt.ItemDataRole.UserRole, idx)
                
                # 源头行高亮（可选）
                if term_reason:
                    item.setForeground(2, QtGui.QBrush(QtGui.QColor('#4CAF50')))  # 绿色标记源头
                
                self.list.addTopLevelItem(item)
        finally:
            self.list.setUpdatesEnabled(True)
            self.list.viewport().update()

    def _on_search(self) -> None:
        """统一入口：优先按“寄存器+值”做值链追踪，否则使用污点前向。"""
        reg = (self.input_edit.text() or '').strip().lower()
        val_txt = (self.value_edit.text() or '').strip().lower()
        if reg and val_txt:
            self._on_trace_value()
        else:
            self._on_forward()
        self._update_trace_btn_state()

    def _on_forward(self) -> None:
        """统一入口：仅进行污点前向分析。"""
        has_taint = bool((self.taint_regs_edit.text() or '').strip() or (self.taint_mem_edit.text() or '').strip())
        if not has_taint:
            QtWidgets.QMessageBox.information(self, '提示', '请在下方输入污点寄存器/内存')
            return
        sel = self.list.selectedItems()
        start_idx = 0
        if sel:
            maybe = sel[0].data(0, QtCore.Qt.ItemDataRole.UserRole)
            if isinstance(maybe, int):
                start_idx = maybe
        self._run_taint(start_idx=start_idx)

    def _search_register(self, reg: str, in_scope_fn, match_val: Optional[int], side_sel: str) -> None:
        reg = reg.lower()
        for idx, ev in enumerate(self.parser.events):
            if not in_scope_fn(ev):
                continue
            rw = None
            if reg in ev.writes:
                rw = 'W'
            elif reg in ev.reads:
                rw = 'R'
            if rw:
                before = ev.reads.get(reg)
                after = ev.writes.get(reg)
                # 兜底补全：必要时使用寄存器复原
                if before is None or after is None:
                    fb, fa, _ = self._fallback_before_after(idx, reg)
                    if before is None:
                        before = fb
                    if after is None:
                        after = fa
                # 按值匹配（默认执行前）
                if match_val is not None:
                    b = None if before is None else (before & 0xFFFFFFFF)
                    a = None if after is None else (after & 0xFFFFFFFF)
                    mv = match_val & 0xFFFFFFFF
                    if side_sel == '执行前' and b != mv:
                        continue
                    if side_sel == '执行后' and a != mv:
                        continue
                    if side_sel == '任意' and (b != mv and a != mv):
                        continue
                low8 = self._fmt_low8(reg, idx)
                bitops = self._fmt_c_summary(ev.asm)
                tag = self._classify_tag(reg, idx)
                item = QtWidgets.QTreeWidgetItem([
                    str(ev.line_no), f'0x{ev.pc:08x}', rw, tag, ev.asm,
                    '' if before is None else f"0x{before:08x}",
                    '' if after is None else f"0x{after:08x}",
                    str(getattr(ev, 'call_id', 0)),
                    low8, bitops
                ])
                item.setData(0, QtCore.Qt.ItemDataRole.UserRole, idx)
                self.list.addTopLevelItem(item)

    def _search_memory(self, addr_range: Tuple[int, int], in_scope_fn) -> None:
        lo, hi = addr_range
        for idx, ev in enumerate(self.parser.events):
            if not in_scope_fn(ev):
                continue
            if self.eval_effaddr_cb is None:
                break
            # 只粗略匹配常见 str/ldr/strb/ldrb/strh/ldrh
            asm = ev.asm.lower()
            if not any(k in asm for k in ('str', 'ldr')):
                continue
            eff = self.eval_effaddr_cb(idx)
            if eff is None:
                continue
            if lo <= eff <= hi:
                rw = 'W' if asm.startswith('str') else 'R'
                # 未指定寄存器的 memory 事件：尝试自动补全前/后值
                low8 = self._fmt_low8(None, idx)
                bitops = self._fmt_c_summary(ev.asm)
                tag = self._classify_tag(None, idx)
                fb, fa, _auto = self._fallback_before_after(idx, None)
                item = QtWidgets.QTreeWidgetItem([
                    str(ev.line_no), f'0x{ev.pc:08x}', rw, tag, ev.asm,
                    '' if fb is None else f"0x{fb:08x}",
                    '' if fa is None else f"0x{fa:08x}",
                    str(getattr(ev, 'call_id', 0)), low8, bitops
                ])
                item.setData(0, QtCore.Qt.ItemDataRole.UserRole, idx)
                self.list.addTopLevelItem(item)

    # 保留占位，避免旧调用；当前不再使用作用域筛选
    def _build_scope_filter(self):
        return lambda ev: True

    def _on_double(self, item: QtWidgets.QTreeWidgetItem, col: int) -> None:
        idx = item.data(0, QtCore.Qt.ItemDataRole.UserRole)
        if not isinstance(idx, int):
            return
        # 简单节流：两次跳转间隔 >= 80ms
        now = time.perf_counter()
        if now - getattr(self, '_last_jump_ts', 0.0) < 0.08:
            return
        self._last_jump_ts = now
        self.jumpToEvent.emit(idx)

    def _on_click(self, item: QtWidgets.QTreeWidgetItem, col: int) -> None:
        # 单击也跳转，便于快速观察寄存器面板随行变化（同样使用节流）
        self._on_double(item, col)

    # === 值路径追踪 ===
    def _on_trace_value(self) -> None:
        if not self.parser:
            return
        reg = (self.input_edit.text() or '').strip().lower()
        if not reg:
            QtWidgets.QMessageBox.information(self, '提示', '请先在上方输入寄存器名，例如 r1')
            return
        val_txt = (self.value_edit.text() or '').strip().lower()
        if not val_txt:
            QtWidgets.QMessageBox.information(self, '提示', '请填写要追踪的值（十六进制，如 0xfffffffb）')
            return
        try:
            match_val = int(val_txt, 16) & 0xFFFFFFFF
        except Exception:
            QtWidgets.QMessageBox.warning(self, '值格式错误', '请填写十六进制值，例如 0xfffffffb')
            return
        # 直接基于倒排索引全局收集候选（与右键“指定值追踪”一致），按“运行前/运行后”侧过滤
        candidates = []  # (idx, ev, before, after)
        seen = set()
        want_after = (self.side_combo.currentText() == '运行后')
        if want_after:
            for idx in (self.parser.reg_write_index.get(reg, []) or []):
                ev = self.parser.events[idx]
                try:
                    a = self.parser._get_write_value(ev, reg)
                except Exception:
                    a = ev.writes.get(reg)
                if a is not None and (a & 0xFFFFFFFF) == match_val and idx not in seen:
                    candidates.append((idx, ev, ev.reads.get(reg), a))
                    seen.add(idx)
        else:
            for idx in (self.parser.reg_read_index.get(reg, []) or []):
                ev = self.parser.events[idx]
                try:
                    b = self.parser._get_read_value(ev, reg)
                except Exception:
                    b = ev.reads.get(reg)
                if b is not None and (b & 0xFFFFFFFF) == match_val and idx not in seen:
                    candidates.append((idx, ev, b, ev.writes.get(reg)))
                    seen.add(idx)

        if not candidates:
            QtWidgets.QMessageBox.information(self, '未找到', '当前作用域内未匹配到该值。请检查寄存器名、值或作用域设置。')
            return

        # 选择起点（优先使用主窗口当前行锚点），保证与“右键当前行追踪”一致
        start_idx = None
        # 尝试从主窗口获取当前代码行索引
        try:
            parent = self.parent()
            if hasattr(parent, 'current_event_index'):
                idx_hint = parent.current_event_index()
                if isinstance(idx_hint, int):
                    # 若该行即是候选之一，直接使用它
                    for i, (cidx, _, _, _) in enumerate(candidates):
                        if cidx == idx_hint:
                            start_idx = idx_hint
                            break
        except Exception:
            pass
        if start_idx is None and len(candidates) == 1:
            start_idx = candidates[0][0]
        else:
            start_idx = self._select_candidate_dialog(reg, match_val, '任意', candidates)
            if start_idx is None:
                return

        # 构建值路径
        # 起点侧以用户选择为准
        side_sel = '执行后' if want_after else '执行前'
        cache_key = f"{reg}|{match_val:08x}|{side_sel}|{start_idx}"
        if cache_key in self._chain_cache:
            chain_indices = self._chain_cache[cache_key]
            self._render_chain_list_fast(reg, chain_indices)
            return

        # 后台计算，避免卡顿
        self._chain_req_id += 1
        req_id = self._chain_req_id
        self._set_busy(True)
        if self._chain_worker and self._chain_worker.isRunning():
            try:
                self._chain_worker.requestInterruption()
                # 等待上一任务退出，避免 QThread 销毁警告
                self._chain_worker.wait(150)
            except Exception:
                pass
        self._chain_worker = ChainWorker(self.parser, reg, start_idx, match_val, side_sel, req_id)
        self._chain_worker.finishedWithId.connect(self._on_chain_ready)
        self._chain_worker.start()
        # 保存上下文，便于解释
        self._last_trace_ctx = {'reg': reg, 'start_idx': start_idx, 'match_val': match_val, 'side': side_sel}

    def _build_value_chain(self, reg: str, start_idx: int, val: int, side_sel: str) -> List[int]:
        # 确定写入该值的起点事件
        writer_idx = None
        if side_sel == '执行后' and reg in self.parser.events[start_idx].writes and (self.parser.events[start_idx].writes.get(reg) & 0xFFFFFFFF) == (val & 0xFFFFFFFF):
            writer_idx = start_idx
        else:
            writer_idx = self._find_prev_write_with_value(reg, start_idx, val)
        if writer_idx is None:
            writer_idx = start_idx

        chain: List[int] = []
        # 上一个写入（为上下文提供来源，例如 add ...）
        prev_writer = self._find_prev_write_any(reg, writer_idx)
        if prev_writer is not None:
            chain.append(prev_writer)
        # 当前写入（将寄存器设为目标值）
        if writer_idx not in chain:
            chain.append(writer_idx)
        # 向后收集：直到下一个写入改变该寄存器的值为止，包含所有读取
        for j in range(writer_idx + 1, len(self.parser.events)):
            ev = self.parser.events[j]
            if reg in ev.writes:
                a = ev.writes.get(reg)
                if a is None or (a & 0xFFFFFFFF) != (val & 0xFFFFFFFF):
                    break
                else:
                    chain.append(j)
                    continue
            if reg in ev.reads:
                chain.append(j)
        return chain

    def _find_prev_write_with_value(self, reg: str, idx: int, val: int) -> Optional[int]:
        for j in range(idx - 1, -1, -1):
            ev = self.parser.events[j]
            if reg in ev.writes:
                a = ev.writes.get(reg)
                if a is not None and (a & 0xFFFFFFFF) == (val & 0xFFFFFFFF):
                    return j
        return None

    def _find_prev_write_any(self, reg: str, idx: int) -> Optional[int]:
        for j in range(idx - 1, -1, -1):
            if reg in self.parser.events[j].writes:
                return j
        return None

    def _fmt_with_reg_context(self, ev, reg: str, before: Optional[int], after: Optional[int]) -> str:
        # 在指令列追加寄存器上下文，如："ldr r1, [r1, #4]"  r1=0xe4fff404 => r1=0xfffffffb
        parts = [ev.asm]
        ctx = []
        if before is not None or after is not None:
            b = '' if before is None else f"r1=0x{before:08x}" if reg == 'r1' else f"{reg}=0x{before:08x}"
            a = '' if after is None else f"r1=0x{after:08x}" if reg == 'r1' else f"{reg}=0x{after:08x}"
            if b or a:
                arrow = ' => ' if b and a else ''
                ctx.append(f"{b}{arrow}{a}")
        # 附带显示参与的其它寄存器读取值（最多两个）
        extras = []
        for k, v in list(ev.reads.items()):
            if k == reg:
                continue
            extras.append(f"{k}=0x{v:08x}")
            if len(extras) >= 2:
                break
        if extras:
            ctx.append(' '.join(extras))
        if ctx:
            parts.append(' [' + '  '.join(ctx) + ']')
        return ' '.join(parts)

    def _update_trace_btn_state(self) -> None:
        """更新追踪按钮的启用状态"""
        # 反向追踪：必须同时填写寄存器和值
        has_reg = bool((self.input_edit.text() or '').strip())
        has_val = bool((self.value_edit.text() or '').strip())
        self.btn_trace_backward.setEnabled(has_reg and has_val)
        
        # 前向追踪：必须填写源寄存器或源内存
        has_taint = bool((self.taint_regs_edit.text() or '').strip() or (self.taint_mem_edit.text() or '').strip())
        self.btn_taint_forward.setEnabled(has_taint)

    def _on_chain_ready(self, indices: List[int], reg: str, req_id: int) -> None:
        if req_id != self._chain_req_id:
            return  # 已过期
        self._set_busy(False)
        # 缓存键与上下文一致：寄存器+值+侧+起点
        try:
            ctx = getattr(self, '_last_trace_ctx', {}) or {}
            mv = ctx.get('match_val', 0)
            side = ctx.get('side', '')
            sidx = ctx.get('start_idx', 0)
            cache_key = f"{reg}|{mv:08x}|{side}|{sidx}"
            # LRU 写入
            self._chain_cache[cache_key] = list(indices)
            # 裁剪容量
            while len(self._chain_cache) > self._chain_cache_cap:
                try:
                    self._chain_cache.popitem(last=False)
                except Exception:
                    self._chain_cache.clear()
                    break
        except Exception:
            pass
        # 渲染
        self._render_chain_list_fast(reg, indices)
        # 附带来源解释
        try:
            ctx = getattr(self, '_last_trace_ctx', None)
            if ctx and self.parser and indices:
                info = self.parser.analyze_value_origin(ctx['reg'], ctx['start_idx'], ctx['match_val'], ctx['side'])
                self._show_origin_info(info)
        except Exception:
            pass

    def _show_origin_info(self, info: dict) -> None:
        if not isinstance(info, dict):
            return
        lines = []
        d = info.get('direct')
        if d:
            lines.append(f"直接来源：{d}")
        for it in info.get('indirect', []) or []:
            lines.append(str(it))
        gaps = info.get('gaps', []) or []
        for g in gaps:
            if isinstance(g, dict):
                lines.append(f"溯源缺口：{g.get('type')} {g.get('addr')} {g.get('hint','')}")
            else:
                lines.append(str(g))
        if lines:
            try:
                self.parent().statusBar().showMessage(' | '.join(lines)[:300], 6000)  # type: ignore[union-attr]
            except Exception:
                QtWidgets.QToolTip.showText(self.mapToGlobal(QtCore.QPoint(0, 0)), ' | '.join(lines)[:300])

    def _render_chain_list_fast(self, reg: str, chain_indices: List[int]) -> None:
        self.list.setUpdatesEnabled(False)
        try:
            self.list.clear()
            for idx in chain_indices:
                ev = self.parser.events[idx]
                before = ev.reads.get(reg)
                after = ev.writes.get(reg)
                if before is None or after is None:
                    fb, fa, _ = self._fallback_before_after(idx, reg)
                    if before is None:
                        before = fb
                    if after is None:
                        after = fa
                rw = 'W' if reg in ev.writes else ('R' if reg in ev.reads else '')
                asm = self._fmt_with_reg_context(ev, reg, before, after)
                tag = self._classify_tag(reg, idx)
                item = QtWidgets.QTreeWidgetItem([
                    str(ev.line_no), f"0x{ev.pc:08x}", rw, tag, asm,
                    '' if before is None else f"0x{before:08x}",
                    '' if after is None else f"0x{after:08x}",
                    str(getattr(ev, 'call_id', 0)),
                    self._fmt_low8(reg, idx), self._fmt_c_summary(ev.asm)
                ])
                item.setData(0, QtCore.Qt.ItemDataRole.UserRole, idx)
                self.list.addTopLevelItem(item)
        finally:
            self.list.setUpdatesEnabled(True)
            self.list.viewport().update()

    # === 终止条件与节点标注 ===
    def _classify_tag(self, reg: Optional[str], idx: int) -> str:
        if not self.parser:
            return ''
        ev = self.parser.events[idx]
        s = ev.asm.lower()
        # 1) 初始数据源
        if reg:
            if self.parser._is_immediate_write(ev, reg) or self.parser._is_constant_zero_write(ev, reg):
                return '源头'
        # rodata/常量内存（通过“无前序 store”的ldr识别）
        if s.startswith('ldr') and (not ev.writes or (reg and reg in ev.writes)):
            try:
                if self.parser._is_load_from_const_memory(idx, reg or next(iter(ev.writes.keys()), '')):
                    return '常量'
            except Exception:
                pass
        # 2) 系统/外部边界（粗识别：svc/bl libc 符号不可用时退化为空）
        if s.startswith('svc'):
            return '边界'
        try:
            if s.startswith('bl '):
                return '调用-外' if self.parser.is_external_call(idx) else '调用'
        except Exception:
            pass
        # 3) 循环/递归起点（简单：同一 asm 在短窗口内重复）
        try:
            if self.parser.is_loop_head(idx, window=32):
                return '循环'
        except Exception:
            pass
        # 4) 栈地址访问提示
        try:
            if self.parser.is_stack_address(idx):
                return '栈'
        except Exception:
            pass
        # 兜底分类，避免空白
        try:
            if s.startswith('ldr'):
                return '读内存'
            if s.startswith('str'):
                return '写内存'
            if s.startswith(('mov', 'mvn')):
                return '传送'
            mnem = s.split(' ', 1)[0]
            if mnem in ('add','sub','eor','orr','or','and','bic','orn','mul','mla','mls','lsl','lsr','asr','ror'):
                return '运算'
        except Exception:
            pass
        return ''

    def _set_busy(self, busy: bool) -> None:
        if busy:
            QtWidgets.QApplication.setOverrideCursor(QtCore.Qt.CursorShape.WaitCursor)
        else:
            QtWidgets.QApplication.restoreOverrideCursor()

    # === 列表右键菜单 ===
    def _on_list_context(self, pos: QtCore.QPoint) -> None:
        sel = self.list.selectedItems()
        menu = QtWidgets.QMenu(self)
        act_copy = menu.addAction('复制选中行')
        act_c = menu.addAction('导出所选为伪C')
        act_py = menu.addAction('导出所选为伪Python')
        menu.addSeparator()
        act_taint_here = menu.addAction('以此行为起点做污点分析')
        if not sel:
            act_copy.setEnabled(False)
            act_c.setEnabled(False)
            act_py.setEnabled(False)
            act_taint_here.setEnabled(False)
        act_copy.triggered.connect(self._copy_selected_rows)
        act_c.triggered.connect(lambda: self._export_code_via_selection(mode='c'))
        act_py.triggered.connect(lambda: self._export_code_via_selection(mode='py'))
        act_taint_here.triggered.connect(self._on_taint_run_from_context)
        menu.exec_(self.list.mapToGlobal(pos))

    def _copy_selected_rows(self) -> None:
        sel = self.list.selectedItems()
        if not sel:
            return
        pairs = []  # (idx, item)
        for it in sel:
            idx = it.data(0, QtCore.Qt.ItemDataRole.UserRole)
            if isinstance(idx, int):
                pairs.append((idx, it))
        pairs.sort(key=lambda x: x[0])
        lines = []
        for _, it in pairs:
            cols = [it.text(c) for c in range(self.list.columnCount())]
            lines.append('\t'.join(cols))
        QtWidgets.QApplication.clipboard().setText('\n'.join(lines))
        try:
            self.parent().statusBar().showMessage('已复制到剪贴板', 1500)  # type: ignore[union-attr]
        except Exception:
            QtWidgets.QToolTip.showText(self.mapToGlobal(QtCore.QPoint(0, 0)), '已复制到剪贴板')

    # === 统一导出通道，支持大选择异步生成 ===
    def _export_code_via_selection(self, mode: str) -> None:
        if not self.parser:
            return
        sel = self.list.selectedItems()
        indices = [it.data(0, QtCore.Qt.ItemDataRole.UserRole) for it in sel if isinstance(it.data(0, QtCore.Qt.ItemDataRole.UserRole), int)]
        if not indices:
            QtWidgets.QMessageBox.information(self, '提示', '请在结果列表中选择若干行再导出')
            return
        indices = sorted(set(indices))
        # 大体量异步生成，避免 UI 卡顿
        if len(indices) >= 800:
            self._set_busy(True)
            try:
                if hasattr(self, '_codegen_worker') and self._codegen_worker and self._codegen_worker.isRunning():
                    self._codegen_worker.requestInterruption()
            except Exception:
                pass
            self._codegen_worker = _CodeGenWorker(self, indices, mode)
            self._codegen_worker.finishedWithCode.connect(self._on_codegen_ready)
            self._codegen_worker.start()
            return
        # 小体量：同步生成
        if mode == 'c':
            code = self._gen_c_code(indices)
            title, name, filt = '导出伪C代码', 'replay.c', 'C Files (*.c);;All Files (*)'
        else:
            code = self._gen_py_code(indices)
            title, name, filt = '导出 Python 伪代码', 'replay.py', 'Python Files (*.py);;All Files (*)'
        self._show_code_dialog(title, name, filt, code)

    # === 污点分析 ===
    def _on_taint_run_from_context(self) -> None:
        sel = self.list.selectedItems()
        if not sel:
            return
        it = sel[0]
        idx = it.data(0, QtCore.Qt.ItemDataRole.UserRole)
        if not isinstance(idx, int):
            return
        self._run_taint(start_idx=idx)

    def _on_taint_run(self) -> None:
        sel = self.list.selectedItems()
        start_idx = 0
        if sel:
            maybe = sel[0].data(0, QtCore.Qt.ItemDataRole.UserRole)
            if isinstance(maybe, int):
                start_idx = maybe
        self._run_taint(start_idx=start_idx)

    # === 溯源入口 ===
    def _on_provenance(self) -> None:
        if not self.parser:
            return
        sel = self.list.selectedItems()
        if sel:
            idx = sel[0].data(0, QtCore.Qt.ItemDataRole.UserRole)
        else:
            idx = 0
        if not isinstance(idx, int):
            idx = 0
        reg, ok = QtWidgets.QInputDialog.getText(self, '溯源', '输入寄存器名（如 r1/x0）：')
        if not ok or not reg:
            return
        reg = reg.strip().lower()
        side = '执行后'
        self._set_busy(True)
        try:
            if self._prov_worker and self._prov_worker.isRunning():
                self._prov_worker.requestInterruption()
        except Exception:
            pass
        self._prov_worker = _ProvenanceWorker(self.parser, reg, idx, side)
        self._prov_worker.finishedWithPath.connect(self._on_provenance_ready)
        self._prov_worker.start()

    @QtCore.pyqtSlot(object)
    def _show_save_dialog(self, content: str) -> None:
        # 替换为导出 trace 文本
        dlg = QtWidgets.QDialog(self)
        dlg.setWindowTitle('导出溯源信息为 trace')
        lay = QtWidgets.QVBoxLayout(dlg)
        edit = QtWidgets.QPlainTextEdit()
        edit.setPlainText(content)
        lay.addWidget(edit)
        btns = QtWidgets.QHBoxLayout()
        btn_copy = QtWidgets.QPushButton('复制到剪贴板')
        btn_save = QtWidgets.QPushButton('保存为 .trace')
        btn_copy.clicked.connect(lambda: (QtWidgets.QApplication.clipboard().setText(edit.toPlainText()), QtWidgets.QMessageBox.information(dlg, '已复制', '内容已复制')))
        def _save():
            path, _ = QtWidgets.QFileDialog.getSaveFileName(dlg, '保存为 .trace', 'provenance.trace', 'Trace Files (*.trace *.txt);;All Files (*)')
            if path:
                try:
                    with open(path, 'w', encoding='utf-8') as f:
                        f.write(edit.toPlainText())
                    QtWidgets.QMessageBox.information(dlg, '已保存', f'已保存到\n{path}')
                except Exception as e:
                    QtWidgets.QMessageBox.critical(dlg, '保存失败', str(e))
        btn_save.clicked.connect(_save)
        btns.addStretch(1)
        btns.addWidget(btn_copy)
        btns.addWidget(btn_save)
        lay.addLayout(btns)
        dlg.resize(760, 560)
        dlg.exec()

    @QtCore.pyqtSlot(list, list, str)
    def _on_provenance_ready(self, nodes_edges_reg: list, edges: list = None, reg: str = '') -> None:
        self._set_busy(False)
        # 兼容信号打包参数（使用 _ProvenanceWorker 的签名）
        if edges is None and isinstance(nodes_edges_reg, list):
            indices = nodes_edges_reg
        else:
            indices = nodes_edges_reg or []
        if not indices:
            QtWidgets.QMessageBox.information(self, '溯源', '未能构建溯源路径')
            return
        self.list.setUpdatesEnabled(False)
        try:
            self.list.clear()
            for idx in indices:
                ev = self.parser.events[idx]
                before = ev.reads.get(reg) if reg else None
                after = ev.writes.get(reg) if reg else None
                if before is None or after is None:
                    fb, fa, _ = self._fallback_before_after(idx, reg or None)
                    if before is None:
                        before = fb
                    if after is None:
                        after = fa
                asm = self._fmt_with_reg_context(ev, reg, before, after)
                rw = 'W' if reg in ev.writes else ('R' if reg in ev.reads else '')
                tag = '[溯源]'
                item = QtWidgets.QTreeWidgetItem([
                    str(ev.line_no), f"0x{ev.pc:08x}", rw, tag, asm,
                    '' if before is None else f"0x{before:08x}",
                    '' if after is None else f"0x{after:08x}",
                    str(getattr(ev, 'call_id', 0)),
                    self._fmt_low8(reg, idx), self._fmt_c_summary(ev.asm)
                ])
                item.setData(0, QtCore.Qt.ItemDataRole.UserRole, idx)
                self.list.addTopLevelItem(item)
            # 改为导出“当前列表中所有行”的原始 trace 文本
            try:
                idxs = []
                for i in range(self.list.topLevelItemCount()):
                    it = self.list.topLevelItem(i)
                    v = it.data(0, QtCore.Qt.ItemDataRole.UserRole)
                    if isinstance(v, int):
                        idxs.append(v)
                txt = self._build_trace_text(idxs)
                self._show_save_dialog(txt)
            except Exception:
                pass
        finally:
            self.list.setUpdatesEnabled(True)
            self.list.viewport().update()

    def _build_trace_text(self, indices: list) -> str:
        lines = []
        for idx in indices:
            ev = self.parser.events[idx]
            raw = ev.raw or ''
            # 只导出“汇编之前”的 trace 内容
            if raw:
                try:
                    prefix = raw.split('"')[0].rstrip()
                except Exception:
                    prefix = raw
            else:
                # 回退：构造到冒号为止
                prefix = f"[{ev.timestamp}][{ev.module} {ev.module_offset}] [{ev.encoding}] 0x{ev.pc:08x}:"
            lines.append(prefix)
        return '\n'.join(lines)

    def _parse_taint_inputs(self) -> tuple:
        """解析污点输入，返回 (source_regs, source_addrs, target_regs, target_addrs)"""
        # 源污点
        regs_txt = (self.taint_regs_edit.text() or '').strip()
        mem_txt = (self.taint_mem_edit.text() or '').strip()
        source_regs = [s.strip().lower() for s in regs_txt.split(',') if s.strip()]
        source_addrs = []
        if mem_txt:
            for s in mem_txt.split(','):
                st = s.strip().lower()
                if not st:
                    continue
                try:
                    # 正确处理十六进制和十进制
                    if st.startswith('0x'):
                        source_addrs.append(int(st, 16))
                    else:
                        # 尝试十六进制，失败则尝试十进制
                        try:
                            source_addrs.append(int(st, 16))
                        except ValueError:
                            source_addrs.append(int(st, 10))
                except Exception:
                    # 静默跳过无效输入
                    pass
        
        # 目标污点（高级模式）
        target_regs = []
        target_addrs = []
        if hasattr(self, 'target_regs_edit') and hasattr(self, 'target_mem_edit'):
            target_regs_txt = (self.target_regs_edit.text() or '').strip()
            target_mem_txt = (self.target_mem_edit.text() or '').strip()
            target_regs = [s.strip().lower() for s in target_regs_txt.split(',') if s.strip()]
            if target_mem_txt:
                for s in target_mem_txt.split(','):
                    st = s.strip().lower()
                    if not st:
                        continue
                    try:
                        # 正确处理十六进制和十进制
                        if st.startswith('0x'):
                            target_addrs.append(int(st, 16))
                        else:
                            try:
                                target_addrs.append(int(st, 16))
                            except ValueError:
                                target_addrs.append(int(st, 10))
                    except Exception:
                        pass
        
        return source_regs, source_addrs, target_regs, target_addrs

    def _run_taint(self, start_idx: int) -> None:
        if not self.parser:
            return
        source_regs, source_addrs, target_regs, target_addrs = self._parse_taint_inputs()
        same_call = bool(self.samecall_chk.isChecked())
        
        # 检查是否启用增强模式
        use_enhanced = bool(getattr(self, 'use_enhanced_chk', None) and self.use_enhanced_chk.isChecked())
        show_confluence = bool(getattr(self, 'show_confluence_chk', None) and self.show_confluence_chk.isChecked())
        
        # 获取污点策略
        policy_text = 'normal'
        if hasattr(self, 'taint_policy_combo'):
            policy_idx = self.taint_policy_combo.currentIndex()
            policy_text = ['normal', 'strict', 'loose'][policy_idx]
        
        # 高级模式选项（向后兼容）
        enable_mem_taint = bool(getattr(self, 'enable_mem_taint_chk', None) and self.enable_mem_taint_chk.isChecked())
        track_constants = bool(getattr(self, 'track_constants_chk', None) and self.track_constants_chk.isChecked())
        advanced_mode = bool(getattr(self, 'advanced_mode_chk', None) and self.advanced_mode_chk.isChecked())
        
        # 若主窗口提供当前代码区锚点，则优先以该行作为起点（避免默认从 0 开始导致“只看到开头几行”）
        idx = self._find_anchor_event_index()
        if isinstance(idx, int):
            start_idx = idx
        self._set_busy(True)
        try:
            if hasattr(self, '_taint_worker') and self._taint_worker and self._taint_worker.isRunning():
                self._taint_worker.requestInterruption()
        except Exception:
            pass
        # 若已有在跑的污点线程，则请求中断并等待片刻
        try:
            if hasattr(self, '_taint_worker') and self._taint_worker and self._taint_worker.isRunning():
                self._taint_worker.requestInterruption()
                self._taint_worker.wait(150)
        except Exception:
            pass
            
        # 根据模式选择不同的Worker
        if use_enhanced:
            # 使用增强污点分析
            self._taint_worker = EnhancedTaintWorker(
                self.parser, start_idx, source_regs, source_addrs,
                same_call, policy_text, show_confluence
            )
            self._taint_worker.finishedWithEnhancedResults.connect(self._on_enhanced_taint_ready)
        elif advanced_mode and target_regs:
            # 使用原高级模式
            self._taint_worker = AdvancedTaintWorker(
                self.parser, start_idx, source_regs, source_addrs, 
                target_regs, target_addrs, same_call, 
                enable_mem_taint, track_constants
            )
            self._taint_worker.finishedWithAdvancedResults.connect(self._on_advanced_taint_ready)
        else:
            # 使用原基础模式
            self._taint_worker = TaintWorker(self.parser, start_idx, source_regs, source_addrs, same_call)
            self._taint_worker.finishedWithHits.connect(self._on_taint_ready)
        self._taint_worker.start()

    @QtCore.pyqtSlot(dict)
    def _on_advanced_taint_ready(self, results: dict) -> None:
        """处理高级污点分析结果"""
        self._set_busy(False)
        hits = results.get("hits", [])
        statistics = results.get("statistics", {})
        target_reached = results.get("target_reached", False)
        
        if not hits:
            msg = '未命中污点相关事件'
            if statistics:
                msg += f"\n统计信息：已分析 {statistics.get('total_steps', 0)} 步"
            QtWidgets.QMessageBox.information(self, '污点分析', msg)
            return
            
        # 显示统计信息
        stats_msg = f"找到 {len(hits)} 个污点事件"
        if target_reached:
            stats_msg += "\n✅ 已到达目标寄存器/内存"
        if statistics:
            stats_msg += f"\n• 总步数: {statistics.get('total_steps', 0)}"
            stats_msg += f"\n• 寄存器传播: {statistics.get('register_propagations', 0)}"
            stats_msg += f"\n• 内存传播: {statistics.get('memory_propagations', 0)}"
            stats_msg += f"\n• 清洗次数: {statistics.get('cleanups', 0)}"
            stats_msg += f"\n• 目标命中: {statistics.get('target_hits', 0)}"
            
        QtWidgets.QMessageBox.information(self, '高级污点分析完成', stats_msg)
        
        # 填充结果列表（与普通模式相同）
        self._populate_taint_results(hits)

    def _populate_taint_results(self, hits: list) -> None:
        """填充污点分析结果到列表"""
        self.list.setUpdatesEnabled(False)
        try:
            self.list.clear()
            for idx in hits:
                ev = self.parser.events[idx]
                rw = 'W' if ev.writes else ('R' if ev.reads else '')
                tag = self._classify_tag(None, idx)
                item = QtWidgets.QTreeWidgetItem([
                    str(ev.line_no), f"0x{ev.pc:08x}", rw, tag, ev.asm,
                    '', '', str(getattr(ev, 'call_id', 0)), self._fmt_low8(None, idx), self._fmt_c_summary(ev.asm)
                ])
                item.setData(0, QtCore.Qt.ItemDataRole.UserRole, idx)
                self.list.addTopLevelItem(item)
        finally:
            self.list.setUpdatesEnabled(True)
            self.list.viewport().update()

    @QtCore.pyqtSlot(list)
    def _on_taint_ready(self, hits: list) -> None:
        self._set_busy(False)
        if not hits:
            QtWidgets.QMessageBox.information(self, '污点分析', '未命中污点相关事件')
            return
        self._populate_taint_results(hits)
    
    @QtCore.pyqtSlot(dict)
    def _on_enhanced_taint_ready(self, results: dict) -> None:
        """处理增强污点分析结果"""
        self._set_busy(False)
        hits = results.get("hits", [])
        confluence_points = results.get("confluence_points", {})
        propagation_count = results.get("propagation_count", 0)
        
        if not hits:
            QtWidgets.QMessageBox.information(self, '增强污点分析', '未命中污点相关事件')
            return
        
        # 显示统计信息
        stats_msg = f"找到 {len(hits)} 个污点事件"
        if propagation_count > 0:
            stats_msg += f"\n• 污点传播次数: {propagation_count}"
        if confluence_points:
            stats_msg += f"\n• 污点汇合点: {len(confluence_points)} 个 ⭐"
            stats_msg += "\n  (多个污点来源合并的关键计算点)"
        
        QtWidgets.QMessageBox.information(self, '增强污点分析完成', stats_msg)
        
        # 填充结果列表并高亮汇合点
        self._populate_enhanced_taint_results(hits, confluence_points)
    
    def _populate_enhanced_taint_results(self, hits: list, confluence_points: dict) -> None:
        """填充增强污点分析结果到列表，高亮汇合点"""
        self.list.setUpdatesEnabled(False)
        try:
            self.list.clear()
            for idx in hits:
                ev = self.parser.events[idx]
                rw = 'W' if ev.writes else ('R' if ev.reads else '')
                tag = self._classify_tag(None, idx)
                
                # 标记汇合点
                if idx in confluence_points:
                    sources = confluence_points[idx]
                    tag = f"⭐汇合点 ({len(sources)}源)"
                
                item = QtWidgets.QTreeWidgetItem([
                    str(ev.line_no), f"0x{ev.pc:08x}", rw, tag, ev.asm,
                    '', '', str(getattr(ev, 'call_id', 0)), 
                    self._fmt_low8(None, idx), self._fmt_c_summary(ev.asm)
                ])
                item.setData(0, QtCore.Qt.ItemDataRole.UserRole, idx)
                
                # 汇合点用特殊颜色高亮
                if idx in confluence_points:
                    for col in range(self.list.columnCount()):
                        item.setBackground(col, QtGui.QColor(255, 250, 205))  # 浅黄色
                        item.setForeground(col, QtGui.QColor(139, 69, 19))    # 棕色
                
                self.list.addTopLevelItem(item)
        finally:
            self.list.setUpdatesEnabled(True)
            self.list.viewport().update()

    def _show_code_dialog(self, title: str, default_name: str, file_filter: str, code: str) -> None:
        dlg = QtWidgets.QDialog(self)
        dlg.setWindowTitle(title)
        lay = QtWidgets.QVBoxLayout(dlg)
        edit = QtWidgets.QPlainTextEdit()
        edit.setPlainText(code)
        edit.setReadOnly(False)
        lay.addWidget(edit)
        btns = QtWidgets.QHBoxLayout()
        btn_copy = QtWidgets.QPushButton('复制到剪贴板')
        btn_save = QtWidgets.QPushButton('保存到文件')
        btn_copy.clicked.connect(lambda: (QtWidgets.QApplication.clipboard().setText(edit.toPlainText()), QtWidgets.QMessageBox.information(dlg, '已复制', '代码已复制')))
        def _save():
            path, _ = QtWidgets.QFileDialog.getSaveFileName(dlg, f'保存为 {default_name}', default_name, file_filter)
            if path:
                try:
                    with open(path, 'w', encoding='utf-8') as f:
                        f.write(edit.toPlainText())
                    QtWidgets.QMessageBox.information(dlg, '已保存', f'已保存到\n{path}')
                except Exception as e:
                    QtWidgets.QMessageBox.critical(dlg, '保存失败', str(e))
        btn_save.clicked.connect(_save)
        btns.addStretch(1)
        btns.addWidget(btn_copy)
        btns.addWidget(btn_save)
        lay.addLayout(btns)
        dlg.resize(760, 560)
        dlg.exec()

    def _gen_c_code(self, indices: list) -> str:
        used_regs = set()
        for idx in indices:
            ev = self.parser.events[idx]
            used_regs.update(ev.reads.keys())
            used_regs.update(ev.writes.keys())
        reg_list = sorted(used_regs, key=lambda x: (x[0], int(x[1:]) if x[1:].isdigit() else 99))
        lines = [
            '/* 生成自 trace 值流选择（伪C） */',
            '#include <stdint.h>',
            '',
        ]
        if reg_list:
            decls = ', '.join(f'uint32_t {r}=0' for r in reg_list)
            lines.append(f'{decls};')
            lines.append('')
        lines.append('void replay(void) {')
        for idx in indices:
            ev = self.parser.events[idx]
            expr = self._bitop_c_expr(ev.asm)
            if expr:
                lines.append(f'    {expr}  // {ev.asm}')
            else:
                lines.append(f'    // {ev.asm}')
        lines.append('}')
        return '\n'.join(lines)

    def _gen_py_code(self, indices: list) -> str:
        used_regs = set()
        for idx in indices:
            ev = self.parser.events[idx]
            used_regs.update(ev.reads.keys())
            used_regs.update(ev.writes.keys())
        reg_list = sorted(used_regs, key=lambda x: (x[0], int(x[1:]) if x[1:].isdigit() else 99))
        lines = [
            '# 生成自 trace 值流选择（Python 伪代码）',
            '',
            'MASK32 = 0xFFFFFFFF',
            'def u32(x): return x & MASK32',
            'def brev32(x):',
            '    x = ((x >> 1) & 0x55555555) | ((x & 0x55555555) << 1)',
            '    x = ((x >> 2) & 0x33333333) | ((x & 0x33333333) << 2)',
            '    x = ((x >> 4) & 0x0f0f0f0f) | ((x & 0x0f0f0f0f) << 4)',
            '    x = ((x >> 8) & 0x00ff00ff) | ((x & 0x00ff00ff) << 8)',
            '    return u32((x >> 16) | (x << 16))',
            'def ror32(x, s): s &= 31; return u32((x >> s) | ((x << ((32 - s) & 31))))',
            'def rev32(x): return ((x & 0xFF) << 24) | (x & 0xFF00) << 8 | (x >> 8) & 0xFF00 | (x >> 24) & 0xFF',
            'def rev16(x): return (((x << 8) & 0xFF00FF00) | ((x >> 8) & 0x00FF00FF))',
            'def revsh(x): import struct; return struct.unpack("<i", struct.pack("<h", (x & 0xFFFF) << 0))[0]',
            'def clz32(x): return 32 - int(x & MASK32).bit_length() if x & MASK32 else 32',
            '',
        ]
        if reg_list:
            decls = '='.join([*reg_list, '0'])
            lines.append(decls)
            lines.append('')
        lines.append('def replay():')
        for idx in indices:
            ev = self.parser.events[idx]
            stmt = self._bitop_py_stmt(ev.asm)
            if stmt:
                lines.append(f'    {stmt}  # {ev.asm}')
            else:
                lines.append(f'    # {ev.asm}')
        return '\n'.join(lines)

    @QtCore.pyqtSlot(str, str)
    def _on_codegen_ready(self, code: str, mode: str) -> None:
        self._set_busy(False)
        if not code:
            QtWidgets.QMessageBox.warning(self, '导出失败', '生成代码失败')
            return
        if mode == 'c':
            title, name, filt = '导出伪C代码', 'replay.c', 'C Files (*.c);;All Files (*)'
        else:
            title, name, filt = '导出 Python 伪代码', 'replay.py', 'Python Files (*.py);;All Files (*)'
        self._show_code_dialog(title, name, filt, code)

    # === 辅助：低8位与位运算摘要 ===
    def _fmt_low8(self, reg: Optional[str], idx: int) -> str:
        if not self.parser:
            return ''
        ev = self.parser.events[idx]
        before = None
        after = None
        if reg and reg in ev.reads:
            before = ev.reads.get(reg)
        if reg and reg in ev.writes:
            after = ev.writes.get(reg)
        # 不指定寄存器时，尝试从右侧写寄存器中取一个
        if not reg and ev.writes:
            k, v = next(iter(ev.writes.items()))
            after = v
        if after is None and before is None:
            return ''
        if before is None:
            return f"-> {after & 0xFF:02x}"
        if after is None:
            return f"{before & 0xFF:02x} ->"
        return f"{before & 0xFF:02x} -> {after & 0xFF:02x}"

    def _fmt_bitops(self, asm: str) -> str:
        s = asm.lower()
        try:
            # 访存类：不显示
            if s.startswith('ldr') or s.startswith('str'):
                return ''
            if s.startswith('mvn'):
                return '~'
            if s.startswith('eor') or '^' in s:
                return '^'
            if s.startswith('orr') or ' orr ' in s or s.startswith('or '):
                return '|'
            if s.startswith('and'):
                return '&'
            if s.startswith('bic'):
                return '&~'
            if s.startswith('orn'):
                return '|~'
            if s.startswith('add'):
                return '+'
            if s.startswith('sub') or s.startswith('rsb'):
                return '-'
            if 'lsr' in s:
                return '>>'
            if 'lsl' in s:
                return '<<'
            if 'asr' in s:
                return '>>'
            # 其它复杂单目/位域等不统一为简写，留空
        except Exception:
            pass
        return ''

    def _fmt_c_summary(self, asm: str) -> str:
        """更精确的 C 表达式摘要。优先用现有解析 `_bitop_c_expr`，
        未覆盖/访存类返回空字符串。该函数仅做字符串解析，性能开销极小。"""
        s = (asm or '').strip().lower()
        if not s or s.startswith('ldr') or s.startswith('str'):
            return ''
        try:
            expr = self._bitop_c_expr(asm)
            # 去掉结尾分号，简洁展示
            if expr and expr.endswith(';'):
                expr = expr[:-1]
            return expr or ''
        except Exception:
            return ''

    # === 辅助：补全 before/after（必要时自动选择寄存器） ===
    def _fallback_before_after(self, idx: int, reg: Optional[str]) -> tuple:
        """当某事件的 reads/writes 没有给出 before/after 时，回退使用寄存器复原补全。

        返回 (before, after, used_reg)。当 reg 为空时，自动选择：
        - 若仅有一个写寄存器，优先选它；
        - 否则若仅有一个读寄存器，选它；
        - 否则返回 (None, None, None)。
        """
        try:
            ev = self.parser.events[idx]
            use_reg = (reg or '').lower() if reg else None
            if not use_reg:
                if len(ev.writes) == 1:
                    use_reg = next(iter(ev.writes.keys()))
                elif len(ev.reads) == 1:
                    use_reg = next(iter(ev.reads.keys()))
                else:
                    return None, None, None
            regs_after = self.parser.reconstruct_regs_at(idx)
            before = None
            after = regs_after.get(use_reg)
            if idx > 0:
                try:
                    regs_before = self.parser.reconstruct_regs_at(idx - 1)
                    before = regs_before.get(use_reg)
                except Exception:
                    before = None
            return before, after, use_reg
        except Exception:
            return None, None, None

    # === 导出（伪C） ===
    def _on_export_c(self) -> None:
        if not self.parser:
            return
        sel = self.list.selectedItems()
        indices = [it.data(0, QtCore.Qt.ItemDataRole.UserRole) for it in sel if isinstance(it.data(0, QtCore.Qt.ItemDataRole.UserRole), int)]
        if not indices:
            QtWidgets.QMessageBox.information(self, '提示', '请在结果列表中选择若干行再导出')
            return
        indices.sort()
        # 收集使用到的寄存器，用于声明
        used_regs = set()
        for idx in indices:
            ev = self.parser.events[idx]
            used_regs.update(ev.reads.keys())
            used_regs.update(ev.writes.keys())
        reg_list = sorted(used_regs, key=lambda x: (x[0], int(x[1:]) if x[1:].isdigit() else 99))

        # 生成伪C代码
        lines = [
            '/* 生成自 trace 值流选择（伪C） */',
            '#include <stdint.h>',
            '',
        ]
        if reg_list:
            decls = ', '.join(f'uint32_t {r}=0' for r in reg_list)
            lines.append(f'{decls};')
            lines.append('')
        lines.append('void replay(void) {')
        for i, idx in enumerate(indices, 1):
            ev = self.parser.events[idx]
            expr = self._bitop_c_expr(ev.asm)
            if expr:
                lines.append(f'    {expr}  // {ev.asm}')
            else:
                lines.append(f'    // {ev.asm}')
        lines.append('}')

        code = '\n'.join(lines)
        dlg = QtWidgets.QDialog(self)
        dlg.setWindowTitle('导出伪C代码')
        lay = QtWidgets.QVBoxLayout(dlg)
        edit = QtWidgets.QPlainTextEdit()
        edit.setPlainText(code)
        edit.setReadOnly(False)
        lay.addWidget(edit)
        btns = QtWidgets.QHBoxLayout()
        btn_copy = QtWidgets.QPushButton('复制到剪贴板')
        btn_save = QtWidgets.QPushButton('保存为 .c 文件')
        btn_copy.clicked.connect(lambda: (QtWidgets.QApplication.clipboard().setText(code), QtWidgets.QMessageBox.information(dlg, '已复制', '代码已复制')))
        def _save():
            path, _ = QtWidgets.QFileDialog.getSaveFileName(dlg, '保存为 .c', 'replay.c', 'C Files (*.c);;All Files (*)')
            if path:
                try:
                    with open(path, 'w', encoding='utf-8') as f:
                        f.write(edit.toPlainText())
                    QtWidgets.QMessageBox.information(dlg, '已保存', f'已保存到\n{path}')
                except Exception as e:
                    QtWidgets.QMessageBox.critical(dlg, '保存失败', str(e))
        btn_save.clicked.connect(_save)
        btns.addStretch(1)
        btns.addWidget(btn_copy)
        btns.addWidget(btn_save)
        lay.addLayout(btns)
        dlg.resize(760, 560)
        dlg.exec()

    def _on_export_py(self) -> None:
        if not self.parser:
            return
        sel = self.list.selectedItems()
        indices = [it.data(0, QtCore.Qt.ItemDataRole.UserRole) for it in sel if isinstance(it.data(0, QtCore.Qt.ItemDataRole.UserRole), int)]
        if not indices:
            QtWidgets.QMessageBox.information(self, '提示', '请在结果列表中选择若干行再导出')
            return
        indices.sort()
        # 收集寄存器
        used_regs = set()
        for idx in indices:
            ev = self.parser.events[idx]
            used_regs.update(ev.reads.keys())
            used_regs.update(ev.writes.keys())
        reg_list = sorted(used_regs, key=lambda x: (x[0], int(x[1:]) if x[1:].isdigit() else 99))

        lines = [
            '# 生成自 trace 值流选择（Python 伪代码）',
            '',
            'MASK32 = 0xFFFFFFFF',
            'def u32(x): return x & MASK32',
            'def brev32(x):',
            '    x = ((x >> 1) & 0x55555555) | ((x & 0x55555555) << 1)',
            '    x = ((x >> 2) & 0x33333333) | ((x & 0x33333333) << 2)',
            '    x = ((x >> 4) & 0x0f0f0f0f) | ((x & 0x0f0f0f0f) << 4)',
            '    x = ((x >> 8) & 0x00ff00ff) | ((x & 0x00ff00ff) << 8)',
            '    return u32((x >> 16) | (x << 16))',
            'def ror32(x, s): s &= 31; return u32((x >> s) | ((x << ((32 - s) & 31))))',
            'def rev32(x): return ((x & 0xFF) << 24) | (x & 0xFF00) << 8 | (x >> 8) & 0xFF00 | (x >> 24) & 0xFF',
            'def rev16(x): return (((x << 8) & 0xFF00FF00) | ((x >> 8) & 0x00FF00FF))',
            'def revsh(x): import struct; return struct.unpack("<i", struct.pack("<h", (x & 0xFFFF) << 0))[0]',
            'def clz32(x):return 32 - int(x & MASK32).bit_length() if x & MASK32 else 32',
            '',
        ]
        if reg_list:
            decls = '='.join([*reg_list, '0'])
            # 形如: r0=r1=r2=...=0
            lines.append(decls)
            lines.append('')
        lines.append('def replay():')
        for idx in indices:
            ev = self.parser.events[idx]
            stmt = self._bitop_py_stmt(ev.asm)
            if stmt:
                lines.append(f'    {stmt}  # {ev.asm}')
            else:
                lines.append(f'    # {ev.asm}')
        code = '\n'.join(lines)
        dlg = QtWidgets.QDialog(self)
        dlg.setWindowTitle('导出 Python 伪代码')
        lay = QtWidgets.QVBoxLayout(dlg)
        edit = QtWidgets.QPlainTextEdit()
        edit.setPlainText(code)
        edit.setReadOnly(False)
        lay.addWidget(edit)
        btns = QtWidgets.QHBoxLayout()
        btn_copy = QtWidgets.QPushButton('复制到剪贴板')
        btn_save = QtWidgets.QPushButton('保存为 .py 文件')
        btn_copy.clicked.connect(lambda: (QtWidgets.QApplication.clipboard().setText(edit.toPlainText()), QtWidgets.QMessageBox.information(dlg, '已复制', '代码已复制')))
        def _save():
            path, _ = QtWidgets.QFileDialog.getSaveFileName(dlg, '保存为 .py', 'replay.py', 'Python Files (*.py);;All Files (*)')
            if path:
                try:
                    with open(path, 'w', encoding='utf-8') as f:
                        f.write(edit.toPlainText())
                    QtWidgets.QMessageBox.information(dlg, '已保存', f'已保存到\n{path}')
                except Exception as e:
                    QtWidgets.QMessageBox.critical(dlg, '保存失败', str(e))
        btn_save.clicked.connect(_save)
        btns.addStretch(1)
        btns.addWidget(btn_copy)
        btns.addWidget(btn_save)
        lay.addLayout(btns)
        dlg.resize(760, 560)
        dlg.exec()

    def _bitop_py_stmt(self, asm: str) -> str:
        s = asm.strip(); low = s.lower()
        m = re.match(r"^(\w+)\s+(\w+)\s*,\s*([^,]+)(?:\s*,\s*(.+))?$", low)
        if not m:
            if low.startswith('mov '):
                try:
                    rest = ' '.join(low.split()[1:])
                    rd, rn = [x.strip() for x in rest.split(',', 1)]
                    rn = rn.replace('#', '')
                    return f"{rd} = u32({rn})"
                except Exception:
                    return ''
            if low.startswith('mvn '):
                try:
                    rest = ' '.join(low.split()[1:])
                    rd, rn = [x.strip() for x in rest.split(',', 1)]
                    rn = rn.replace('#', '')
                    return f"{rd} = u32(~{rn})"
                except Exception:
                    return ''
            return ''
        op, rd, rn, rm = m.group(1), m.group(2), m.group(3), m.group(4)
        rm = '' if rm is None else rm
        rd = rd.strip(); rn = rn.strip()
        # 内联第三参移位
        def _sh(opname, txt):
            parts = txt.split(opname)
            base = parts[0].strip(' ,')
            sh = parts[1].strip().replace('#','').strip()
            if opname == 'asr':
                return f"((({base}) & 0x80000000) and u32(({base}) >> {sh}) or u32(({base}) >> {sh}))"
            return f"(({base}) { '<<' if opname=='lsl' else '>>' } {sh})"
        if 'lsl' in rm:
            rm = _sh('lsl', rm)
        elif 'lsr' in rm:
            rm = _sh('lsr', rm)
        elif 'asr' in rm:
            rm = _sh('asr', rm)
        rm_clean = rm.replace('#','').strip() if rm else ''

        # 特殊/单目
        if op == 'rbit':
            return f"{rd} = brev32({rn})"
        if op == 'clz':
            return f"{rd} = clz32({rn})"
        if op == 'rev':
            return f"{rd} = rev32({rn})"
        if op == 'rev16':
            return f"{rd} = rev16({rn})"
        if op == 'revsh':
            return f"{rd} = revsh({rn})"

        # 位域
        if op == 'ubfx':
            try:
                lsb, width = [x.strip().lstrip('#') for x in rm.split(',')]
                return f"{rd} = u32(({rn} >> {lsb}) & ((1 << {width}) - 1))"
            except Exception:
                return ''
        if op == 'sbfx':
            try:
                lsb, width = [x.strip().lstrip('#') for x in rm.split(',')]
                return f"{rd} = u32((((({rn}) << (32 - ({lsb} + {width}))) & MASK32) >> (32 - {width})))"
            except Exception:
                return ''
        if op == 'bfc':
            try:
                lsb, width = [x.strip().lstrip('#') for x in rm.split(',')]
                return f"{rd} = u32({rd} & ~(((1 << {width}) - 1) << {lsb}))"
            except Exception:
                return ''
        if op == 'bfi':
            try:
                lsb, width = [x.strip().lstrip('#') for x in rm.split(',')]
                return f"{rd} = u32(({rd} & ~(((1 << {width}) - 1) << {lsb})) | ((({rn}) << {lsb}) & (((1 << {width}) - 1) << {lsb})))"
            except Exception:
                return ''

        # 扩展
        if op == 'uxtb':
            return f"{rd} = u32({rn} & 0xFF)"
        if op == 'uxth':
            return f"{rd} = u32({rn} & 0xFFFF)"
        if op == 'sxtb':
            return f"{rd} = u32((({rn}) & 0xFF) if (({rn}) & 0x80)==0 else (0xFFFFFFFF - ((~({rn})+1) & 0xFF)))"
        if op == 'sxth':
            return f"{rd} = u32((({rn}) & 0xFFFF) if (({rn}) & 0x8000)==0 else (0xFFFFFFFF - ((~({rn})+1) & 0xFFFF)))"
        if op == 'sxtah':
            return f"{rd} = u32({rn} + (({rm_clean}) & 0xFFFF if (({rm_clean}) & 0x8000)==0 else (0xFFFFFFFF - ((~({rm_clean})+1) & 0xFFFF))))"

        # 基本运算
        if op == 'mvn':
            return f"{rd} = u32(~{rn})"
        if op == 'eor':
            return f"{rd} = u32({rn} ^ {rm_clean})"
        if op in ('orr', 'or'):
            return f"{rd} = u32({rn} | {rm_clean})"
        if op == 'and':
            return f"{rd} = u32({rn} & {rm_clean})"
        if op == 'add':
            return f"{rd} = u32({rn} + {rm_clean})"
        if op == 'sub':
            return f"{rd} = u32({rn} - {rm_clean})"
        if op == 'mov':
            return f"{rd} = u32({rn})"

        # 纯移位/旋转
        if op in ('lsl','lsls'):
            return f"{rd} = u32({rn} << {rm_clean})"
        if op in ('lsr','lsrs'):
            return f"{rd} = u32({rn} >> {rm_clean})"
        if op in ('asr','asrs'):
            return f"{rd} = u32((({rn} & 0x80000000) and ({rn} >> {rm_clean})) or ({rn} >> {rm_clean}))"
        if op in ('ror','rors'):
            return f"{rd} = ror32({rn}, {rm_clean})"
        return ''

    def _bitop_pseudocode(self, asm: str) -> str:
        """将常见位运算指令转为简要伪代码（尽量提取 rd/rn/rm 与移位）。"""
        s = asm.strip()
        low = s.lower()
        # 通用三段式解析：op rd, rn, rm/operand2
        m = None
        m = re.match(r"^(\w+)\s+(\w+)\s*,\s*([^,]+)(?:\s*,\s*(.+))?$", low)
        if not m:
            if low.startswith('mvn'):
                # mvn rd, rn 亦有两参形式；尽量保留原文
                return s.replace('mvn', 'rd := ~rn')
            return ''
        op, rd, rn, rm = m.group(1), m.group(2), m.group(3), m.group(4)
        if rm is None:
            rm = ''
        # 处理移位
        sh = ''
        if 'lsl' in rm:
            parts = rm.split('lsl')
            rm = parts[0].strip(' ,')
            sh = parts[1].strip()
            rm = f"({rm} << {sh})"
        elif 'lsr' in rm:
            parts = rm.split('lsr')
            rm = parts[0].strip(' ,')
            sh = parts[1].strip()
            rm = f"({rm} >> {sh})"
        rn = rn.strip()
        rm = rm.strip()
        if op == 'mvn':
            return f"{rd} := ~{rn}"
        if op == 'eor':
            return f"{rd} := {rn} ^ {rm}"
        if op == 'orr':
            return f"{rd} := {rn} | {rm}"
        if op == 'and':
            return f"{rd} := {rn} & {rm}"
        if op == 'add':
            return f"{rd} := {rn} + {rm}"
        if op == 'sub':
            return f"{rd} := {rn} - {rm}"
        if op in ('lsl', 'lsr'):
            return f"{rd} := {rn} {op} {rm}"
        return ''

    def _bitop_c_expr(self, asm: str) -> str:
        """将常见 ARM32/ARM64/Thumb 位运算与简单算术转为 C 表达式（末尾分号）。
        覆盖：and/or/eor/mov/mvn/add/sub/lsl/lsr/lsrs/asr/ror/ubfx/sbfx/bfc/bfi/rbit/clz/rev/rev16/revsh/
        uxtb/uxth/sxtb/sxth/sxtah 等常见形式。未覆盖的返回注释行。
        """
        s = asm.strip()
        low = s.lower()
        m = re.match(r"^(\w+)\s+(\w+)\s*,\s*([^,]+)(?:\s*,\s*(.+))?$", low)
        if not m:
            # 两参形式：mov/mvn/单目
            if low.startswith('mov '):
                try:
                    parts = low.split()
                    rest = ' '.join(parts[1:])
                    rd, rn = [x.strip() for x in rest.split(',', 1)]
                    rn = rn.replace('#', '')
                    return f"{rd} = {rn};"
                except Exception:
                    return ''
            if low.startswith('mvn '):
                try:
                    parts = low.split()
                    rest = ' '.join(parts[1:])
                    rd, rn = [x.strip() for x in rest.split(',', 1)]
                    rn = rn.replace('#', '')
                    return f"{rd} = ~{rn};"
                except Exception:
                    return ''
            # rbit/clz/rev* 两参也可能以此分支进入
            return ''
        op, rd, rn, rm = m.group(1), m.group(2), m.group(3), m.group(4)
        rm = '' if rm is None else rm
        opb = op.rstrip('s')  # 兼容 lsrs/asrs 等
        rd = rd.strip()
        rn = rn.strip()

        # 若第三参自带移位（如 ip, lsr #20），先内联为 C 表达式
        if 'lsl' in rm:
            parts = rm.split('lsl')
            base = parts[0].strip(' ,')
            sh = parts[1].strip()
            rm = f"({base} << {sh.replace('#','').strip()})"
        elif 'lsr' in rm:
            parts = rm.split('lsr')
            base = parts[0].strip(' ,')
            sh = parts[1].strip()
            rm = f"({base} >> {sh.replace('#','').strip()})"
        elif 'asr' in rm:
            parts = rm.split('asr')
            base = parts[0].strip(' ,')
            sh = parts[1].strip()
            rm = f"((int32_t){base} >> {sh.replace('#','').strip()})"
        rm_clean = rm.strip().replace('#', '')

        # 单目/特殊
        if op == 'rbit':
            return f"{rd} = __builtin_bitreverse32({rn});"
        if op == 'clz':
            return f"{rd} = __builtin_clz({rn});"
        if op == 'rev':
            return f"{rd} = __builtin_bswap32({rn});"
        if op == 'rev16':
            return f"{rd} = ((({rn} << 8) & 0xFF00FF00u) | (({rn} >> 8) & 0x00FF00FFu));"
        if op == 'revsh':
            return f"{rd} = (int32_t)(int16_t)__builtin_bswap16((uint16_t){rn});"

        # 位域
        if op == 'ubfx':
            try:
                lsb, width = [x.strip().lstrip('#') for x in rm.split(',')]
                return f"{rd} = (({rn} >> {lsb}) & ((1u << {width}) - 1));"
            except Exception:
                return ''
        if op == 'sbfx':
            try:
                lsb, width = [x.strip().lstrip('#') for x in rm.split(',')]
                return f"{rd} = ((int32_t)({rn} << (32 - ({lsb} + {width}))) >> (32 - {width}));"
            except Exception:
                return ''
        if op == 'bfc':
            try:
                lsb, width = [x.strip().lstrip('#') for x in rm.split(',')]
                return f"{rd} &= ~(((1u << {width}) - 1) << {lsb});"
            except Exception:
                return ''
        if op == 'bfi':
            try:
                # 语法：bfi rd, rn, #lsb, #width
                lsb, width = [x.strip().lstrip('#') for x in rm.split(',')]
                return f"{{ uint32_t __mask = ((1u << {width}) - 1) << {lsb}; {rd} = ({rd} & ~__mask) | ((({rn}) << {lsb}) & __mask); }}"
            except Exception:
                return ''

        # 扩展/带加
        if op == 'uxtb':
            return f"{rd} = (uint32_t)(({rn}) & 0xFF);"
        if op == 'uxth':
            return f"{rd} = (uint32_t)(({rn}) & 0xFFFF);"
        if op == 'sxtb':
            return f"{rd} = (int32_t)(int8_t)({rn} & 0xFF);"
        if op == 'sxth':
            return f"{rd} = (int32_t)(int16_t)({rn} & 0xFFFF);"
        if op == 'sxtah':
            # rd = rn + SignExtend16(rm)
            return f"{rd} = {rn} + (int32_t)(int16_t)({rm_clean} & 0xFFFF);"

        # 基本运算
        if op == 'mvn':
            return f"{rd} = ~{rn};"
        if op == 'eor':
            return f"{rd} = {rn} ^ {rm_clean};"
        if op in ('orr', 'or'):  # 兼容解析
            return f"{rd} = {rn} | {rm_clean};"
        if op == 'and':
            return f"{rd} = {rn} & {rm_clean};"
        if op == 'add':
            return f"{rd} = {rn} + {rm_clean};"
        if op == 'sub':
            return f"{rd} = {rn} - {rm_clean};"
        if op == 'mov':
            return f"{rd} = {rn};"

        # 纯移位类（rd, rn, sh）
        if opb == 'lsl':
            return f"{rd} = {rn} << {rm_clean};"
        if opb == 'lsr':
            return f"{rd} = {rn} >> {rm_clean};"
        if opb == 'asr':
            return f"{rd} = ((int32_t){rn}) >> {rm_clean};"
        if opb == 'ror':
            return f"{rd} = ({rn} >> ({rm_clean} & 31)) | ({rn} << ((32 - ({rm_clean} & 31)) & 31));"

        return ''


class ChainWorker(QtCore.QThread):
    finishedWithId = QtCore.pyqtSignal(list, str, int)

    def __init__(self, parser, reg: str, start_idx: int, match_val: int, side: str, req_id: int) -> None:
        super().__init__()
        self._parser = parser
        self._reg = reg
        self._start_idx = start_idx
        self._match_val = match_val
        self._side = side
        self._req_id = req_id
        self._deadline_ms = 300  # 构链时间预算，超时提前返回

    def run(self) -> None:
        # 带时间预算的构链：优先使用"第一阶段（内存感知）"，仅发一次结果
        t0 = time.perf_counter()
        indices: list[int] = []
        try:
            prelim = self._parser.build_value_chain_phase1(self._reg, self._start_idx, self._match_val, self._side)
            if self.isInterruptionRequested():
                return
            # 限流输出规模，保持 UI 顺滑
            indices = prelim[:512]
            # 超时直接返回当前结果
            elapsed_ms = (_t.perf_counter() - t0) * 1000.0
            if elapsed_ms >= self._deadline_ms:
                if not self.isInterruptionRequested():
                    self.finishedWithId.emit(sorted(set(indices)), self._reg, self._req_id)
                return
        except Exception:
            indices = []
        if self.isInterruptionRequested():
            return
        self.finishedWithId.emit(sorted(set(indices)), self._reg, self._req_id)


class _CodeGenWorker(QtCore.QThread):
    finishedWithCode = QtCore.pyqtSignal(str, str)

    def __init__(self, dock, indices: list, mode: str) -> None:
        super().__init__(dock)
        self._dock = dock
        self._indices = list(indices)
        self._mode = mode

    def run(self) -> None:
        try:
            if self._mode == 'c':
                code = self._dock._gen_c_code(self._indices)
            else:
                code = self._dock._gen_py_code(self._indices)
        except Exception:
            code = ''
        if not self.isInterruptionRequested():
            self.finishedWithCode.emit(code, self._mode)


class TaintWorker(QtCore.QThread):
    finishedWithHits = QtCore.pyqtSignal(list)

    def __init__(self, parser, start_idx: int, regs: List[str], mem_addrs: List[int], same_call: bool) -> None:
        super().__init__()
        self._parser = parser
        self._start_idx = start_idx
        self._regs = list(regs)
        self._mem = list(mem_addrs)
        self._same_call = same_call

    def run(self) -> None:
        try:
            hits = self._parser.taint_forward(self._start_idx, self._regs, self._mem, self._same_call, max_steps=200000)
        except Exception:
            hits = []
        if not self.isInterruptionRequested():
            self.finishedWithHits.emit(hits)


class EnhancedTaintWorker(QtCore.QThread):
    """增强污点分析Worker"""
    finishedWithEnhancedResults = QtCore.pyqtSignal(dict)
    
    def __init__(self, parser, start_idx: int, source_regs: List[str], source_mem_addrs: List[int],
                 same_call: bool, policy: str, show_confluence: bool) -> None:
        super().__init__()
        self._parser = parser
        self._start_idx = start_idx
        self._source_regs = list(source_regs)
        self._source_mem = list(source_mem_addrs)
        self._same_call = same_call
        self._policy = policy
        self._show_confluence = show_confluence
    
    def run(self) -> None:
        try:
            from trace_viewer.enhanced_taint import EnhancedTaintAnalyzer, TaintPolicy
            
            # 转换策略
            policy_map = {
                'strict': TaintPolicy.STRICT,
                'normal': TaintPolicy.NORMAL,
                'loose': TaintPolicy.LOOSE
            }
            policy_enum = policy_map.get(self._policy, TaintPolicy.NORMAL)
            
            # 创建分析器
            analyzer = EnhancedTaintAnalyzer(policy=policy_enum)
            
            # 设置污点源
            for reg in self._source_regs:
                analyzer.add_source('reg', reg, self._start_idx)
            for addr in self._source_mem:
                analyzer.add_source('mem', hex(addr), self._start_idx)
            
            # 遍历trace进行分析
            hits = []
            n = len(self._parser.events)
            
            # 边界检查
            if n == 0 or self._start_idx >= n:
                results = {"hits": [], "confluence_points": {}, "propagation_count": 0}
                if not self.isInterruptionRequested():
                    self.finishedWithEnhancedResults.emit(results)
                return
            
            base_call = self._parser.events[self._start_idx].call_id
            propagation_count = 0
            
            for i in range(self._start_idx, min(n, self._start_idx + 200000)):
                if self.isInterruptionRequested():
                    break
                
                event = self._parser.events[i]
                
                # 同调用限制
                if self._same_call and getattr(event, 'call_id', 0) != base_call:
                    continue
                
                asm = event.asm.lower()
                propagated = False
                
                # 算术/逻辑运算
                if any(asm.startswith(op) for op in ['add ', 'sub ', 'and ', 'orr ', 'eor ', 'mov ', 'mul ']):
                    src_regs = list(event.reads.keys())
                    dst_regs = list(event.writes.keys())
                    if dst_regs:
                        dst = dst_regs[0]
                        is_partial = 'movk' in asm
                        propagated = analyzer.propagate_reg_to_reg(i, src_regs, dst, is_partial)
                
                # 加载指令
                elif asm.startswith('ldr'):
                    if event.effaddr is not None and event.writes:
                        dst_reg = list(event.writes.keys())[0]
                        mem_size = getattr(event, 'mem_width', 4) or 4
                        propagated = analyzer.propagate_mem_to_reg(i, event.effaddr, mem_size, dst_reg)
                
                # 存储指令
                elif asm.startswith('str'):
                    if event.effaddr is not None and event.reads:
                        src_reg = list(event.reads.keys())[0]
                        mem_size = getattr(event, 'mem_width', 4) or 4
                        propagated = analyzer.propagate_reg_to_mem(i, src_reg, event.effaddr, mem_size)
                
                # 条件分支（隐式流）
                elif any(asm.startswith(op) for op in ['cmp ', 'tst ', 'b.eq', 'b.ne', 'beq', 'bne']):
                    cond_regs = list(event.reads.keys())
                    analyzer.propagate_implicit_flow(i, cond_regs)
                    # 检查是否受隐式污点影响
                    if any(analyzer.is_reg_tainted(r) for r in cond_regs):
                        propagated = True
                
                if propagated:
                    hits.append(i)
                    propagation_count += 1
            
            # 获取汇合点
            confluence_points = {}
            if self._show_confluence:
                raw_confluence = analyzer.get_confluence_points()
                for event_idx, sources_list in raw_confluence.items():
                    # 简化数据结构用于传递
                    confluence_points[event_idx] = sources_list
            
            results = {
                "hits": hits,
                "confluence_points": confluence_points,
                "propagation_count": propagation_count
            }
            
        except Exception as e:
            results = {"hits": [], "confluence_points": {}, "propagation_count": 0, "error": str(e)}
        
        if not self.isInterruptionRequested():
            self.finishedWithEnhancedResults.emit(results)


class AdvancedTaintWorker(QtCore.QThread):
    finishedWithAdvancedResults = QtCore.pyqtSignal(dict)

    def __init__(self, parser, start_idx: int, source_regs: List[str], source_mem_addrs: List[int], 
                 target_regs: List[str], target_mem_addrs: List[int], same_call: bool,
                 enable_mem_taint: bool, track_constants: bool) -> None:
        super().__init__()
        self._parser = parser
        self._start_idx = start_idx
        self._source_regs = list(source_regs)
        self._source_mem = list(source_mem_addrs)
        self._target_regs = list(target_regs)
        self._target_mem = list(target_mem_addrs)
        self._same_call = same_call
        self._enable_mem_taint = enable_mem_taint
        self._track_constants = track_constants

    def run(self) -> None:
        try:
            results = self._parser.advanced_taint_analysis(
                self._start_idx, 
                self._source_regs, self._source_mem,
                self._target_regs, self._target_mem,
                self._same_call, 
                max_steps=200000,
                enable_memory_taint=self._enable_mem_taint,
                track_constants=self._track_constants
            )
        except Exception:
            results = {"hits": [], "taint_path": [], "statistics": {}, "target_reached": False}
        if not self.isInterruptionRequested():
            self.finishedWithAdvancedResults.emit(results)



class _ProvenanceWorker(QtCore.QThread):
    finishedWithPath = QtCore.pyqtSignal(list, list, str)

    def __init__(self, parser, reg: str, start_idx: int, side: str) -> None:
        super().__init__()
        self._parser = parser
        self._reg = (reg or '').lower()
        self._idx = int(start_idx)
        self._side = side

    def run(self) -> None:
        try:
            nodes, edges = self._parser.build_provenance_graph(self._reg, self._idx, self._side, max_nodes=5000)
        except Exception:
            nodes, edges = [], []
        if not self.isInterruptionRequested():
            self.finishedWithPath.emit(nodes, edges, self._reg)


class BackwardTaintWorker(QtCore.QThread):
    """反向污点分析Worker：异步调用parser.taint_backward"""
    finishedWithBackwardResults = QtCore.pyqtSignal(list, str, int)  # (hits, reg, req_id)

    def __init__(self, parser, reg: str, start_idx: int, value: int, same_call: bool, req_id: int) -> None:
        super().__init__()
        self._parser = parser
        self._reg = (reg or '').lower()
        self._start_idx = int(start_idx)
        self._value = int(value)
        self._same_call = same_call
        self._req_id = req_id

    def run(self) -> None:
        try:
            # 调用反向污点分析
            hits = self._parser.taint_backward(
                self._start_idx,
                self._reg,
                self._value,
                same_call_only=self._same_call,
                max_steps=100000,
                enable_memory_taint=True
            )
        except Exception:
            hits = []
        
        if not self.isInterruptionRequested():
            self.finishedWithBackwardResults.emit(hits, self._reg, self._req_id)

