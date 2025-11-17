import re
import os
from bisect import bisect_left, bisect_right
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional, Iterable
import threading
import time
from collections import OrderedDict
import logging
try:
    from .decoders import get_decoder
except Exception:
    get_decoder = None  # 回退


class TraceEvent:
    """单条 trace 事件的数据结构。
    
    使用__slots__优化内存占用：
    - 标准dict实例: 约280-300字节/对象
    - 使用__slots__: 约100-120字节/对象
    - 节省约60%内存，对于800MB文件（5-10M事件）可节省约1-2GB内存
    
    注：不使用@dataclass因为Python 3.8的dataclass与__slots__有兼容性问题。
    """
    __slots__ = ('line_no', 'timestamp', 'module', 'module_offset', 'encoding', 
                 'pc', 'asm', 'raw', 'writes', 'reads', 'effaddr', 'mem_width', 
                 'mem_op', 'call_id', 'call_depth')
    
    def __init__(self, line_no: int, timestamp: str, module: str, module_offset: str,
                 encoding: str, pc: int, asm: str, raw: str,
                 writes: Optional[Dict[str, int]] = None,
                 reads: Optional[Dict[str, int]] = None,
                 effaddr: Optional[int] = None,
                 mem_width: int = 0,
                 mem_op: str = '',
                 call_id: int = 0,
                 call_depth: int = 0):
        self.line_no = line_no
        self.timestamp = timestamp
        self.module = module
        self.module_offset = module_offset
        self.encoding = encoding
        self.pc = pc
        self.asm = asm
        self.raw = raw
        self.writes = writes if writes is not None else {}
        self.reads = reads if reads is not None else {}
        self.effaddr = effaddr
        self.mem_width = mem_width
        self.mem_op = mem_op
        self.call_id = call_id
        self.call_depth = call_depth


class TraceParser:
    """unidbg trace 文件解析器与索引器（兼容 ARM32/ARM64 文本格式）。

    功能概述：
    - 流式按行解析超大 trace 文件；
    - 构建 地址→事件索引，并收集分支目标作为"函数候选"；
    - 解析每行寄存器读写，并定期保存寄存器快照以便快速复原任意时刻寄存器。"""

    # 示例行格式（支持两种格式）：
    # 格式1 - 标准Unidbg格式 (ARM32/Thumb):
    #   [041091e5][libjni.so 0x1202588c][041091e5] 0x1202588c: "ldr r1, [r1, #4]" ...
    # 格式2 - JD trace格式 (ARM64):
    #   [14:07:57 422][0x29ce4] [e007bea9] 0x40029ce4: "stp x0, x1, [sp, #-0x20]!" ...
    
    # 兼容两种格式的正则表达式
    LINE_RE = re.compile(
        r"^\[(?P<ts>[^\]]+)\]"  # 时间戳：支持十六进制或时分秒格式
        r"\[(?P<mod>[^\]]+?)"   # 模块信息：可能包含空格和偏移，或只有偏移
        r"(?:\s+(?P<modoff>0x[0-9a-fA-F]+))?\]\s+"  # 可选的模块偏移
        r"\[(?P<enc>[0-9a-fA-F]{4}(?:\s{0,4}[0-9a-fA-F]{0,4})?)\]\s+"  # 编码
        r"(?P<pc>0x[0-9a-fA-F]+):\s+"  # PC地址
        r"\"(?P<asm>[^\"]+)\""  # 汇编指令
        r"(?P<rest>.*)$"  # 其余部分
    )

    # 寄存器匹配：ARM32 的 r0..r15, sp, lr, pc, cpsr；兼容 ARM64 的 x0..x30 及 w0..w30
    REG_PAIR_RE = re.compile(r"\b([rxw][0-9]{1,2}|sp|lr|pc|cpsr)=0x[0-9a-fA-F]+\b")
    REG_NAME_RE = re.compile(r"^([rxw][0-9]{1,2}|sp|lr|pc|cpsr)=")
    HEX_RE = re.compile(r"0x[0-9a-fA-F]+")

    BRANCH_TARGET_RE = re.compile(r"\b(b|bl|beq|bne|bhi|blo|bge|blt|bpl|bmi)\s+#?(0x[0-9a-fA-F]+)\b")
    ADD_PC_TARGET_RE = re.compile(r"\badd\s+pc,\s*(r\d+|x\d+),\s*(r\d+|x\d+|#?0x[0-9a-fA-F]+)\b")
    DIRECT_ADDR_RE = re.compile(r"\b(0x[0-9a-fA-F]+)\b")

    def __init__(self, checkpoint_interval: int = 2000, arch_hint: str = 'auto') -> None:
        """初始化解析器。

        checkpoint_interval：每隔多少行保存一次寄存器快照，用于加速寄存器复原。"""
        self.events: List[TraceEvent] = []
        self.addr_index: Dict[int, List[int]] = {}
        self.branch_targets: Dict[int, str] = {}
        self._reg_checkpoints: Dict[int, Dict[str, int]] = {}
        self._checkpoint_interval = checkpoint_interval
        self._current_regs: Dict[str, int] = {}
        # 调用跟踪
        self._call_stack: List[int] = []
        self._next_call_id: int = 1
        # 寄存器读写倒排索引
        self.reg_read_index: Dict[str, List[int]] = {}
        self.reg_write_index: Dict[str, List[int]] = {}
        # 架构提示：'auto'/'arm32'/'arm64'
        self.arch: str = arch_hint if arch_hint in ('auto', 'arm32', 'arm64') else 'auto'
        # 寄存器复原 LRU 缓存
        self._regs_cache: "OrderedDict[int, Dict[str, int]]" = OrderedDict()
        self._regs_cache_cap: int = 1024
        # 增量缓存：记录访问模式，智能选择最近缓存点（性能优化）
        self._recent_access_idx: int = -1  # 最近访问的事件索引
        # 有效地址 LRU 缓存，避免重复重建寄存器
        self._effaddr_cache: "OrderedDict[int, Optional[int]]" = OrderedDict()
        self._effaddr_cache_cap: int = 8192
        # store 地址索引：addr -> 已排序的事件索引列表（仅 str* 指令）
        self.store_addr_index: Dict[int, List[int]] = {}
        # 解码器回退日志（限频）
        self._decoder_warn_counts: Dict[str, int] = {}
        self._decoder_warn_limit: int = 20
        # 寄存器别名缓存（性能优化）
        self._alias_cache: Dict[str, List[str]] = {}

    def parse_file(self, path: str, progress_cb: Optional[callable] = None) -> None:
        """解析 trace 文件并构建索引；若存在可用 SQLite 缓存则直接加载。"""
        # 优先尝试缓存
        cache = None
        try:
            from .sqlite_cache import SQLiteCache  # type: ignore
            cache = SQLiteCache(path)
        except Exception:
            cache = None  # 运行环境缺 sqlite 缓存模块时退化为内存解析

        if cache is not None and cache.is_valid(self._checkpoint_interval, version="v1"):
            self._load_from_cache(cache)
            cache.close()
            return

        # 常规解析；为避免写库导致卡顿，默认不写缓存。
        # 如需构建缓存，请设置环境变量 TRACE_CACHE_BUILD=1
        import os as _os
        build_cache = bool(_os.environ.get('TRACE_CACHE_BUILD') == '1')
        if not build_cache:
            cache = None

        # 常规解析并（可选）边写入缓存
        total_size = 0
        try:
            total_size = os.path.getsize(path)
        except Exception:
            total_size = 0
        bytes_read = 0
        last_pct = -1
        
        # 立即报告0%，让用户知道开始解析了
        if progress_cb:
            try:
                progress_cb(0)
            except Exception:
                pass
        
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for i, line in enumerate(f, start=1):
                line = line.rstrip('\n')
                # 进度按字节估算，减少二次扫描开销
                # 使用简单的字符长度估算（ASCII约等于字节，中文按3倍计算更准确但开销大，这里用1:1近似）
                try:
                    bytes_read += len(line) + 1
                    # 每处理100行才检查一次进度，减少回调开销
                    if progress_cb and total_size > 0 and i % 100 == 0:
                        pct = int((bytes_read * 100) / total_size)
                        if pct != last_pct:
                            last_pct = pct
                            progress_cb(pct)
                except Exception:
                    pass
                ev = self._parse_line(i, line)
                if ev is None:
                    continue
                self._annotate_call(ev)
                self._index_event(ev)
                self._apply_writes(ev)
                # 写入缓存
                if cache is not None:
                    if i == 1:
                        # 首次批量优化
                        try:
                            cache.begin_bulk()
                        except Exception:
                            pass
                    idx = len(self.events) - 1
                    cache.add_event(idx, ev.line_no, ev.timestamp, ev.module, ev.module_offset, ev.encoding, ev.pc, ev.asm, ev.call_id, ev.call_depth)
                    if ev.reads:
                        cache.add_reads(idx, ev.reads.items())
                    if ev.writes:
                        cache.add_writes(idx, ev.writes.items())
                if i % self._checkpoint_interval == 0:
                    self._reg_checkpoints[i] = dict(self._current_regs)
                # 优化：SQLite commit间隔独立设置，减少I/O开销
                # checkpoint_interval=2000，但commit_interval=10000
                if cache is not None and i % 10000 == 0:
                    cache.commit()
        
        # 解析完成，报告100%
        if progress_cb:
            try:
                progress_cb(100)
            except Exception:
                pass
        
        # 解析完成后，预计算 ldr/str 的有效地址并构建 store_addr 索引
        self._precompute_memory_effects()
        if cache is not None:
            try:
                cache.write_signature(self._checkpoint_interval, version="v1")
                cache.end_bulk()
            finally:
                cache.close()

    # 后台异步落库：解析完成后调用，不阻塞 UI
    def start_background_cache_dump(self, path: str) -> None:
        try:
            from .sqlite_cache import SQLiteCache  # type: ignore
        except Exception:
            return

        def _job():
            cache = None
            try:
                cache = SQLiteCache(path)
                # 已有有效缓存则跳过
                if cache.is_valid(self._checkpoint_interval, version="v1"):
                    cache.close()
                    return
                cache.begin_bulk()
                batch = 0
                for idx, ev in enumerate(self.events):
                    cache.add_event(idx, ev.line_no, ev.timestamp, ev.module, ev.module_offset, ev.encoding, ev.pc, ev.asm, ev.call_id, ev.call_depth)
                    if ev.reads:
                        cache.add_reads(idx, ev.reads.items())
                    if ev.writes:
                        cache.add_writes(idx, ev.writes.items())
                    batch += 1
                    if batch >= 5000:
                        cache.commit()
                        batch = 0
                        time.sleep(0.001)  # 让出 CPU，避免顶满
                cache.write_signature(self._checkpoint_interval, version="v1")
                cache.end_bulk()
            except Exception:
                try:
                    if cache is not None:
                        cache.close()
                except Exception:
                    pass
            finally:
                try:
                    if cache is not None:
                        cache.close()
                except Exception:
                    pass

        t = threading.Thread(target=_job, name="TraceCacheDump", daemon=True)
        t.start()

    def _load_from_cache(self, cache) -> None:
        """从 SQLite 缓存装载事件并重建索引与快照。"""
        self.events.clear()
        self.addr_index.clear()
        self.branch_targets.clear()
        self._reg_checkpoints.clear()
        self._current_regs.clear()
        self.reg_read_index.clear()
        self.reg_write_index.clear()

        for row in cache.iter_events():
            idx, line_no, ts, module, modoff, enc, pc, asm, call_id, call_depth = row
            ev = TraceEvent(
                line_no=line_no,
                timestamp=ts,
                module=module,
                module_offset=modoff,
                encoding=enc,
                pc=int(pc),
                asm=asm,
                raw='',
                writes={},
                reads={},
                call_id=int(call_id or 0),
                call_depth=int(call_depth or 0),
            )
            # 读写寄存器
            for r, v in cache.iter_reads_for_event(idx):
                ev.reads[r] = int(v)
            for r, v in cache.iter_writes_for_event(idx):
                ev.writes[r] = int(v)
            self._index_event(ev)
            self._apply_writes(ev)
            if line_no % self._checkpoint_interval == 0:
                self._reg_checkpoints[line_no] = dict(self._current_regs)
        # 从缓存加载后同样补建内存相关预计算
        self._precompute_memory_effects()
    
    def _annotate_call(self, ev: TraceEvent) -> None:
        """为事件打上调用实例编号与深度。
        规则：
        - 在处理 bl/blx 之前，当前事件标注为“调用前”的上下文（仍属调用者）；随后 push 新实例供后续事件使用。
        - 在处理 return 指令时，先按照“被调方”上下文标注，再 pop。
        """
        asm = ev.asm.lower().strip()
        # 标注当前上下文
        ev.call_depth = len(self._call_stack)
        ev.call_id = self._call_stack[-1] if self._call_stack else 0

        # 根据当前指令调整调用栈（优先解码器，失败回退字符串判断）
        if self._is_call_event(ev):
            self._call_stack.append(self._next_call_id)
            self._next_call_id += 1
            return
        if self._is_return_event(ev):
            if self._call_stack:
                self._call_stack.pop()

    def _is_call_insn(self, asm: str) -> bool:
        # 仅识别函数调用：bl、blx
        return asm.startswith('bl ') or asm.startswith('blx ')

    def _is_return_insn(self, asm: str) -> bool:
        # 常见返回：bx lr / mov pc, lr / pop {..., pc} / ldr pc, [...] / ldm ..., {..., pc}
        if 'bx lr' in asm:
            return True
        if asm.startswith('mov ') and 'pc' in asm and 'lr' in asm:
            return True
        if asm.startswith('pop ') and 'pc' in asm:
            return True
        if asm.startswith('ldr ') and asm.split()[1].rstrip(',') == 'pc':
            return True
        if asm.startswith('ldm') and 'pc' in asm:
            return True
        return False

    # === 解码器辅助（带退化日志） ===
    def _decode_event(self, ev: TraceEvent):
        try:
            if get_decoder is None:
                return None
            enc_hex = (ev.encoding or '').replace(' ', '')
            if not enc_hex:
                return None
            dec = get_decoder()
            enc = bytes.fromhex(enc_hex)
            thumb = (len(enc) == 2) and (self.arch == 'arm32')
            return dec.decode(ev.pc, enc, self.arch if self.arch != 'auto' else 'arm32', thumb)
        except Exception:
            return None

    def _warn_decoder(self, reason: str, ev: TraceEvent, exc: Optional[Exception] = None) -> None:
        try:
            cnt = self._decoder_warn_counts.get(reason, 0)
            if cnt < self._decoder_warn_limit:
                logging.getLogger(__name__).warning(
                    "decoder fallback (%s) at line=%d pc=0x%08x asm=%s%s",
                    reason, ev.line_no, ev.pc, ev.asm,
                    f" err={exc}" if exc else ""
                )
                self._decoder_warn_counts[reason] = cnt + 1
            elif cnt == self._decoder_warn_limit:
                logging.getLogger(__name__).warning(
                    "decoder fallback (%s) warnings exceeded limit; suppressing further logs",
                    reason
                )
                self._decoder_warn_counts[reason] = cnt + 1
        except Exception:
            pass

    def _is_call_event(self, ev: TraceEvent) -> bool:
        ins = self._decode_event(ev)
        if ins is None:
            self._warn_decoder('call_decode_unavailable', ev)
            return self._is_call_insn(ev.asm.lower())
        return bool(getattr(ins, 'is_call', False))

    def _is_return_event(self, ev: TraceEvent) -> bool:
        ins = self._decode_event(ev)
        if ins is None:
            self._warn_decoder('ret_decode_unavailable', ev)
            return self._is_return_insn(ev.asm.lower())
        return bool(getattr(ins, 'is_ret', False))

    def _parse_line(self, line_no: int, line: str) -> Optional[TraceEvent]:
        m = self.LINE_RE.match(line)
        if not m:
            return None
        ts = m.group('ts')
        mod = m.group('mod')
        modoff = m.group('modoff')
        enc = m.group('enc')
        pc_hex = m.group('pc')
        asm = m.group('asm')
        rest = m.group('rest') or ''
        try:
            pc = int(pc_hex, 16)
        except ValueError:
            return None

        # 处理JD trace格式：[0x29ce4] 只有偏移，没有模块名
        # 如果mod看起来像一个十六进制地址（0x开头），说明这是JD格式
        if mod and mod.startswith('0x'):
            # JD格式：mod实际是偏移地址
            modoff = mod
            mod = 'unknown'  # 设置默认模块名
        elif modoff is None:
            # 标准格式但没有偏移（不太可能）
            modoff = ''

        reads, writes = self._parse_regs(rest)
        ev = TraceEvent(
            line_no=line_no,
            timestamp=ts,
            module=mod,
            module_offset=modoff,
            encoding=enc,
            pc=pc,
            asm=asm,
            raw=line,
            writes=writes,
            reads=reads,
        )

        # 分支目标收集为“函数候选”
        for bm in self.BRANCH_TARGET_RE.finditer(asm):
            tgt = int(bm.group(2), 16)
            self.branch_targets.setdefault(tgt, f"sub_{bm.group(2)}")

        return ev

    def _parse_regs(self, rest: str) -> Tuple[Dict[str, int], Dict[str, int]]:
        # 解析寄存器对；若出现 '=> rX=0x..' 视为写寄存器（右侧），左侧视为读
        reads: Dict[str, int] = {}
        writes: Dict[str, int] = {}

        if '=>' in rest:
            left, right = rest.split('=>', 1)
        else:
            left, right = rest, ''

        for seg, target in ((left, reads), (right, writes)):
            for m in self.REG_PAIR_RE.finditer(seg):
                pair = m.group(0)
                name_m = self.REG_NAME_RE.match(pair)
                if not name_m:
                    continue
                name = name_m.group(1)
                val_m = self.HEX_RE.search(pair)
                if not val_m:
                    continue
                try:
                    val = int(val_m.group(0), 16)
                except ValueError:
                    continue
                lname = name.lower()
                target[lname] = val
                # 基于寄存器名推断架构（仅在 auto 模式）
                if self.arch == 'auto':
                    if lname.startswith('x') or lname.startswith('w'):
                        self.arch = 'arm64'
                    elif lname.startswith('r') and self.arch != 'arm64':
                        self.arch = 'arm32'

        return reads, writes

    def _index_event(self, ev: TraceEvent) -> None:
        self.events.append(ev)
        idx = len(self.events) - 1
        self.addr_index.setdefault(ev.pc, []).append(idx)
        # 建立倒排索引
        if ev.reads:
            for r in ev.reads.keys():
                # 同时索引 ARM64 的别名（wN/xN 互通）
                for alias in self._alias_names(r):
                    self.reg_read_index.setdefault(alias, []).append(idx)
        if ev.writes:
            for r in ev.writes.keys():
                for alias in self._alias_names(r):
                    self.reg_write_index.setdefault(alias, []).append(idx)

    def _apply_writes(self, ev: TraceEvent) -> None:
        # 先用“读取”补全未知寄存器（尽力而为），再用“写入”覆盖
        for k, v in ev.reads.items():
            # 仅在该寄存器尚无值时设置
            if k not in self._current_regs:
                self._current_regs[k] = v
        for k, v in ev.writes.items():
            self._current_regs[k] = v

    def reconstruct_regs_at(self, event_index: int) -> Dict[str, int]:
        """在给定事件索引处复原寄存器状态。

        使用最近的快照作为起点，减少回放成本。"""
        if not self.events:
            return {}
        event_index = max(0, min(event_index, len(self.events) - 1))

        # LRU 缓存命中
        cached = self._regs_cache.get(event_index)
        if cached is not None:
            # 移动到尾部（最新）
            self._regs_cache.move_to_end(event_index)
            # 更新最近访问索引
            self._recent_access_idx = event_index
            return cached

        # 优化1：检测顺序访问模式
        # 如果是顺序访问（距离上次访问<100），优先从上次位置增量回放
        is_sequential = (self._recent_access_idx >= 0 and 
                        0 < abs(event_index - self._recent_access_idx) < 100)
        
        # 优先：从最近缓存的"精确或之前的"事件状态开始，减少回放成本
        cached_start_idx = None
        cached_regs = None
        
        if is_sequential and self._recent_access_idx in self._regs_cache:
            # 顺序访问：从上次位置开始（即使不是最近的缓存点）
            if self._recent_access_idx <= event_index:
                cached_start_idx = self._recent_access_idx
                cached_regs = self._regs_cache[self._recent_access_idx]
        
        if cached_regs is None and self._regs_cache:
            best_key = -1
            for k in self._regs_cache.keys():
                if k <= event_index and k > best_key:
                    best_key = k
            if best_key >= 0:
                cached_start_idx = best_key
                cached_regs = self._regs_cache[best_key]

        if cached_regs is not None:
            regs = dict(cached_regs)
            start_idx = cached_start_idx + 1
        else:
            # 查找小于等于目标行号的最近快照
            target_line = self.events[event_index].line_no
            checkpoint_line = 0
            for ln in sorted(self._reg_checkpoints.keys()):
                if ln <= target_line:
                    checkpoint_line = ln
                else:
                    break

            regs = dict(self._reg_checkpoints.get(checkpoint_line, {}))

            # 从快照位置回放到目标事件
            start_idx = 0
            if checkpoint_line:
                # 寻找快照行号对应的事件起始索引
                lo, hi = 0, len(self.events) - 1
                while lo <= hi:
                    mid = (lo + hi) // 2
                    if self.events[mid].line_no < checkpoint_line:
                        lo = mid + 1
                    else:
                        hi = mid - 1
                start_idx = lo

        # 优化2：对于回放距离>50的情况，缓存中间点
        replay_distance = event_index - start_idx + 1
        should_cache_midpoint = replay_distance > 50
        midpoint_cached = False
        
        for idx in range(start_idx, event_index + 1):
            ev = self.events[idx]
            if ev.reads:
                for k, v in ev.reads.items():
                    regs.setdefault(k, v)
            if ev.writes:
                regs.update(ev.writes)
            
            # 缓存中间点（约在一半位置）
            if should_cache_midpoint and not midpoint_cached:
                if idx >= start_idx + replay_distance // 2:
                    self._regs_cache[idx] = dict(regs)
                    midpoint_cached = True

        # 记录本次访问位置（用于顺序访问优化）
        self._recent_access_idx = event_index
        
        # 写入缓存并裁剪容量
        self._regs_cache[event_index] = regs
        if len(self._regs_cache) > self._regs_cache_cap:
            try:
                self._regs_cache.popitem(last=False)
            except Exception:
                self._regs_cache.clear()
        return regs

    def find_first_event_by_pc(self, pc: int) -> Optional[int]:
        """查找某地址首次出现的事件索引。"""
        lst = self.addr_index.get(pc)
        return lst[0] if lst else None

    # === 寄存器倒排索引与快速导航 ===
    def find_prev_write(self, reg: str, from_index_exclusive: int) -> Optional[int]:
        lst = self.reg_write_index.get(reg)
        if not lst:
            return None
        pos = bisect_left(lst, from_index_exclusive) - 1
        return lst[pos] if pos >= 0 else None

    def find_next_write(self, reg: str, from_index_inclusive: int) -> Optional[int]:
        lst = self.reg_write_index.get(reg)
        if not lst:
            return None
        pos = bisect_left(lst, from_index_inclusive)
        return lst[pos] if 0 <= pos < len(lst) else None

    def read_indices_in_range(self, reg: str, lo_exclusive: int, hi_exclusive: int) -> List[int]:
        lst = self.reg_read_index.get(reg, [])
        i = bisect_right(lst, lo_exclusive)
        j = bisect_left(lst, hi_exclusive)
        return lst[i:j]

    def build_value_chain_fast(self, reg: str, start_idx: int, value_u32: int, side: str = '执行前') -> List[int]:
        """基于倒排索引快速构建链路：找到将寄存器置为 value 的写入点，然后收集之后的读取直到该值被覆盖。

        side：'执行前'/'执行后'/'任意' 用于确定起点附近的语义，但最终都会回溯到写入点。
        返回：事件索引序列（包括写入点与读取/同值写入）。
        """
        n = len(self.events)
        start_idx = max(0, min(start_idx, n - 1))
        # 定位写入点
        writer_idx: Optional[int] = None
        if side == '执行后':
            ev = self.events[start_idx]
            v_here = self._get_write_value(ev, reg)
            if v_here is not None and (v_here & 0xFFFFFFFF) == (value_u32 & 0xFFFFFFFF):
                writer_idx = start_idx
        if writer_idx is None:
            j = self.find_prev_write(reg, start_idx)
            while j is not None:
                evj = self.events[j]
                val = self._get_write_value(evj, reg)
                if val is not None and (val & 0xFFFFFFFF) == (value_u32 & 0xFFFFFFFF):
                    writer_idx = j
                    break
                j = self.find_prev_write(reg, j)
        if writer_idx is None:
            # 兜底：从起点直接开始
            writer_idx = start_idx

        chain: List[int] = []
        # 向后追加当前 writer
        if writer_idx not in chain:
            chain.append(writer_idx)

        # 向后回溯上游写入，尽可能找到“源”（立即数或只读内存加载）
        back: List[int] = []
        j = self.find_prev_write(reg, writer_idx)
        steps_guard = 0
        while j is not None and steps_guard < 5000:
            steps_guard += 1
            back.append(j)
            evj = self.events[j]
            # 终止条件 1：立即数写入（包含 #imm）
            if self._is_immediate_write(evj, reg):
                break
            # 终止条件 2：内存加载来源且地址无更早的 store（视为常量/字面量池）
            if self._is_load_from_const_memory(j, reg):
                break
            j = self.find_prev_write(reg, j)
        back.reverse()
        chain = back + chain

        # 找到下一个覆盖该寄存器值的写入（不同值）
        nxt = self.find_next_write(reg, writer_idx + 1)
        cutoff = nxt if nxt is not None else n
        # 读取事件（在 writer 与 cutoff 之间）
        reads = self.read_indices_in_range(reg, writer_idx, cutoff)
        chain.extend(reads)
        # 如果期间存在相同值的重复写入，也加入链路并延长 cutoff
        k = nxt
        while k is not None:
            evk = self.events[k]
            valk = self._get_write_value(evk, reg)
            if valk is None:
                break
            if (valk & 0xFFFFFFFF) != (value_u32 & 0xFFFFFFFF):
                break
            chain.append(k)
            k2 = self.find_next_write(reg, k + 1)
            # 追加该写入之后到下一覆盖前的读取
            reads2 = self.read_indices_in_range(reg, k, k2 if k2 is not None else n)
            chain.extend(reads2)
            k = k2
        # 去重并排序
        chain = sorted(set(chain))
        return chain

    def _parse_store_value_reg(self, asm: str) -> Optional[str]:
        """从 store 指令里解析被写入内存的“源寄存器”，例如：
        - str r1, [r0, #4] -> r1
        - strb r2, [r3] -> r2
        - strh x1, [x0, x2, lsl #1] -> x1
        """
        s = asm.strip().lower()
        if not s.startswith('str'):
            return None
        import re as _re
        m = _re.match(r"^str\w*\s+([rxw][0-9]{1,2})\s*,\s*\[", s)
        if not m:
            return None
        return m.group(1)

    def _find_prev_store_to_address(self, addr: int, from_index_exclusive: int, max_steps: int = 1500, same_call_id: Optional[int] = None) -> Optional[int]:
        # 若有地址索引，直接在列表中二分回溯
        lst = self.store_addr_index.get(addr)
        if lst:
            from bisect import bisect_left
            pos = bisect_left(lst, from_index_exclusive) - 1
            while pos >= 0:
                j = lst[pos]
                if same_call_id is not None and self.events[j].call_id != same_call_id:
                    pos -= 1
                    continue
                return j
            return None
        # 退化：顺序扫描（带步数上限）
        steps = 0
        for j in range(from_index_exclusive - 1, -1, -1):
            if steps >= max_steps:
                break
            evj = self.events[j]
            sj = evj.asm.lower()
            if not sj.startswith('str'):
                continue
            if same_call_id is not None and evj.call_id != same_call_id:
                continue
            steps += 1
            a = evj.effaddr if evj.effaddr is not None else self.effective_address(j)
            if a == addr:
                return j
        return None

    def build_value_chain_phase1(self, reg: str, start_idx: int, value_u32: int, side: str = '执行前') -> List[int]:
        """第一阶段：内存感知的值链追踪。

        目标：当目标寄存器的值来源于一次 ldr 加载时，向前找到写入该内存地址的最近一次 store，
        并继续回溯该 store 的“源寄存器”的写入链，直到遇到 ldr 或包含立即数的写入为止。

        若不满足上述条件，回退到 build_value_chain_fast 的结果。
        """
        reg = (reg or '').lower()
        n = len(self.events)
        if n == 0:
            return []
        start_idx = max(0, min(start_idx, n - 1))

        # 先拿到基本链（含写入点与后续读取），用于兜底与并集
        base_chain = set(self.build_value_chain_fast(reg, start_idx, value_u32 & 0xFFFFFFFF, side))

        # 定位写入点（复用快速链路中的逻辑片段）
        writer_idx: Optional[int] = None
        if side == '执行后':
            ev = self.events[start_idx]
            v_here = self._get_write_value(ev, reg)
            if v_here is not None and (v_here & 0xFFFFFFFF) == (value_u32 & 0xFFFFFFFF):
                writer_idx = start_idx
        if writer_idx is None:
            j = self.find_prev_write(reg, start_idx)
            while j is not None:
                evj = self.events[j]
                val = self._get_write_value(evj, reg)
                if val is not None and (val & 0xFFFFFFFF) == (value_u32 & 0xFFFFFFFF):
                    writer_idx = j
                    break
                j = self.find_prev_write(reg, j)
        if writer_idx is None:
            writer_idx = start_idx

        writer_ev = self.events[writer_idx]
        s = writer_ev.asm.lower()
        # 仅在 ldr 写入该寄存器时尝试跨内存回溯
        if not (s.startswith('ldr') and self._has_write(writer_ev, reg)):
            return sorted(base_chain) if base_chain else [writer_idx]

        addr = self.effective_address(writer_idx)
        if addr is None:
            return sorted(base_chain) if base_chain else [writer_idx]

        # 先在同一调用内查找最近 store，未命中再放宽到全局并扩大步数
        store_idx = self._find_prev_store_to_address(addr, writer_idx, same_call_id=self.events[writer_idx].call_id)
        if store_idx is None:
            store_idx = self._find_prev_store_to_address(addr, writer_idx, max_steps=4000, same_call_id=None)
        if store_idx is None:
            return sorted(base_chain) if base_chain else [writer_idx]

        store_ev = self.events[store_idx]
        src_reg = self._parse_store_value_reg(store_ev.asm)
        if not src_reg:
            return sorted(base_chain) if base_chain else [writer_idx]

        # 从 store 之前回溯源寄存器的写入序列，直到 ldr 或立即数写入
        back_chain: List[int] = []
        guard = 0
        j = self.find_prev_write(src_reg, store_idx)
        while j is not None and guard < 6000:
            guard += 1
            evj = self.events[j]
            back_chain.append(j)
            sj = evj.asm.lower()
            if sj.startswith('ldr '):
                break
            if self._is_immediate_write(evj, src_reg):
                break
            j = self.find_prev_write(src_reg, j)

        chain = set(back_chain)
        chain.add(store_idx)
        chain.add(writer_idx)
        # 合并基础链（含向后读取等）
        chain.update(base_chain)
        return sorted(chain)

    def value_chain_from_event(self, reg: str, event_index: int, side: str = '执行前') -> List[int]:
        ev = self.events[event_index]
        b = self._get_read_value(ev, reg)
        a = self._get_write_value(ev, reg)
        val = None
        if side == '执行后' and a is not None:
            val = a
        elif b is not None:
            val = b
        elif a is not None:
            val = a
        else:
            # 回退到复原
            if side == '执行前':
                val = self.reconstruct_regs_at(event_index - 1).get(reg)
            else:
                val = self.reconstruct_regs_at(event_index).get(reg)
        if val is None:
            return []
        return self.build_value_chain_fast(reg, event_index, val & 0xFFFFFFFF, side)

    # === 反向溯源（Backward Dynamic Slice） ===
    def build_provenance_backtrace(self,
                                   reg: str,
                                   start_idx: int,
                                   side: str = '执行后',
                                   max_nodes: int = 4000) -> List[int]:
        """从指定事件与寄存器出发，回溯其值的来源路径（寄存器/内存）。

        规则：
        - 若定义来自立即数/恒零归约：作为叶子停止；
        - 若定义来自 ldr：找到上一次对该地址的 store，将其加入路径，并继续回溯 store 的源寄存器；
        - 若定义来自算术/位运算：对所有读取寄存器回溯其上一次写入；
        返回：涉及的事件索引（去重、按时间排序）。
        """
        reg = (reg or '').lower()
        n = len(self.events)
        if n == 0:
            return []
        start_idx = max(0, min(start_idx, n - 1))

        # 取起点值（用于定位对应写入点）
        ev0 = self.events[start_idx]
        v_before = ev0.reads.get(reg)
        v_after = self._get_write_value(ev0, reg)
        if side == '执行后' and v_after is not None:
            want_val = v_after & 0xFFFFFFFF
        elif v_before is not None:
            want_val = v_before & 0xFFFFFFFF
        else:
            # 回退复原
            ref = self.reconstruct_regs_at(start_idx if side == '执行后' else (start_idx - 1))
            want_val = ref.get(reg)
            if want_val is None:
                return []
            want_val &= 0xFFFFFFFF

        # 定位写入该值的定义点
        writer_idx: Optional[int] = None
        if side == '执行后':
            v_here = self._get_write_value(ev0, reg)
            if v_here is not None and (v_here & 0xFFFFFFFF) == want_val:
                writer_idx = start_idx
        if writer_idx is None:
            j = self.find_prev_write(reg, start_idx)
            while j is not None:
                evj = self.events[j]
                valj = self._get_write_value(evj, reg)
                if valj is not None and (valj & 0xFFFFFFFF) == want_val:
                    writer_idx = j
                    break
                j = self.find_prev_write(reg, j)
        if writer_idx is None:
            writer_idx = start_idx

        # 回溯工作栈
        work: List[Tuple[str, int]] = [(reg, writer_idx)]
        seen_keys = set()
        nodes: List[int] = []

        guard = 0
        while work and guard < max_nodes:
            guard += 1
            cur_reg, cur_idx = work.pop()
            key = (cur_reg, cur_idx)
            if key in seen_keys:
                continue
            seen_keys.add(key)
            if cur_idx not in nodes:
                nodes.append(cur_idx)

            ev = self.events[cur_idx]
            s = ev.asm.lower()

            # 立即数/恒零：叶子
            if self._is_constant_zero_write(ev, cur_reg) or self._is_immediate_write(ev, cur_reg):
                continue

            # ldr：回溯 store 源
            if s.startswith('ldr') and self._has_write(ev, cur_reg):
                addr = self.effective_address(cur_idx)
                if addr is None:
                    # 地址不可解析，视为叶子
                    continue
                store_idx = self._find_prev_store_to_address(addr, cur_idx, same_call_id=ev.call_id)
                if store_idx is None:
                    store_idx = self._find_prev_store_to_address(addr, cur_idx, max_steps=6000, same_call_id=None)
                if store_idx is not None:
                    if store_idx not in nodes:
                        nodes.append(store_idx)
                    src_reg = self._parse_store_value_reg(self.events[store_idx].asm)
                    if src_reg:
                        prev = self.find_prev_write(src_reg, store_idx)
                        if prev is not None:
                            work.append((src_reg, prev))
                continue

            # 算术/位运算：回溯所有读取寄存器
            if ev.reads:
                for src_reg in list(ev.reads.keys()):
                    prev = self.find_prev_write(src_reg, cur_idx)
                    if prev is not None:
                        work.append((src_reg, prev))

        # 输出按事件时间排序，去重
        nodes = sorted(set(nodes))
        return nodes

    def build_provenance_graph(self,
                               reg: str,
                               start_idx: int,
                               side: str = '执行后',
                               max_nodes: int = 4000) -> Tuple[List[int], List[Tuple[str, int, int, str]]]:
        """与 build_provenance_backtrace 类似，但同时返回边集合。

        返回：
          nodes: 事件索引（有序、去重）
          edges: 列表 (etype, src_idx, dst_idx, meta)
                 - etype: 'data' | 'mem'
                 - meta:  对 data 为寄存器名；对 mem 为 0x... 地址字符串
        """
        reg = (reg or '').lower()
        n = len(self.events)
        if n == 0:
            return [], []
        start_idx = max(0, min(start_idx, n - 1))

        ev0 = self.events[start_idx]
        v_before = ev0.reads.get(reg)
        v_after = self._get_write_value(ev0, reg)
        if side == '执行后' and v_after is not None:
            want_val = v_after & 0xFFFFFFFF
        elif v_before is not None:
            want_val = v_before & 0xFFFFFFFF
        else:
            ref = self.reconstruct_regs_at(start_idx if side == '执行后' else (start_idx - 1))
            want_val = ref.get(reg)
            if want_val is None:
                return [], []
            want_val &= 0xFFFFFFFF

        writer_idx: Optional[int] = None
        if side == '执行后':
            v_here = self._get_write_value(ev0, reg)
            if v_here is not None and (v_here & 0xFFFFFFFF) == want_val:
                writer_idx = start_idx
        if writer_idx is None:
            j = self.find_prev_write(reg, start_idx)
            while j is not None:
                evj = self.events[j]
                valj = self._get_write_value(evj, reg)
                if valj is not None and (valj & 0xFFFFFFFF) == want_val:
                    writer_idx = j
                    break
                j = self.find_prev_write(reg, j)
        if writer_idx is None:
            writer_idx = start_idx

        work: List[Tuple[str, int]] = [(reg, writer_idx)]
        seen_keys = set()
        nodes: List[int] = []
        edges: List[Tuple[str, int, int, str]] = []

        guard = 0
        while work and guard < max_nodes:
            guard += 1
            cur_reg, cur_idx = work.pop()
            key = (cur_reg, cur_idx)
            if key in seen_keys:
                continue
            seen_keys.add(key)
            if cur_idx not in nodes:
                nodes.append(cur_idx)

            ev = self.events[cur_idx]
            s = ev.asm.lower()

            if self._is_constant_zero_write(ev, cur_reg) or self._is_immediate_write(ev, cur_reg):
                continue

            if s.startswith('ldr') and self._has_write(ev, cur_reg):
                addr = self.effective_address(cur_idx)
                if addr is None:
                    continue
                store_idx = self._find_prev_store_to_address(addr, cur_idx, same_call_id=ev.call_id)
                if store_idx is None:
                    store_idx = self._find_prev_store_to_address(addr, cur_idx, max_steps=6000, same_call_id=None)
                if store_idx is not None:
                    if store_idx not in nodes:
                        nodes.append(store_idx)
                    edges.append(('mem', store_idx, cur_idx, f"0x{addr & 0xFFFFFFFF:08x}"))
                    src_reg = self._parse_store_value_reg(self.events[store_idx].asm)
                    if src_reg:
                        prev = self.find_prev_write(src_reg, store_idx)
                        if prev is not None:
                            edges.append(('data', prev, store_idx, src_reg))
                            work.append((src_reg, prev))
                continue

            if ev.reads:
                for src_reg in list(ev.reads.keys()):
                    prev = self.find_prev_write(src_reg, cur_idx)
                    if prev is not None:
                        edges.append(('data', prev, cur_idx, src_reg))
                        work.append((src_reg, prev))

        nodes = sorted(set(nodes))
        # 去重 edges（稳定顺序）
        seen_e = set()
        ordered_edges = []
        for et, u, v, m in edges:
            key = (et, u, v, m)
            if key in seen_e:
                continue
            seen_e.add(key)
            ordered_edges.append((et, u, v, m))
        return nodes, ordered_edges

    # === 值来源解释（面向 UI 显示） ===
    def analyze_value_origin(self, reg: str, start_idx: int, value_u32: int, side: str = '执行前') -> Dict[str, object]:
        """给出“直接来源 / 间接依赖 / 溯源缺口”的简要解释。

        直接来源：若起点定义是 ldr，报告有效地址；若是算术，报告表达式与参与寄存器；若是立即数，报告字面量。
        间接依赖：给出寻址依赖寄存器值（base/index/imm）或算术参与寄存器快照。
        溯源缺口：列出需要继续追的内存地址（找上次 store）与栈地址（找更早的 str）。
        """
        result: Dict[str, object] = {
            'direct': '',
            'indirect': [],
            'gaps': [],
        }
        n = len(self.events)
        if n == 0:
            return result
        start_idx = max(0, min(start_idx, n - 1))

        # 找写入该值的定义点
        writer_idx: Optional[int] = None
        if side == '执行后' and self._has_write(self.events[start_idx], reg) and (self._get_write_value(self.events[start_idx], reg) & 0xFFFFFFFF) == (value_u32 & 0xFFFFFFFF):
            writer_idx = start_idx
        if writer_idx is None:
            j = self.find_prev_write(reg, start_idx)
            while j is not None:
                evj = self.events[j]
                valj = self._get_write_value(evj, reg)
                if valj is not None and (valj & 0xFFFFFFFF) == (value_u32 & 0xFFFFFFFF):
                    writer_idx = j
                    break
                j = self.find_prev_write(reg, j)
        if writer_idx is None:
            writer_idx = start_idx

        evw = self.events[writer_idx]
        s = evw.asm.lower()
        regs_at = self.reconstruct_regs_at(writer_idx)

        # 1) ldr 直接来源：有效地址
        if s.startswith('ldr') and self._has_write(evw, reg):
            addr = self.effective_address(writer_idx)
            if addr is not None:
                result['direct'] = f"从内存 0x{addr:08x} 加载"
                # 尝试构造 base/index/imm 解释（粗略从 reads 取前两个）
                reads = list(evw.reads.keys())
                base = reads[0] if reads else None
                index = reads[1] if len(reads) >= 2 else None
                if base:
                    bval = regs_at.get(base)
                    ctx = f"{base}=0x{bval:08x}" if bval is not None else base
                    if index:
                        ival = regs_at.get(index)
                        result['indirect'].append(f"地址依赖：{ctx}, {index}=0x{(ival or 0):08x}")
                    else:
                        result['indirect'].append(f"地址依赖：{ctx}")
                # 缺口：该地址上一次写入
                result['gaps'].append({'type': 'mem', 'addr': f"0x{addr:08x}", 'hint': '查找更早的 store/写入'})
            return result

        # 2) 立即数 / 恒零
        if self._is_immediate_write(evw, reg) or self._is_constant_zero_write(evw, reg):
            result['direct'] = '立即数装载/恒等归零'
            return result

        # 3) 算术/位运算：记录参与寄存器
        if evw.reads:
            parts = []
            for r in list(evw.reads.keys())[:3]:
                v = regs_at.get(r)
                parts.append(f"{r}=0x{(v or 0):08x}")
            result['direct'] = '算术/位运算结果'
            if parts:
                result['indirect'].append('参与寄存器：' + ', '.join(parts))
        return result

    # === 源判定与有效地址 ===
    def _is_immediate_write(self, ev: TraceEvent, reg: str) -> bool:
        if reg not in ev.writes:
            return False
        s = ev.asm.lower()
        if '#' not in s:
            return False
        # 常见包含立即数的写入/合成指令
        # 注：arm64 的 movz/movn 属于立即数装载，会覆盖目标寄存器；movk 只修改部分位，不视为清洗
        return any(s.startswith(op) for op in (
            'mov ', 'mvn ', 'orr ', 'eor ', 'and ', 'add ', 'sub ', 'movw', 'movt', 'movz', 'movn'
        ))

    def _is_constant_zero_write(self, ev: TraceEvent, reg: str) -> bool:
        """判断本条写入是否将 reg 设为与任何输入无关的"常量 0"。

        覆盖若干常见等式归约：
        - mov rd, xzr/wzr            -> 0
        - eor rd, rn, rn             -> 0
        - sub/rsb rd, rn, rn         -> 0
        - bic rd, rn, rn             -> 0   (rn & ~rn)
        - and rd, rn, #0             -> 0
        - mul rd, rn, #0 / mul rd, rn, xzr -> 0
        - mov rd, #0                 -> 属于 _is_immediate_write 覆盖，此处不重复判断
        """
        if reg not in ev.writes:
            return False
        s = ev.asm.lower().strip()
        import re as _re
        # 通用二参：op rd, rn
        m2 = _re.match(r"^(\w+)\s+(\w+)\s*,\s*([^,]+)$", s)
        # 通用三参：op rd, rn, rm/operand2
        m3 = _re.match(r"^(\w+)\s+(\w+)\s*,\s*([^,]+)\s*,\s*(.+)$", s)

        def _is_zero_imm(txt: str) -> bool:
            t = txt.replace('#', '').strip()
            try:
                if t.startswith('0x'):
                    return int(t, 16) == 0
                return int(t, 10) == 0
            except Exception:
                return False

        # mov rd, xzr/wzr
        if m2 and m2.group(1) == 'mov' and m2.group(2) == reg:
            rn = m2.group(3).strip()
            if rn in ('xzr', 'wzr'):
                return True
        # and rd, rn, #0
        if m3 and m3.group(1) == 'and' and m3.group(2) == reg:
            rm = m3.group(4).strip()
            if _is_zero_imm(rm):
                return True
        # mul rd, rn, #0 / mul rd, rn, xzr/wzr
        if m3 and m3.group(1) in ('mul', 'mla', 'mls') and m3.group(2) == reg:
            rm = m3.group(4).strip()
            if _is_zero_imm(rm) or rm in ('xzr', 'wzr'):
                return True
        # eor/sub/rsb/bic rd, rn, rn
        if m3 and m3.group(2) == reg:
            op = m3.group(1)
            rn = m3.group(3).strip().rstrip(',')
            rm = m3.group(4).strip()
            if rm.endswith(','):
                rm = rm[:-1].strip()
            if rm == rn and op in ('eor', 'sub', 'rsb', 'bic'):
                return True
        return False

    def _is_load_from_const_memory(self, event_index: int, reg: str) -> bool:
        ev = self.events[event_index]
        s = ev.asm.lower()
        if not s.startswith('ldr') or not self._has_write(ev, reg):
            return False
        addr = self.effective_address(event_index)
        if addr is None:
            return False
        # 优先使用预建索引：若该地址在整个 trace 中没有任何 store，或在本次 ldr 之前没有 store，则视为常量来源
        lst = self.store_addr_index.get(addr)
        if not lst:
            return True
        from bisect import bisect_left
        pos = bisect_left(lst, event_index) - 1
        return pos < 0

    # === 内存污点辅助函数 ===
    def _get_mem_access_width(self, asm: str) -> int:
        """根据指令助记符返回访存宽度（字节数）。
        
        ldrb/strb -> 1
        ldrh/strh -> 2
        ldr/str -> 4
        ldrd/strd -> 8
        默认 -> 4
        """
        s = asm.lower().strip()
        mnem = s.split()[0] if s else ''
        
        if mnem.endswith('b'):  # ldrb, strb
            return 1
        elif mnem.endswith('h'):  # ldrh, strh
            return 2
        elif mnem.endswith('d'):  # ldrd, strd
            return 8
        else:
            return 4
    
    def _mark_memory_tainted(self, tainted_mem: set, base_addr: int, width: int) -> None:
        """将内存地址及其跨越的字节范围标记为污点。
        
        Args:
            tainted_mem: 污点内存地址集合
            base_addr: 基地址
            width: 访存宽度（字节数）
        """
        base = base_addr & 0xFFFFFFFF
        for offset in range(width):
            tainted_mem.add((base + offset) & 0xFFFFFFFF)
    
    def _check_memory_tainted(self, tainted_mem: set, base_addr: int, width: int) -> bool:
        """检查内存地址范围内是否有任何字节被污染。
        
        Args:
            tainted_mem: 污点内存地址集合
            base_addr: 基地址
            width: 访存宽度（字节数）
            
        Returns:
            如果访问范围内有任何字节被污染，返回True
        """
        base = base_addr & 0xFFFFFFFF
        for offset in range(width):
            if ((base + offset) & 0xFFFFFFFF) in tainted_mem:
                return True
        return False

    # === 指令类型判定（用于污点分析） ===
    def _is_bitfield_op(self, asm: str) -> bool:
        """判断是否为位域操作指令（ubfx/sbfx/bfc/bfi）"""
        s = asm.lower().strip()
        return any(s.startswith(op) for op in ('ubfx ', 'sbfx ', 'bfc ', 'bfi '))

    def _is_multiply_op(self, asm: str) -> bool:
        """判断是否为乘法指令（mul/mla/mls/umull/smull等）"""
        s = asm.lower().strip()
        return any(s.startswith(op) for op in ('mul ', 'mla ', 'mls ', 'umull ', 'smull ', 'umlal ', 'smlal '))
    
    def _is_extend_op(self, asm: str) -> bool:
        """判断是否为扩展运算指令（sxtah/sxtab/uxtah/uxtab等）"""
        s = asm.lower().strip()
        return any(s.startswith(op) for op in ('sxtah ', 'sxtab ', 'uxtah ', 'uxtab ', 'sxth ', 'sxtb ', 'uxth ', 'uxtb '))
    
    def _is_bitwise_not_op(self, asm: str) -> bool:
        """判断是否为位非相关运算（orn/bic/mvn等）"""
        s = asm.lower().strip()
        return any(s.startswith(op) for op in ('orn ', 'bic ', 'mvn '))

    def _is_unary_op(self, asm: str) -> bool:
        """判断是否为单目指令（clz/rbit/rev/rev16等）"""
        s = asm.lower().strip()
        return any(s.startswith(op) for op in ('clz ', 'rbit ', 'rev ', 'rev16 ', 'revsh '))

    def _is_conditional_op(self, asm: str) -> bool:
        """判断是否为条件执行指令（带条件后缀的指令）"""
        s = asm.lower().strip()
        import re as _re
        # 匹配指令助记符后跟条件码：如 addeq, movne, streq 等
        m = _re.match(r'^([a-z]+)(eq|ne|cs|hs|cc|lo|mi|pl|vs|vc|hi|ls|ge|lt|gt|le|al)\s', s)
        return m is not None

    def _is_partial_bitfield_clear(self, ev: TraceEvent, reg: str) -> bool:
        """检测 bfc 指令是否将寄存器的某些位清零（部分清洗）。
        
        bfc 指令格式：bfc rd, #lsb, #width
        将 rd[lsb+width-1:lsb] 清零，其他位保持不变。
        
        对于污点分析：
        - 如果污点在被清零的位域内，则部分清洗
        - 但我们无法精确跟踪位级污点，因此保守策略是：
          * 不完全清洗寄存器污点（因为其他位可能仍被污染）
          * 标记为部分清洗事件供用户参考
        
        返回True表示这是一个bfc指令，False表示不是。
        """
        if reg not in ev.writes:
            return False
        s = ev.asm.lower().strip()
        return s.startswith('bfc ')

    def _parse_register_list(self, asm: str) -> List[str]:
        """解析指令中的寄存器列表。
        
        支持格式：
        - push {r0-r7, lr}
        - pop {r0, r1, r2, pc}
        - stm sp!, {r0-r3}
        - ldm sp!, {r4-r7}
        
        返回展开后的寄存器列表，如 ['r0', 'r1', 'r2', ...]
        """
        import re as _re
        s = asm.lower().strip()
        
        # 提取花括号内的内容
        m = _re.search(r'\{([^}]+)\}', s)
        if not m:
            return []
        
        reg_text = m.group(1).strip()
        regs = []
        
        # 分割逗号分隔的各项
        for part in reg_text.split(','):
            part = part.strip()
            
            # 处理范围：r0-r7, x0-x3 等
            if '-' in part:
                range_match = _re.match(r'([rxw])(\d+)-([rxw])(\d+)', part)
                if range_match:
                    prefix = range_match.group(1)
                    start = int(range_match.group(2))
                    end = int(range_match.group(4))
                    for i in range(start, end + 1):
                        regs.append(f"{prefix}{i}")
            else:
                # 单个寄存器
                if part in ('r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9',
                           'r10', 'r11', 'r12', 'r13', 'r14', 'r15',
                           'sp', 'lr', 'pc', 'cpsr') or \
                   _re.match(r'^[xw]\d{1,2}$', part):
                    regs.append(part)
        
        return regs
    
    def _parse_dual_regs(self, asm: str) -> Tuple[Optional[str], Optional[str]]:
        """解析双寄存器指令（ldrd/strd）的两个目标/源寄存器。
        
        格式：
        - ldrd r0, r1, [r2]  -> ('r0', 'r1')
        - strd r0, r1, [r2, #8]  -> ('r0', 'r1')
        
        返回 (reg1, reg2) 或 (None, None) 如果解析失败
        """
        import re as _re
        s = asm.lower().strip()
        
        # 匹配 strd/ldrd rd1, rd2, [...]
        m = _re.match(r'^(strd|ldrd)\s+([rxw]\d{1,2})\s*,\s*([rxw]\d{1,2})\s*,\s*\[', s)
        if m:
            return (m.group(2), m.group(3))
        
        return (None, None)
    
    def _is_multi_register_load_store(self, asm: str) -> bool:
        """判断是否为多寄存器加载/存储指令（push/pop/ldm/stm）"""
        s = asm.lower().strip()
        return any(s.startswith(op) for op in ('push ', 'pop ', 'ldm', 'stm', 'ldrd ', 'strd '))
    
    # === ARM64特有指令检测 ===
    
    def _is_conditional_select_op(self, asm: str) -> bool:
        """检测ARM64条件选择指令（csel/csinc/csinv/csneg）
        
        csel xd, xn, xm, cond - 根据条件选择xn或xm
        csinc xd, xn, xm, cond - 选择xn或(xm+1)
        csinv xd, xn, xm, cond - 选择xn或(~xm)
        csneg xd, xn, xm, cond - 选择xn或(-xm)
        
        出现次数：约12.7万次（csel）
        """
        s = asm.lower().strip()
        return any(s.startswith(op) for op in ('csel ', 'csinc ', 'csinv ', 'csneg '))
    
    def _is_conditional_set_op(self, asm: str) -> bool:
        """检测ARM64条件设置指令（cset/csetm）
        
        cset wd, cond - 根据条件设置为0或1
        csetm wd, cond - 根据条件设置为0或-1(0xFFFFFFFF)
        
        出现次数：约11.6万次（cset）
        污点传播：设置常量，应该清洗污点
        """
        s = asm.lower().strip()
        return any(s.startswith(op) for op in ('cset ', 'csetm '))
    
    def _parse_csel_operands(self, asm: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """解析csel指令的操作数：rd, rn, rm
        
        格式：csel xd, xn, xm, cond
        返回：(xd, xn, xm)
        """
        import re as _re
        s = asm.lower().strip()
        # 匹配: csel/csinc/csinv/csneg xd, xn, xm, cond
        m = _re.match(r'^cs(?:el|inc|inv|neg)\s+([xw]\d+)\s*,\s*([xw]\d+)\s*,\s*([xw]\d+)\s*,', s)
        if m:
            return (m.group(1), m.group(2), m.group(3))
        return (None, None, None)
    
    def _is_movk_op(self, asm: str) -> bool:
        """检测ARM64 movk指令（构造多字节立即数）
        
        movk xd, #imm, lsl #shift - 修改寄存器的特定16位，其他位保持不变
        
        出现次数：约69.9万次
        污点传播：不应完全清洗污点（与mov不同），因为只修改部分位
        """
        s = asm.lower().strip()
        return s.startswith('movk ')
    
    def _is_madd_op(self, asm: str) -> bool:
        """检测ARM64乘加指令（madd/msub/smaddl/umaddl等）
        
        madd xd, xn, xm, xa - xd = xa + (xn * xm)
        msub xd, xn, xm, xa - xd = xa - (xn * xm)
        smaddl xd, wn, wm, xa - xd = xa + SignExtend(wn * wm)
        umaddl xd, wn, wm, xa - xd = xa + ZeroExtend(wn * wm)
        
        出现次数：1.9万（madd）+ 9598（smaddl）
        """
        s = asm.lower().strip()
        return any(s.startswith(op) for op in ('madd ', 'msub ', 'smaddl ', 'umaddl ', 'smsubl ', 'umsubl '))
    
    def _parse_madd_operands(self, asm: str) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
        """解析madd指令的4个操作数：rd, rn, rm, ra
        
        格式：madd xd, xn, xm, xa
        返回：(xd, xn, xm, xa)
        """
        import re as _re
        s = asm.lower().strip()
        # 匹配: madd/msub/smaddl等 xd, xn, xm, xa
        m = _re.match(r'^[smu]*[madd|msub|maddl|msubl]+\s+([xw]\d+)\s*,\s*([xw]\d+)\s*,\s*([xw]\d+)\s*,\s*([xw]\d+)', s)
        if m:
            return (m.group(1), m.group(2), m.group(3), m.group(4))
        return (None, None, None, None)
    
    def _is_extend_op_arm64(self, asm: str) -> bool:
        """检测ARM64扩展指令（sxtw/sxth/sxtb/uxtw/uxth/uxtb）
        
        sxtw xd, wn - 将32位值符号扩展到64位
        uxtw xd, wn - 将32位值零扩展到64位
        
        出现次数：1万（sxtw）
        """
        s = asm.lower().strip()
        # ARM64的扩展指令（不带h后缀，与ARM32区分）
        return any(s.startswith(op) for op in ('sxtw ', 'uxtw '))
    
    def _is_adrp_op(self, asm: str) -> bool:
        """检测ARM64 adrp指令（计算页对齐地址）
        
        adrp xd, #addr - 计算页对齐地址（4KB对齐）
        
        出现次数：约8.8万次
        污点传播：结果是编译时确定的地址常量，应该清洗污点
        """
        s = asm.lower().strip()
        return s.startswith('adrp ')

    def _is_constant_pool_load(self, event_index: int, reg: str) -> bool:
        """判断是否从常量池加载（可视为污点清洗的特殊情况）。
        
        常量池加载的特征：
        1. ldr 指令
        2. 从只读内存区域加载（该地址在整个trace中从未被写入）
        3. 通常是 ldr rd, [pc, #offset] 形式
        
        这种加载可以视为污点清洗，因为值来自编译时确定的常量。
        """
        if event_index < 0 or event_index >= len(self.events):
            return False
        ev = self.events[event_index]
        s = ev.asm.lower()
        
        # 必须是 ldr 指令且写入目标寄存器
        if not s.startswith('ldr') or not self._has_write(ev, reg):
            return False
        
        # 检查是否为 PC 相对寻址（常见的常量池访问模式）
        if 'pc' in s or '[pc' in s:
            # 这是一个强指示，通常是从常量池加载
            return True
        
        # 使用已有的 _is_load_from_const_memory 检测
        return self._is_load_from_const_memory(event_index, reg)

    # === 辅助：边界与循环/栈等识别 ===
    def _bl_target_addr(self, asm: str) -> Optional[int]:
        try:
            m = self.DIRECT_ADDR_RE.search(asm)
            if m:
                return int(m.group(1), 16)
        except Exception:
            return None
        return None

    def is_external_call(self, event_index: int) -> bool:
        ev = self.events[event_index]
        s = ev.asm.lower()
        if not s.startswith('bl'):
            return False
        tgt = self._bl_target_addr(s)
        if tgt is None:
            return False
        # 不在 addr_index 视为外部/未跟踪函数
        return self.addr_index.get(tgt) is None

    def is_loop_head(self, event_index: int, window: int = 32) -> bool:
        pc = self.events[event_index].pc
        lo = max(0, event_index - window)
        for j in range(event_index - 1, lo - 1, -1):
            if self.events[j].pc == pc:
                return True
        return False

    def is_stack_address(self, event_index: int) -> bool:
        ev = self.events[event_index]
        if not (ev.asm.lower().startswith('ldr') or ev.asm.lower().startswith('str')):
            return False
        # 基于读取集包含 sp 或 地址接近 sp 的启发式
        regs = self.reconstruct_regs_at(event_index)
        sp = regs.get('sp')
        addr = self.effective_address(event_index)
        if 'sp' in ev.reads:
            return True
        if sp is not None and addr is not None:
            return abs(((addr & 0xFFFFFFFF) - (sp & 0xFFFFFFFF)) & 0xFFFFFFFF) < 0x8000
        return False

    def effective_address(self, event_index: int) -> Optional[int]:
        if event_index < 0 or event_index >= len(self.events):
            return None
        # LRU 缓存
        cached = self._effaddr_cache.get(event_index)
        if cached is not None:
            self._effaddr_cache.move_to_end(event_index)
            return cached
        ev = self.events[event_index]
        asm = ev.asm.lower()
        if not (asm.startswith('str') or asm.startswith('ldr')):
            return None
        # 优先尝试解码器（若可用），并记录退化原因
        try:
            if get_decoder is not None and ev.encoding:
                dec = get_decoder()
                enc_hex = ev.encoding.replace(' ', '')
                enc = bytes.fromhex(enc_hex)
                thumb = (len(enc) == 2) and (self.arch == 'arm32')
                ins = dec.decode(ev.pc, enc, self.arch if self.arch != 'auto' else 'arm32', thumb)
                if ins is None:
                    self._warn_decoder('effaddr_decode_none', ev)
                elif not getattr(ins, 'mem_ops', None):
                    self._warn_decoder('effaddr_no_memops', ev)
                else:
                    regs = self.reconstruct_regs_at(event_index)
                    base = None
                    index = None
                    shift = 0
                    imm = 0
                    # 先占位读取 mem_ops（未来可解析 base/index/imm/shift）
                    for r in ev.reads.keys():
                        if base is None:
                            base = r
                        elif index is None:
                            index = r
                    b = regs.get((base or '').lower()) if base else None
                    i = regs.get((index or '').lower()) if index else None
                    if b is None:
                        self._warn_decoder('effaddr_missing_base', ev)
                    else:
                        val = (b + ((i or 0) << shift) + imm) & 0xFFFFFFFF
                        self._effaddr_cache[event_index] = val
                        if len(self._effaddr_cache) > self._effaddr_cache_cap:
                            try:
                                self._effaddr_cache.popitem(last=False)
                            except Exception:
                                self._effaddr_cache.clear()
                        return val
            else:
                self._warn_decoder('effaddr_decoder_unavailable', ev)
        except Exception as e:
            self._warn_decoder('effaddr_exception', ev, e)
        # 若已预计算，直接返回并写入 LRU
        if ev.effaddr is not None:
            self._effaddr_cache[event_index] = ev.effaddr
            return ev.effaddr
        lb = asm.find('[')
        rb = asm.find(']', lb + 1)
        if lb < 0 or rb < 0:
            return None
        expr = asm[lb + 1:rb].strip()
        suffix = asm[rb + 1:].strip()  # 处理 post-index 形式：], #imm
        regs = self.reconstruct_regs_at(event_index)

        def getv(rname: str):
            return regs.get(rname.strip().lower())

        # 统一解析：base + (index << shift) + imm, ARM64 变体（含 uxtw/sxtw/sxtx/lsl），以及 pre/post-index
        try:
            base = None
            index = None
            shift = 0
            imm = 0
            import re as _re
            # 1) 提取 base 与剩余
            parts = [p.strip() for p in expr.split(',')]
            if len(parts) >= 1:
                base = parts[0]
            # 2) 立即数在 [] 内： [x0, #imm]
            if len(parts) >= 2 and parts[1].startswith('#'):
                try:
                    imm = int(parts[1].lstrip('#'), 0)
                except Exception:
                    imm = 0
            # 3) index + 可选变换： [x0, x2, lsl #3] / [x0, w2, uxtw #2] / [x0, w2, uxtw]
            if len(parts) >= 2 and not parts[1].startswith('#'):
                index = parts[1]
                if len(parts) >= 3:
                    mod = parts[2].lower()
                    if 'lsl' in mod:
                        try:
                            shift = int(mod.split('#')[-1], 0)
                        except Exception:
                            shift = 0
                    # uxtw/sxtw/sxtx：本实现仅作为索引参与，按 32bit/符号扩展近似
                    # 实际地址宽度我们仍按 32 位裁剪
                # 某些语法为 [x0, w2, uxtw #2] 或 [x0, w2, uxtw]
                if len(parts) >= 3 and ('uxtw' in parts[2].lower() or 'sxtw' in parts[2].lower() or 'sxtx' in parts[2].lower()):
                    if '#' in parts[2]:
                        try:
                            shift = int(parts[2].split('#')[-1], 0)
                        except Exception:
                            shift = shift
            # 4) pre-index: 以 ']' 后紧跟 '!' 表示，实际地址为 base+imm
            pre_index = '!' in asm[lb:rb+1]
            # 5) post-index: '], #imm' 出现在后缀；实际地址为 base（本次访存使用旧 base）
            post_index_imm = 0
            if suffix.startswith(',') and '# ' in suffix.replace('#', ' #'):
                try:
                    m = _re.search(r",\s*#\s*([+-]?(?:0x[0-9a-fA-F]+|\d+))", suffix)
                    if m:
                        post_index_imm = int(m.group(1), 0)
                except Exception:
                    post_index_imm = 0

            b = getv(base or '') if base else None
            i = getv(index or '') if index else 0
            if b is None:
                return None
            addr = (b + ((i or 0) << (shift or 0)) + (imm if pre_index else 0)) & 0xFFFFFFFF
            # post-index 不影响本次有效地址
            res = addr
            self._effaddr_cache[event_index] = res
            if len(self._effaddr_cache) > self._effaddr_cache_cap:
                try:
                    self._effaddr_cache.popitem(last=False)
                except Exception:
                    self._effaddr_cache.clear()
            return res
        except Exception:
            pass
        # 兼容最简单形式： [r0]/[x0]/[w0]
        if ',' not in expr and (expr.startswith('r') or expr.startswith('x') or expr.startswith('w')):
            v = getv(expr)
            if v is None:
                return None
            res = v & 0xFFFFFFFF
            self._effaddr_cache[event_index] = res
            return res
        # 未命中可解析形式
        self._effaddr_cache[event_index] = None
        if len(self._effaddr_cache) > self._effaddr_cache_cap:
            try:
                self._effaddr_cache.popitem(last=False)
            except Exception:
                self._effaddr_cache.clear()
        return None

    def _precompute_memory_effects(self) -> None:
        """为所有 ldr/str 事件预计算有效地址，并为 str 事件建立地址倒排索引。"""
        try:
            self.store_addr_index.clear()
            for idx, ev in enumerate(self.events):
                s = ev.asm.lower()
                if not (s.startswith('ldr') or s.startswith('str')):
                    continue
                # 计算并缓存有效地址
                addr = self.effective_address(idx)
                ev.effaddr = addr
                # 标注访存类型与宽度
                try:
                    ev.mem_op = 'ldr' if s.startswith('ldr') else ('str' if s.startswith('str') else '')
                    # 优先依据助记符中的后缀判定宽度（b/h -> 1/2），否则依据目的/源寄存器名称宽度
                    width = 0
                    mnem = s.split()[0]
                    if mnem.startswith('ldrb') or mnem.startswith('strb'):
                        width = 1
                    elif mnem.startswith('ldrh') or mnem.startswith('strh'):
                        width = 2
                    else:
                        # 依据寄存器名推断：xN -> 8 ; wN/rN -> 4
                        # 对于访存，首参通常为寄存器（ldr/str 的 rd 或 rn）
                        try:
                            ops_txt = ev.asm.split(None, 1)[1]
                            first_op = ops_txt.split(',')[0].strip()
                            if first_op.startswith('x'):
                                width = 8
                            else:
                                width = 4
                        except Exception:
                            width = 4
                    ev.mem_width = width
                except Exception:
                    ev.mem_op = ev.mem_op or ''
                    ev.mem_width = ev.mem_width or 0
                # 仅索引 store，且按字节跨度建立覆盖索引，便于 ldrb/ldrh 反查到此前的宽写入
                if addr is not None and s.startswith('str'):
                    span = max(1, int(ev.mem_width or 1))
                    base = addr & 0xFFFFFFFF
                    for off in range(span):
                        a2 = (base + off) & 0xFFFFFFFF
                        self.store_addr_index.setdefault(a2, []).append(idx)
            # 保证每个地址下的列表有序
            for addr, lst in self.store_addr_index.items():
                lst.sort()
        except Exception:
            # 预计算失败不影响基础功能
            pass

    def find_events_near(self, event_index: int, window: int = 300) -> Tuple[int, List[TraceEvent]]:
        """获取某事件索引附近的一段事件窗口（用于代码视图展示）。"""
        event_index = max(0, min(event_index, len(self.events) - 1))
        start = max(0, event_index - window)
        end = min(len(self.events), event_index + window)
        return start, self.events[start:end]

    def get_branch_function_list(self) -> List[Tuple[int, str]]:
        # 返回按地址排序的“函数候选”列表
        items = sorted(self.branch_targets.items(), key=lambda x: x[0])
        return [(addr, name) for addr, name in items]

    # === 污点分析（前向传播） ===
    def taint_forward(self,
                      start_idx: int,
                      source_regs: Iterable[str] = (),
                      source_mem_addrs: Iterable[int] = (),
                      same_call_only: bool = False,
                      max_steps: int = 120000,
                      enable_memory_taint: bool = True,
                      enable_implicit_flow: bool = False) -> List[int]:
        """从给定起点事件开始，按标准污点传播规则向前分析，返回涉及污点的事件索引（有序、去重）。

        规则（简化动态污点）：
        - 算术/位运算/数据搬运：若读取集中包含污点寄存器，则写入目的寄存器被标记为污点；
        - ldr：若有效内存地址被污点标记，则目标寄存器变为污点；反之若读取寄存器存在污点且影响寻址，不清洗污点；
        - str：若源寄存器是污点，则有效地址对应的内存被标记为污点；
        - 立即数覆盖：若对寄存器的写入仅来自立即数（_is_immediate_write）且不依赖污点输入，则视为清洗该寄存器的污点；
        - 命中：凡读取或写入涉及污点（含传播/覆盖/清洗）之事件，均计入结果。
        """
        n = len(self.events)
        if n == 0:
            return []
        i0 = max(0, min(start_idx, n - 1))
        # 初始污点寄存器集合：包含 ARM64 wN/xN 的互为别名
        tainted_regs: set[str] = set()
        for r in (source_regs or ()):  # type: ignore[assignment]
            for a in self._alias_names((r or '').lower()):
                tainted_regs.add(a)
        tainted_mem = set(int(a) & 0xFFFFFFFF for a in source_mem_addrs)
        hits: List[int] = []
        steps = 0
        base_call = self.events[i0].call_id

        for i in range(i0, n):
            if steps >= max_steps:
                break
            ev = self.events[i]
            if same_call_only and ev.call_id != base_call:
                continue
            steps += 1
            used = False

            # 读取命中（考虑别名）
            for r in ev.reads.keys():
                if r in tainted_regs:
                    used = True
                    break
                for a in self._alias_names(r):
                    if a in tainted_regs:
                        used = True
                        break
                if used:
                    break

            # ldr 命中（从污点内存加载）- 支持字节级检测
            asm = ev.asm.lower()
            eff = None
            if asm.startswith('ldr'):
                eff = self.effective_address(i)
                if eff is not None:
                    # 使用字节级检测：只要访问范围内有任何字节被污染就命中
                    width = self._get_mem_access_width(asm)
                    if self._check_memory_tainted(tainted_mem, eff, width):
                        used = True

            # 写入传播/清洗
            if ev.writes:
                for rd in list(ev.writes.keys()):
                    # 0) 特殊恒等归约：将值置零，独立于输入 -> 清洗污点
                    if self._is_constant_zero_write(ev, rd):
                        for a in self._alias_names(rd):
                            if a in tainted_regs:
                                tainted_regs.discard(a)
                            used = True
                        # 即使 reads 命中污点，此处也不传播（结果恒定为 0）
                        continue
                    propagated = False
                    # 1) 来自污点寄存器的传播
                    for rn in ev.reads.keys():
                        if rn in tainted_regs:
                            propagated = True
                            break
                        for a in self._alias_names(rn):
                            if a in tainted_regs:
                                propagated = True
                                break
                        if propagated:
                            break
                    # 2) ldr 从污点内存传播 - 支持字节级检测
                    if not propagated and asm.startswith('ldr'):
                        if eff is None:
                            eff = self.effective_address(i)
                        if eff is not None:
                            width = self._get_mem_access_width(asm)
                            if self._check_memory_tainted(tainted_mem, eff, width):
                                propagated = True
                    # 3) 特殊指令：位域操作、乘法、单目指令 - 都需要传播污点
                    # 这些指令如果读取寄存器包含污点，则写入也被污染
                    # （上面步骤1已处理，此处无需额外逻辑）
                    
                    if propagated:
                        for a in self._alias_names(rd):
                            if a not in tainted_regs:
                                tainted_regs.add(a)
                        used = True
                    else:
                        # 4) 立即数覆盖清洗（不依赖污点输入）
                        if self._is_immediate_write(ev, rd):
                            for a in self._alias_names(rd):
                                if a in tainted_regs:
                                    tainted_regs.discard(a)
                                used = True
                        # 5) 常量池加载清洗
                        elif self._is_constant_pool_load(i, rd):
                            for a in self._alias_names(rd):
                                if a in tainted_regs:
                                    tainted_regs.discard(a)
                                used = True
                        # 6) 部分位域清洗（bfc指令）
                        # 注意：bfc不完全清洗寄存器，只清零部分位
                        # 保守策略：保留污点但标记为已访问
                        elif self._is_partial_bitfield_clear(ev, rd):
                            if any(a in tainted_regs for a in self._alias_names(rd)):
                                used = True
                        # 7) ARM64: cset/csetm指令清洗（设置0或1常量）
                        elif self._is_conditional_set_op(asm):
                            for a in self._alias_names(rd):
                                if a in tainted_regs:
                                    tainted_regs.discard(a)
                                used = True
                        # 8) ARM64: adrp指令清洗（地址常量）
                        elif self._is_adrp_op(asm):
                            for a in self._alias_names(rd):
                                if a in tainted_regs:
                                    tainted_regs.discard(a)
                                used = True
                        # 9) ARM64: movk指令（部分位修改，保守策略：保留污点）
                        elif self._is_movk_op(asm):
                            # movk只修改16位，其他位保持不变
                            # 如果寄存器已被污染，保持污点状态
                            if any(a in tainted_regs for a in self._alias_names(rd)):
                                used = True  # 标记使用但不改变污点状态

            # store 传播到内存 - 支持字节级污点标记
            if asm.startswith('str'):
                eff2 = self.effective_address(i)
                if eff2 is not None:
                    src_reg = self._parse_store_value_reg(asm)
                    if src_reg and (src_reg in tainted_regs or any(a in tainted_regs for a in self._alias_names(src_reg))):
                        # 标记整个访存范围为污点
                        width = self._get_mem_access_width(asm)
                        self._mark_memory_tainted(tainted_mem, eff2, width)
                        used = True
            
            # === 多寄存器指令处理 ===
            
            # 1. push指令：污点寄存器传播到栈内存
            if asm.startswith('push '):
                reg_list = self._parse_register_list(asm)
                for reg in reg_list:
                    if reg in tainted_regs or any(a in tainted_regs for a in self._alias_names(reg)):
                        # push指令将寄存器写入栈，需要标记相应内存为污点
                        # 注：这里简化处理，实际地址计算需要SP值，此处仅标记污点传播发生
                        used = True
                        # 如果能获取有效地址，也标记内存
                        # push是递减栈操作，每个寄存器占4字节
                        # 实际应用中可能需要复原SP值来精确标记地址
                        
            # 2. pop指令：栈内存传播到寄存器
            elif asm.startswith('pop '):
                reg_list = self._parse_register_list(asm)
                # pop将栈内存加载到寄存器
                # 如果栈内存被污染，传播到目标寄存器
                # 简化处理：如果有任何污点寄存器或内存，保守地假设可能通过栈传播
                if tainted_mem:  # 如果有污点内存（可能包含栈）
                    for reg in reg_list:
                        for a in self._alias_names(reg):
                            if a not in tainted_regs:
                                tainted_regs.add(a)
                        used = True
                        
            # 3. stm/stmia/stmdb等：多寄存器存储
            elif asm.startswith('stm'):
                reg_list = self._parse_register_list(asm)
                for reg in reg_list:
                    if reg in tainted_regs or any(a in tainted_regs for a in self._alias_names(reg)):
                        used = True
                        # 类似store，传播到内存
                        
            # 4. ldm/ldmia/ldmdb等：多寄存器加载
            elif asm.startswith('ldm'):
                reg_list = self._parse_register_list(asm)
                # 如果从污点内存加载，传播到所有目标寄存器
                if tainted_mem:
                    for reg in reg_list:
                        for a in self._alias_names(reg):
                            if a not in tainted_regs:
                                tainted_regs.add(a)
                        used = True
                        
            # 5. strd：双字存储（8字节）
            elif asm.startswith('strd '):
                reg1, reg2 = self._parse_dual_regs(asm)
                if reg1 and reg2:
                    # 检查两个源寄存器是否有污点
                    tainted = False
                    for reg in [reg1, reg2]:
                        if reg in tainted_regs or any(a in tainted_regs for a in self._alias_names(reg)):
                            tainted = True
                            break
                    if tainted:
                        # 获取有效地址并标记8字节范围
                        eff3 = self.effective_address(i)
                        if eff3 is not None:
                            self._mark_memory_tainted(tainted_mem, eff3, 8)
                        used = True
                        
            # 6. ldrd：双字加载（8字节）
            elif asm.startswith('ldrd '):
                reg1, reg2 = self._parse_dual_regs(asm)
                if reg1 and reg2:
                    # 检查内存是否被污染
                    eff4 = self.effective_address(i)
                    if eff4 is not None and self._check_memory_tainted(tainted_mem, eff4, 8):
                        # 传播到两个目标寄存器
                        for reg in [reg1, reg2]:
                            for a in self._alias_names(reg):
                                if a not in tainted_regs:
                                    tainted_regs.add(a)
                        used = True
            
            # === ARM64特殊指令处理 ===
            
            # 1. csel/csinc/csinv/csneg指令：条件选择，两个源操作数都可能传播污点
            if self._is_conditional_select_op(asm):
                rd, rn, rm = self._parse_csel_operands(asm)
                if rd and rn and rm:
                    # 检查rn或rm是否被污染
                    tainted = False
                    for reg in [rn, rm]:
                        if reg in tainted_regs or any(a in tainted_regs for a in self._alias_names(reg)):
                            tainted = True
                            break
                    if tainted:
                        # 传播到rd
                        for a in self._alias_names(rd):
                            if a not in tainted_regs:
                                tainted_regs.add(a)
                        used = True
            
            # 2. madd/msub/smaddl等指令：4个操作数，任一被污染则传播
            elif self._is_madd_op(asm):
                rd, rn, rm, ra = self._parse_madd_operands(asm)
                if rd and rn and rm and ra:
                    # 检查rn, rm, ra是否被污染
                    tainted = False
                    for reg in [rn, rm, ra]:
                        if reg in tainted_regs or any(a in tainted_regs for a in self._alias_names(reg)):
                            tainted = True
                            break
                    if tainted:
                        # 传播到rd
                        for a in self._alias_names(rd):
                            if a not in tainted_regs:
                                tainted_regs.add(a)
                        used = True

            if used:
                hits.append(i)

        # 去重并保持顺序
        seen = set()
        ordered = []
        for k in hits:
            if k in seen:
                continue
            seen.add(k)
            ordered.append(k)
        return ordered

    # === 寄存器别名（ARM64）与读写获取 ===
    def _alias_names(self, name: str) -> List[str]:
        """返回寄存器名称的别名集合（含自身）。
        - ARM64: wN/xN 互为别名；其它名称原样返回。
        - 使用缓存优化性能（热路径函数）
        """
        # 快速缓存查找
        if name in self._alias_cache:
            return self._alias_cache[name]
        
        try:
            n = (name or '').strip().lower()
            if n.startswith('x') and n[1:].isdigit():
                result = [n, f"w{n[1:]}"]
            elif n.startswith('w') and n[1:].isdigit():
                result = [n, f"x{n[1:]}"]
            else:
                result = [n]
            
            # 缓存结果（限制缓存大小避免内存泄漏）
            if len(self._alias_cache) < 256:
                self._alias_cache[name] = result
            return result
        except Exception:
            return [name]

    def _has_write(self, ev: TraceEvent, reg: str) -> bool:
        r = (reg or '').lower()
        if r in ev.writes:
            return True
        for a in self._alias_names(r):
            if a in ev.writes:
                return True
        return False

    def _get_write_value(self, ev: TraceEvent, reg: str) -> Optional[int]:
        r = (reg or '').lower()
        v = ev.writes.get(r)
        if v is not None:
            return v
        for a in self._alias_names(r):
            if a in ev.writes:
                return ev.writes.get(a)
        return None

    def _get_read_value(self, ev: TraceEvent, reg: str) -> Optional[int]:
        r = (reg or '').lower()
        v = ev.reads.get(r)
        if v is not None:
            return v
        for a in self._alias_names(r):
            if a in ev.reads:
                return ev.reads.get(a)
        return None

    def advanced_taint_analysis(self,
                                start_idx: int,
                                source_regs: Iterable[str] = (),
                                source_mem_addrs: Iterable[int] = (),
                                target_regs: Iterable[str] = (),
                                target_mem_addrs: Iterable[int] = (),
                                same_call_only: bool = False,
                                max_steps: int = 200000,
                                enable_memory_taint: bool = True,
                                enable_implicit_flow: bool = False,
                                track_constants: bool = True) -> Dict:
        """高级污点分析：提供更详细的分析结果和统计信息。
        
        Args:
            start_idx: 起始事件索引
            source_regs: 源污点寄存器
            source_mem_addrs: 源污点内存地址
            target_regs: 目标寄存器（如果指定，会特别标记何时污点到达目标）
            target_mem_addrs: 目标内存地址
            same_call_only: 是否仅在同一调用内分析
            max_steps: 最大分析步数
            enable_memory_taint: 是否启用内存污点传播
            enable_implicit_flow: 是否启用隐式控制流污点
            track_constants: 是否跟踪常量传播
            
        Returns:
            Dict包含:
            - hits: 污点命中的事件索引列表
            - taint_path: 详细的污点传播路径
            - statistics: 分析统计信息
            - target_reached: 是否到达目标寄存器/内存
        """
        n = len(self.events)
        if n == 0:
            return {"hits": [], "taint_path": [], "statistics": {}, "target_reached": False}
            
        i0 = max(0, min(start_idx, n - 1))
        
        # 初始化污点状态
        tainted_regs: set[str] = set()
        for r in (source_regs or ()):
            for a in self._alias_names((r or '').lower()):
                tainted_regs.add(a)
                
        tainted_mem = set(int(a) & 0xFFFFFFFF for a in source_mem_addrs) if enable_memory_taint else set()
        
        # 目标检测
        target_reg_set = set()
        for r in (target_regs or ()):
            for a in self._alias_names((r or '').lower()):
                target_reg_set.add(a)
        target_mem_set = set(int(a) & 0xFFFFFFFF for a in target_mem_addrs)
        
        # 结果收集
        hits: List[int] = []
        taint_path: List[Dict] = []
        statistics = {
            "total_steps": 0,
            "register_propagations": 0,
            "memory_propagations": 0,
            "cleanups": 0,
            "target_hits": 0
        }
        
        base_call = self.events[i0].call_id
        target_reached = False
        steps = 0
        
        for i in range(i0, n):
            if steps >= max_steps:
                break
                
            ev = self.events[i]
            if same_call_only and ev.call_id != base_call:
                continue
                
            steps += 1
            statistics["total_steps"] += 1
            used = False
            # 性能优化：只在需要时复制污点状态（减少拷贝开销）
            step_info = {
                "event_idx": i,
                "pc": hex(ev.pc),
                "asm": ev.asm,
                "tainted_regs_before": None,  # 延迟拷贝
                "tainted_mem_before": None,   # 延迟拷贝
                "propagation_type": None,
                "target_hit": False
            }
            
            # 检查读取命中
            read_hit_regs = []
            for r in ev.reads.keys():
                if r in tainted_regs or any(a in tainted_regs for a in self._alias_names(r)):
                    read_hit_regs.append(r)
                    used = True
                    
            # 检查内存读取命中（ldr指令）- 支持字节级检测
            asm = ev.asm.lower()
            eff = None
            mem_hit = False
            if enable_memory_taint and asm.startswith('ldr'):
                eff = self.effective_address(i)
                if eff is not None:
                    width = self._get_mem_access_width(asm)
                    if self._check_memory_tainted(tainted_mem, eff, width):
                        mem_hit = True
                        used = True
                    
            # 处理写入传播
            if ev.writes:
                for rd in list(ev.writes.keys()):
                    # 检查是否为常量零写入（清洗）
                    if self._is_constant_zero_write(ev, rd):
                        for a in self._alias_names(rd):
                            if a in tainted_regs:
                                tainted_regs.discard(a)
                                statistics["cleanups"] += 1
                                step_info["propagation_type"] = "cleanup_zero"
                        used = True
                        continue
                        
                    propagated = False
                    
                    # 寄存器到寄存器传播
                    for rn in ev.reads.keys():
                        if rn in tainted_regs or any(a in tainted_regs for a in self._alias_names(rn)):
                            propagated = True
                            break
                            
                    # 内存到寄存器传播（ldr）- 支持字节级检测
                    if not propagated and enable_memory_taint and asm.startswith('ldr'):
                        if eff is None:
                            eff = self.effective_address(i)
                        if eff is not None:
                            width = self._get_mem_access_width(asm)
                            if self._check_memory_tainted(tainted_mem, eff, width):
                                propagated = True
                                step_info["propagation_type"] = "mem_to_reg"
                                statistics["memory_propagations"] += 1
                    
                    # 特殊指令标注（用于统计和调试）
                    if propagated and step_info["propagation_type"] is None:
                        if self._is_bitfield_op(asm):
                            step_info["propagation_type"] = "bitfield_op"
                        elif self._is_multiply_op(asm):
                            step_info["propagation_type"] = "multiply_op"
                        elif self._is_unary_op(asm):
                            step_info["propagation_type"] = "unary_op"
                        elif self._is_extend_op(asm):
                            step_info["propagation_type"] = "extend_op"
                        elif self._is_bitwise_not_op(asm):
                            step_info["propagation_type"] = "bitwise_not_op"
                        else:
                            step_info["propagation_type"] = "reg_to_reg"
                            
                    if propagated:
                        for a in self._alias_names(rd):
                            if a not in tainted_regs:
                                tainted_regs.add(a)
                                if step_info["propagation_type"] == "reg_to_reg":
                                    statistics["register_propagations"] += 1
                        used = True
                        
                        # 检查是否到达目标寄存器
                        if any(a in target_reg_set for a in self._alias_names(rd)):
                            target_reached = True
                            step_info["target_hit"] = True
                            statistics["target_hits"] += 1
                    else:
                        # 立即数覆盖清洗
                        if track_constants and self._is_immediate_write(ev, rd):
                            for a in self._alias_names(rd):
                                if a in tainted_regs:
                                    tainted_regs.discard(a)
                                    statistics["cleanups"] += 1
                                    step_info["propagation_type"] = "cleanup_immediate"
                            used = True
                        # 常量池加载清洗
                        elif track_constants and self._is_constant_pool_load(i, rd):
                            for a in self._alias_names(rd):
                                if a in tainted_regs:
                                    tainted_regs.discard(a)
                                    statistics["cleanups"] += 1
                                    step_info["propagation_type"] = "cleanup_const_pool"
                            used = True
                        # 部分位域清洗（bfc指令）
                        elif self._is_partial_bitfield_clear(ev, rd):
                            if any(a in tainted_regs for a in self._alias_names(rd)):
                                step_info["propagation_type"] = "partial_bitfield_clear"
                                used = True
                        # ARM64: cset/csetm指令清洗
                        elif track_constants and self._is_conditional_set_op(asm):
                            for a in self._alias_names(rd):
                                if a in tainted_regs:
                                    tainted_regs.discard(a)
                                    statistics["cleanups"] += 1
                                    step_info["propagation_type"] = "cset_cleanup"
                            used = True
                        # ARM64: adrp指令清洗
                        elif track_constants and self._is_adrp_op(asm):
                            for a in self._alias_names(rd):
                                if a in tainted_regs:
                                    tainted_regs.discard(a)
                                    statistics["cleanups"] += 1
                                    step_info["propagation_type"] = "adrp_cleanup"
                            used = True
                        # ARM64: movk指令（部分位修改，保留污点）
                        elif self._is_movk_op(asm):
                            if any(a in tainted_regs for a in self._alias_names(rd)):
                                step_info["propagation_type"] = "movk_partial_modify"
                                used = True
                            
            # 处理存储指令（寄存器到内存传播）- 支持字节级污点标记
            if enable_memory_taint and asm.startswith('str'):
                src_reg = self._parse_store_value_reg(asm)
                if src_reg and (src_reg in tainted_regs or any(a in tainted_regs for a in self._alias_names(src_reg))):
                    eff2 = self.effective_address(i)
                    if eff2 is not None:
                        width = self._get_mem_access_width(asm)
                        self._mark_memory_tainted(tainted_mem, eff2, width)
                        step_info["propagation_type"] = "reg_to_mem"
                        statistics["memory_propagations"] += 1
                        used = True
                        
                        # 检查是否到达目标内存（检查整个访存范围）
                        base = eff2 & 0xFFFFFFFF
                        for offset in range(width):
                            if ((base + offset) & 0xFFFFFFFF) in target_mem_set:
                                target_reached = True
                                step_info["target_hit"] = True
                                statistics["target_hits"] += 1
                                break
            
            # === 多寄存器指令处理（advanced版本） ===
            
            # push指令
            if enable_memory_taint and asm.startswith('push '):
                reg_list = self._parse_register_list(asm)
                has_taint = False
                for reg in reg_list:
                    if reg in tainted_regs or any(a in tainted_regs for a in self._alias_names(reg)):
                        has_taint = True
                        break
                if has_taint:
                    step_info["propagation_type"] = "push_multi_reg"
                    statistics["memory_propagations"] += 1
                    used = True
                    
            # pop指令
            elif asm.startswith('pop '):
                reg_list = self._parse_register_list(asm)
                if enable_memory_taint and tainted_mem:
                    for reg in reg_list:
                        for a in self._alias_names(reg):
                            if a not in tainted_regs:
                                tainted_regs.add(a)
                        # 检查目标寄存器
                        if any(a in target_reg_set for a in self._alias_names(reg)):
                            target_reached = True
                            step_info["target_hit"] = True
                            statistics["target_hits"] += 1
                    step_info["propagation_type"] = "pop_multi_reg"
                    statistics["memory_propagations"] += 1
                    used = True
                    
            # stm多寄存器存储
            elif enable_memory_taint and asm.startswith('stm'):
                reg_list = self._parse_register_list(asm)
                has_taint = False
                for reg in reg_list:
                    if reg in tainted_regs or any(a in tainted_regs for a in self._alias_names(reg)):
                        has_taint = True
                        break
                if has_taint:
                    step_info["propagation_type"] = "stm_multi_reg"
                    statistics["memory_propagations"] += 1
                    used = True
                    
            # ldm多寄存器加载
            elif asm.startswith('ldm'):
                reg_list = self._parse_register_list(asm)
                if enable_memory_taint and tainted_mem:
                    for reg in reg_list:
                        for a in self._alias_names(reg):
                            if a not in tainted_regs:
                                tainted_regs.add(a)
                        # 检查目标寄存器
                        if any(a in target_reg_set for a in self._alias_names(reg)):
                            target_reached = True
                            step_info["target_hit"] = True
                            statistics["target_hits"] += 1
                    step_info["propagation_type"] = "ldm_multi_reg"
                    statistics["memory_propagations"] += 1
                    statistics["register_propagations"] += len(reg_list)
                    used = True
                    
            # strd双字存储
            elif enable_memory_taint and asm.startswith('strd '):
                reg1, reg2 = self._parse_dual_regs(asm)
                if reg1 and reg2:
                    has_taint = False
                    for reg in [reg1, reg2]:
                        if reg in tainted_regs or any(a in tainted_regs for a in self._alias_names(reg)):
                            has_taint = True
                            break
                    if has_taint:
                        eff3 = self.effective_address(i)
                        if eff3 is not None:
                            self._mark_memory_tainted(tainted_mem, eff3, 8)
                            step_info["propagation_type"] = "strd_dual_reg"
                            statistics["memory_propagations"] += 1
                            used = True
                            # 检查目标内存
                            base = eff3 & 0xFFFFFFFF
                            for offset in range(8):
                                if ((base + offset) & 0xFFFFFFFF) in target_mem_set:
                                    target_reached = True
                                    step_info["target_hit"] = True
                                    statistics["target_hits"] += 1
                                    break
                    
            # ldrd双字加载
            elif asm.startswith('ldrd '):
                reg1, reg2 = self._parse_dual_regs(asm)
                if reg1 and reg2:
                    eff4 = self.effective_address(i)
                    if enable_memory_taint and eff4 is not None and self._check_memory_tainted(tainted_mem, eff4, 8):
                        for reg in [reg1, reg2]:
                            for a in self._alias_names(reg):
                                if a not in tainted_regs:
                                    tainted_regs.add(a)
                            # 检查目标寄存器
                            if any(a in target_reg_set for a in self._alias_names(reg)):
                                target_reached = True
                                step_info["target_hit"] = True
                                statistics["target_hits"] += 1
                        step_info["propagation_type"] = "ldrd_dual_reg"
                        statistics["memory_propagations"] += 1
                        statistics["register_propagations"] += 2
                        used = True
            
            # === ARM64特殊指令处理（advanced版本） ===
            
            # 1. csel/csinc/csinv/csneg指令：条件选择
            if self._is_conditional_select_op(asm):
                rd, rn, rm = self._parse_csel_operands(asm)
                if rd and rn and rm:
                    tainted = False
                    for reg in [rn, rm]:
                        if reg in tainted_regs or any(a in tainted_regs for a in self._alias_names(reg)):
                            tainted = True
                            break
                    if tainted:
                        for a in self._alias_names(rd):
                            if a not in tainted_regs:
                                tainted_regs.add(a)
                        step_info["propagation_type"] = "csel_conditional"
                        statistics["register_propagations"] += 1
                        used = True
                        # 检查目标寄存器
                        if any(a in target_reg_set for a in self._alias_names(rd)):
                            target_reached = True
                            step_info["target_hit"] = True
                            statistics["target_hits"] += 1
            
            # 2. cset/csetm指令：条件设置常量（清洗）
            elif self._is_conditional_set_op(asm):
                # cset在writes中已处理，此处仅统计
                for rd in ev.writes.keys():
                    for a in self._alias_names(rd):
                        if a in tainted_regs:
                            tainted_regs.discard(a)
                            step_info["propagation_type"] = "cset_cleanup"
                            statistics["cleanups"] += 1
                            used = True
            
            # 3. madd/msub/smaddl等指令：4操作数乘加
            elif self._is_madd_op(asm):
                rd, rn, rm, ra = self._parse_madd_operands(asm)
                if rd and rn and rm and ra:
                    tainted = False
                    for reg in [rn, rm, ra]:
                        if reg in tainted_regs or any(a in tainted_regs for a in self._alias_names(reg)):
                            tainted = True
                            break
                    if tainted:
                        for a in self._alias_names(rd):
                            if a not in tainted_regs:
                                tainted_regs.add(a)
                        step_info["propagation_type"] = "madd_multiply_add"
                        statistics["register_propagations"] += 1
                        used = True
                        # 检查目标寄存器
                        if any(a in target_reg_set for a in self._alias_names(rd)):
                            target_reached = True
                            step_info["target_hit"] = True
                            statistics["target_hits"] += 1
            
            # 4. movk指令：部分位修改（保留污点）
            elif self._is_movk_op(asm):
                for rd in ev.writes.keys():
                    if any(a in tainted_regs for a in self._alias_names(rd)):
                        step_info["propagation_type"] = "movk_partial_modify"
                        used = True
            
            # 5. adrp指令：地址常量（清洗）
            elif self._is_adrp_op(asm):
                for rd in ev.writes.keys():
                    for a in self._alias_names(rd):
                        if a in tainted_regs:
                            tainted_regs.discard(a)
                            step_info["propagation_type"] = "adrp_cleanup"
                            statistics["cleanups"] += 1
                            used = True
                            
            if used:
                hits.append(i)
                # 只在实际使用时才复制状态信息（性能优化）
                if step_info["tainted_regs_before"] is None:
                    step_info["tainted_regs_before"] = set()  # 已经变化，用空集代替
                if step_info["tainted_mem_before"] is None:
                    step_info["tainted_mem_before"] = set()
                step_info["tainted_regs_after"] = tainted_regs.copy()
                step_info["tainted_mem_after"] = tainted_mem.copy()
                taint_path.append(step_info)
                
        return {
            "hits": hits,
            "taint_path": taint_path,
            "statistics": statistics,
            "target_reached": target_reached,
            "final_tainted_regs": list(tainted_regs),
            "final_tainted_mem": list(tainted_mem)
        }

    def find_value_candidates(self, reg: str, value: int) -> List[Tuple[int, 'TraceEvent']]:
        """查找所有匹配指定寄存器和值的事件候选。
        
        使用倒排索引快速定位，返回所有匹配的事件及其索引。
        
        Args:
            reg: 寄存器名（如 'r1', 'x0'）
            value: 目标值（32位）
            
        Returns:
            [(idx, ev), ...] 按原始行号排序的候选列表
        """
        reg = reg.lower()
        value_u32 = value & 0xFFFFFFFF
        candidates = []
        seen = set()
        
        # 从读索引和写索引中查找
        for idx in (self.reg_read_index.get(reg, []) or []):
            if idx in seen:
                continue
            ev = self.events[idx]
            try:
                b = self._get_read_value(ev, reg)
            except Exception:
                b = ev.reads.get(reg)
            if b is not None and (b & 0xFFFFFFFF) == value_u32:
                candidates.append((idx, ev))
                seen.add(idx)
        
        for idx in (self.reg_write_index.get(reg, []) or []):
            if idx in seen:
                continue
            ev = self.events[idx]
            try:
                a = self._get_write_value(ev, reg)
            except Exception:
                a = ev.writes.get(reg)
            if a is not None and (a & 0xFFFFFFFF) == value_u32:
                candidates.append((idx, ev))
                seen.add(idx)
        
        # 按索引排序（即按执行顺序）
        candidates.sort(key=lambda x: x[0])
        return candidates

    def _check_backward_termination(self, idx: int, reg: str) -> Optional[str]:
        """检查是否到达反向追踪的终止条件。
        
        Args:
            idx: 事件索引
            reg: 寄存器名
            
        Returns:
            终止原因标签，如 "源头·立即数" / "源头·参数" / None（继续追踪）
        """
        if idx < 0 or idx >= len(self.events):
            return None
        
        ev = self.events[idx]
        asm = ev.asm.lower()
        
        # 1. 立即数写入
        if reg in ev.writes and self._is_immediate_write(ev, reg):
            # 特殊：eor rd, rd, rd (清零)
            if 'eor' in asm:
                parts = asm.split(',')
                if len(parts) >= 3:
                    r1, r2 = parts[1].strip(), parts[2].strip()
                    if r1 == r2 == reg:
                        return "源头·立即数(清零)"
            return "源头·立即数"
        
        # 2. 常量池加载
        if reg in ev.writes and self._is_constant_pool_load(idx, reg):
            return "源头·常量池"
        
        # 3. 恒零写入（另一种立即数）
        if reg in ev.writes and self._is_constant_zero_write(ev, reg):
            return "源头·立即数(清零)"
        
        # 4. 函数参数（启发式：检测函数入口）
        # ARM32: r0-r3, ARM64: x0-x7/w0-w7
        param_regs_32 = {'r0', 'r1', 'r2', 'r3'}
        param_regs_64 = {f'x{i}' for i in range(8)} | {f'w{i}' for i in range(8)}
        if reg in param_regs_32 or reg in param_regs_64:
            # 简单启发：若该寄存器在此之前很久没写入（>50条指令），可能是参数
            if idx > 50:
                # 向前查找最近的写入
                found_write = False
                for j in range(idx - 1, max(0, idx - 50), -1):
                    if reg in self.events[j].writes:
                        for a in self._alias_names(reg):
                            if a in self.events[j].writes:
                                found_write = True
                                break
                        if found_write:
                            break
                if not found_write:
                    return "源头·参数"
        
        # 5. 系统调用返回（svc 后的 r0/x0）
        if reg in ('r0', 'x0', 'w0') and idx > 0:
            prev_asm = self.events[idx - 1].asm.lower()
            if 'svc' in prev_asm:
                return "源头·系统调用"
        
        # 6. 栈变量加载（ldr from sp，无前序写入）
        if asm.startswith('ldr') and reg in ev.writes and '[sp' in asm:
            # 粗略检测：向前查找是否有对该栈位置的 str
            # 简化：若最近100条指令内无 str 到相同偏移，视为外部栈变量
            return "源头·栈变量"
        
        # 7. 全局变量加载（ldr from 非栈地址，无前序写入）
        # 这个需要有效地址计算，暂时跳过或简化
        
        return None

    def taint_backward(self,
                      start_idx: int,
                      target_reg: str,
                      target_value: Optional[int] = None,
                      same_call_only: bool = False,
                      max_steps: int = 100000,
                      enable_memory_taint: bool = True) -> List[int]:
        """反向污点分析：从目标事件向前追踪值的来源。
        
        算法核心：
        1. 从 start_idx 开始向前遍历（行号递减）
        2. 反向传播规则：若指令**写入**污点寄存器，则其**读取**的寄存器变为污点
        3. 遇到终止条件（立即数、常量池、函数参数等）时停止该路径
        4. 返回所有涉及污点的事件索引，按行号递减排序
        
        Args:
            start_idx: 起始事件索引
            target_reg: 目标寄存器
            target_value: 目标值（可选，用于验证）
            same_call_only: 是否仅在同一调用内分析
            max_steps: 最大分析步数
            enable_memory_taint: 是否启用内存污点追踪
            
        Returns:
            命中的事件索引列表（降序：最早的来源在前）
        """
        n = len(self.events)
        if n == 0:
            return []
        
        start_idx = max(0, min(start_idx, n - 1))
        target_reg = target_reg.lower()
        
        # 初始化污点状态：目标寄存器及其别名
        tainted_regs: set[str] = set()
        for a in self._alias_names(target_reg):
            tainted_regs.add(a)
        
        tainted_mem: set[int] = set()  # 污点内存地址
        hits: List[int] = []  # 命中的事件索引
        terminated_regs: set[str] = set()  # 已到达终止条件的寄存器（不再追踪）
        
        steps = 0
        base_call = self.events[start_idx].call_id
        
        # 反向遍历：从 start_idx 向前到 0
        for i in range(start_idx, -1, -1):
            if steps >= max_steps:
                break
            
            ev = self.events[i]
            
            # 同调用限制
            if same_call_only and ev.call_id != base_call:
                continue
            
            steps += 1
            used = False
            asm = ev.asm.lower()
            
            # === 反向传播核心逻辑 ===
            
            # 1. 处理写入：若写入污点寄存器，则读取的寄存器变为污点
            if ev.writes:
                for rd in list(ev.writes.keys()):
                    # 检查是否写入了污点寄存器
                    is_tainted_write = False
                    for a in self._alias_names(rd):
                        if a in tainted_regs and a not in terminated_regs:
                            is_tainted_write = True
                            break
                    
                    if is_tainted_write:
                        used = True
                        
                        # 检查终止条件
                        term_reason = self._check_backward_termination(i, rd)
                        if term_reason:
                            # 到达源头，标记该寄存器为终止
                            for a in self._alias_names(rd):
                                terminated_regs.add(a)
                            # 记录命中但不继续传播
                            continue
                        
                        # 反向传播：将读取的寄存器标记为污点
                        for rn in ev.reads.keys():
                            for a in self._alias_names(rn):
                                if a not in tainted_regs:
                                    tainted_regs.add(a)
                        
                        # 特殊：ldr 指令，地址寄存器和内存都变为污点
                        if asm.startswith('ldr') and enable_memory_taint:
                            eff = self.effective_address(i)
                            if eff is not None:
                                width = self._get_mem_access_width(asm)
                                self._mark_memory_tainted(tainted_mem, eff, width)
            
            # 2. 处理读取：若读取污点寄存器，记录命中
            for rn in ev.reads.keys():
                read_tainted = False
                for a in self._alias_names(rn):
                    if a in tainted_regs and a not in terminated_regs:
                        read_tainted = True
                        break
                if read_tainted:
                    used = True
                    break
            
            # 3. 处理内存：str 到污点内存 → 源寄存器变污点
            if enable_memory_taint and asm.startswith('str'):
                eff = self.effective_address(i)
                if eff is not None:
                    width = self._get_mem_access_width(asm)
                    if self._check_memory_tainted(tainted_mem, eff, width):
                        used = True
                        # 将 str 的源寄存器标记为污点
                        src_reg = self._parse_store_value_reg(asm)
                        if src_reg:
                            for a in self._alias_names(src_reg):
                                if a not in tainted_regs:
                                    tainted_regs.add(a)
                        # 地址寄存器也可能是污点来源
                        for rn in ev.reads.keys():
                            for a in self._alias_names(rn):
                                if a not in tainted_regs:
                                    tainted_regs.add(a)
            
            # 4. ldr 从污点内存 → 继续追踪（已在写入处理中覆盖）
            
            if used:
                hits.append(i)
        
        # 返回降序结果（最早的来源在前）
        hits.reverse()
        return hits


