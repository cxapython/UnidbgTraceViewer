from __future__ import annotations

"""
解码后端统一入口：优先 pypcode，其次 angr/pyvex，再次 miasm。
输入：pc、机器码（bytes）、架构/模式提示
输出：结构化的单条指令信息：
  - mnemonic
  - regs_read / regs_write: set[str]
  - mem_ops: list[{op:'load'|'store', width:int, base:str|None, index:str|None, shift:int|None, imm:int|None}]
  - is_call / is_ret / is_branch

兼容 Python 3.8。
"""

from dataclasses import dataclass, field
from typing import List, Optional, Set, Dict, Tuple


@dataclass
class MemOp:
    op: str                # 'load' | 'store'
    width: int             # 字节宽度 1/2/4/8
    base: Optional[str] = None
    index: Optional[str] = None
    shift: Optional[int] = None
    imm: Optional[int] = None


@dataclass
class DecodedInsn:
    mnemonic: str
    regs_read: Set[str] = field(default_factory=set)
    regs_write: Set[str] = field(default_factory=set)
    mem_ops: List[MemOp] = field(default_factory=list)
    is_call: bool = False
    is_ret: bool = False
    is_branch: bool = False


class DecoderBackend:
    def decode(self, pc: int, enc: bytes, arch: str, thumb: bool) -> Optional[DecodedInsn]:
        raise NotImplementedError


class PypcodeBackend(DecoderBackend):
    def __init__(self) -> None:
        try:
            import pypcode  # type: ignore
            self._pc = pypcode
        except Exception:
            self._pc = None

    def available(self) -> bool:
        return self._pc is not None

    def _lang(self, arch: str, thumb: bool):
        pc = self._pc
        if pc is None:
            return None
        if arch == 'arm64':
            name = 'AARCH64:LE:64:Apple'  # 兼容小端 64
        else:
            name = 'ARM:LE:32:v8'
        try:
            ctx = pc.Context(pc.Arch(name))
            return ctx
        except Exception:
            return None

    def decode(self, pc_addr: int, enc: bytes, arch: str, thumb: bool) -> Optional[DecodedInsn]:
        if not self.available():
            return None
        ctx = self._lang(arch, thumb)
        if ctx is None:
            return None
        try:
            insn = ctx.decode_instruction(enc, pc_addr)
            pcode_ops = insn.ops
        except Exception:
            return None
        mn = (getattr(insn, 'mnemonic', '') or '').lower()
        out = DecodedInsn(mnemonic=mn)
        # 粗提 regs / mem based on pcode vars
        try:
            for op in pcode_ops:
                opname = op.opcode.name.lower()
                vars_ = [v for v in op.inputs]
                outvar = op.output
                # 简单分类：读写寄存器
                for v in vars_:
                    if getattr(v.space, 'name', '').startswith('register'):
                        out.regs_read.add(ctx.arch.get_register_name(v.offset, v.size).lower())
                if outvar is not None and getattr(outvar.space, 'name', '').startswith('register'):
                    out.regs_write.add(ctx.arch.get_register_name(outvar.offset, outvar.size).lower())
                # 识别内存 load/store
                if 'load' in opname:
                    out.mem_ops.append(MemOp('load', width=op.output.size if op.output else 4))
                elif 'store' in opname:
                    out.mem_ops.append(MemOp('store', width=vars_[2].size if len(vars_) >= 3 else 4))
        except Exception:
            pass
        # 粗识别 call/ret/branch
        out.is_call = mn.startswith('bl') or mn.startswith('blr') or mn == 'call'
        out.is_ret = ('ret' == mn) or ('bx lr' in mn) or (mn.startswith('mov') and 'pc' in mn and 'lr' in mn)
        out.is_branch = mn.startswith('b') and not out.is_call
        return out


class PyVEXBackend(DecoderBackend):
    def __init__(self) -> None:
        try:
            import pyvex  # type: ignore
            self._vx = pyvex
        except Exception:
            self._vx = None

    def available(self) -> bool:
        return self._vx is not None

    def decode(self, pc: int, enc: bytes, arch: str, thumb: bool) -> Optional[DecodedInsn]:
        if not self.available():
            return None
        try:
            irsb = self._vx.IRSB(enc, pc, arch='ARM64' if arch == 'arm64' else 'ARM')
        except Exception:
            return None
        out = DecodedInsn(mnemonic='')
        try:
            for stmt in irsb.statements:
                k = stmt.tag
                if k == 'Ist_WrTmp' and hasattr(stmt.data, 'tag') and stmt.data.tag == 'Iex_Load':
                    out.mem_ops.append(MemOp('load', width=int(stmt.data.result_size/8)))
                elif k == 'Ist_Store':
                    out.mem_ops.append(MemOp('store', width=int(stmt.data.result_size/8)))
        except Exception:
            pass
        return out


class MiasmBackend(DecoderBackend):
    def __init__(self) -> None:
        try:
            from miasm.analysis.machine import Machine  # type: ignore
            self._Machine = Machine
        except Exception:
            self._Machine = None

    def available(self) -> bool:
        return self._Machine is not None

    def decode(self, pc: int, enc: bytes, arch: str, thumb: bool) -> Optional[DecodedInsn]:
        if not self.available():
            return None
        try:
            mach = self._Machine('aarch64' if arch == 'arm64' else 'armv7')
            asmc = mach.dis_engine().dis(enc, pc)
        except Exception:
            return None
        if not asmc:
            return None
        ins = asmc[0]
        mn = getattr(ins, 'name', '').lower()
        out = DecodedInsn(mnemonic=mn)
        # 只做最小信息，详细读写集留给 pypcode
        return out


class CompositeDecoder:
    def __init__(self) -> None:
        self._pyp = PypcodeBackend()
        self._vx = PyVEXBackend()
        self._mia = MiasmBackend()
        self._cache: Dict[Tuple[int, bytes, str, bool], Optional[DecodedInsn]] = {}

    def decode(self, pc: int, enc: bytes, arch: str, thumb: bool) -> Optional[DecodedInsn]:
        key = (pc, enc, arch, thumb)
        if key in self._cache:
            return self._cache[key]
        res = None
        for b in (self._pyp, self._vx, self._mia):
            try:
                if hasattr(b, 'available') and not b.available():
                    continue
                res = b.decode(pc, enc, arch, thumb)
                if res is not None:
                    break
            except Exception:
                continue
        self._cache[key] = res
        # LRU 裁剪
        if len(self._cache) > 16384:
            try:
                self._cache.pop(next(iter(self._cache)))
            except Exception:
                self._cache.clear()
        return res


decoder_singleton: Optional[CompositeDecoder] = None


def get_decoder() -> CompositeDecoder:
    global decoder_singleton
    if decoder_singleton is None:
        decoder_singleton = CompositeDecoder()
    return decoder_singleton


