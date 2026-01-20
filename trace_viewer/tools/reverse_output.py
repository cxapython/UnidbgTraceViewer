#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
从“输出内存 buffer”的最终结果逆推：自动定位每个字节的最后写入点，并尝试识别常见模式（如 eor -> mvn -> strb）。

用途（针对你现在的目标）：
- 已知 x-gorgon 输出落在某段连续内存（例如 0x122802a0..0x122802b9），希望只靠 trace 反推这段算法。
- 该脚本会输出：每个字节写入的 trace 行、PC、指令、写入寄存器值、以及（若识别到）对应的公式。

示例：
python -m trace_viewer.tools.reverse_output \
  --trace /path/to/fanqie_trace.txt \
  --addr 0x122802a0 --len 26
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import logging

from trace_viewer.trace_parser import TraceParser, TraceEvent


@dataclass
class ByteWrite:
    offset: int
    addr: int
    writer_idx: int
    ev: TraceEvent
    src_reg: Optional[str]
    src_val_before: Optional[int]
    byte_value: Optional[int]
    pattern: str = ""


def _parse_int(s: str) -> int:
    s = (s or "").strip().lower()
    if s.startswith("0x"):
        return int(s, 16)
    # 允许用户直接输入十六进制（无 0x）或十进制
    try:
        return int(s, 16)
    except ValueError:
        return int(s, 10)


def _get_reg_before(parser: TraceParser, idx: int, reg: str) -> Optional[int]:
    reg = (reg or "").lower()
    if not reg:
        return None
    ev = parser.events[idx]
    v = ev.reads.get(reg)
    if v is not None:
        return v
    # 兜底：用复原的 idx-1 状态作为“执行前”
    try:
        if idx <= 0:
            regs = parser.reconstruct_regs_at(0)
        else:
            regs = parser.reconstruct_regs_at(idx - 1)
        return regs.get(reg)
    except Exception:
        return None


def _parse_store_src_reg(parser: TraceParser, asm: str) -> Optional[str]:
    asm_low = (asm or "").strip().lower()
    try:
        # 复用 parser 内置的 store 源寄存器解析（更鲁棒）
        if hasattr(parser, "_parse_store_value_reg"):
            r = parser._parse_store_value_reg(asm_low)  # type: ignore[attr-defined]
            if r:
                return str(r).lower()
    except Exception:
        pass
    # 兜底：匹配常见 str/strb/strh 形式：strb r1, [r0]
    # 注意：这里不处理多寄存器 stp/push 等复杂形式
    import re
    m = re.match(r"^(strb|strh|str)\s+([rxw]\d{1,2}|sp|lr|fp|ip|sb|sl)\s*,\s*\[", asm_low)
    if m:
        return m.group(2).lower()
    return None


def _find_prev_write_of_reg(parser: TraceParser, reg: str, from_idx_exclusive: int, max_back: int = 4000) -> Optional[int]:
    reg = (reg or "").lower()
    if not reg:
        return None
    steps = 0
    for j in range(from_idx_exclusive - 1, -1, -1):
        if steps >= max_back:
            return None
        steps += 1
        ev = parser.events[j]
        if reg in ev.writes:
            return j
        # 别名（w8/x8 等）
        try:
            for a in parser._alias_names(reg):  # type: ignore[attr-defined]
                if a in ev.writes:
                    return j
        except Exception:
            pass
    return None


def _guess_pattern_eor_mvn_strb(parser: TraceParser, writer_idx: int, src_reg: str) -> str:
    """
    尝试识别：
      eor  src_reg, imm/reg -> mvn src_reg, src_reg -> strb src_reg, [addr]
    输出一个可复现的简短公式描述。
    """
    src_reg = (src_reg or "").lower()
    if not src_reg:
        return ""

    # 先在较大窗口内找最近一次 mvn 写 src_reg（中间可能会有 ldr/orr/add 等写同寄存器）
    mvn_idx = None
    scan = 0
    for j in range(writer_idx - 1, -1, -1):
        if scan >= 50000:
            break
        scan += 1
        ev = parser.events[j]
        if src_reg not in ev.writes:
            # 别名（w/x）
            try:
                if not any(a in ev.writes for a in parser._alias_names(src_reg)):  # type: ignore[attr-defined]
                    continue
            except Exception:
                continue
        if ev.asm.lower().strip().startswith("mvn"):
            mvn_idx = j
            break
    if mvn_idx is None:
        return ""

    # mvn 之前再找最近一次 eor 写 src_reg
    eor_idx = None
    scan = 0
    for j in range(mvn_idx - 1, -1, -1):
        if scan >= 50000:
            break
        scan += 1
        ev = parser.events[j]
        if src_reg not in ev.writes:
            try:
                if not any(a in ev.writes for a in parser._alias_names(src_reg)):  # type: ignore[attr-defined]
                    continue
            except Exception:
                continue
        if ev.asm.lower().strip().startswith("eor"):
            eor_idx = j
            break
    if eor_idx is None:
        # mvn 之前不一定是 eor，但依然可表示为 out = ~x
        return f"out = (~{src_reg}) & 0xff"
    eor_ev = parser.events[eor_idx]
    asm = eor_ev.asm.lower()
    if not asm.strip().startswith("eor"):
        return f"out = (~{src_reg}) & 0xff"

    # 提取 eor 的“key”：优先立即数；否则尝试从另一个输入寄存器的执行前值推出来
    import re
    imm = None
    m = re.search(r"#(0x[0-9a-f]+|\d+)\b", asm)
    if m:
        imm = m.group(1)
        if imm and not imm.startswith("0x"):
            try:
                imm = hex(int(imm, 10))
            except Exception:
                pass
    if imm:
        return f"out = (~({src_reg} ^ {imm})) & 0xff"

    # eor rd, rn, rm：很多情况下是 eor r1, r2, r1（常量在 r2）
    # 这里尽量把 k 的具体值也打印出来（例如 k=0x14）
    try:
        # 兼容 eor / eor.w / eor.s 等变体
        m2 = re.match(r"^eor(?:\.[a-z0-9]+)?\s+([^,]+)\s*,\s*([^,]+)\s*,\s*([^,]+)\s*$", asm.strip())
        if m2:
            rd = m2.group(1).strip()
            rn = m2.group(2).strip()
            rm = m2.group(3).strip()

            def _same_reg(a: str, b: str) -> bool:
                a = (a or "").strip().lower()
                b = (b or "").strip().lower()
                if a == b:
                    return True
                try:
                    return (a in parser._alias_names(b)) or (b in parser._alias_names(a))  # type: ignore[attr-defined]
                except Exception:
                    return False

            # 选“不是 src_reg 的那个输入寄存器”作为 key 候选
            key_reg = None
            if _same_reg(rn, src_reg) and not _same_reg(rm, src_reg):
                key_reg = rm
            elif _same_reg(rm, src_reg) and not _same_reg(rn, src_reg):
                key_reg = rn

            if key_reg:
                kval = _get_reg_before(parser, eor_idx, key_reg)
                if kval is not None:
                    return f"out = (~({src_reg} ^ 0x{(kval & 0xFFFFFFFF):x})) & 0xff"
    except Exception:
        pass

    return f"out = (~({src_reg} ^ k)) & 0xff"


def reverse_output(trace_path: str, addr: int, length: int, *, end_idx: Optional[int] = None,
                   same_call_only: bool = False) -> List[ByteWrite]:
    parser = TraceParser()
    parser.parse_file(trace_path)

    if not parser.events:
        return []

    if end_idx is None:
        end_idx = len(parser.events) - 1
    end_idx = max(0, min(int(end_idx), len(parser.events) - 1))
    base_call = parser.events[end_idx].call_id

    out: List[ByteWrite] = []
    for off in range(int(length)):
        a = (int(addr) + off) & 0xFFFFFFFF
        writer_idx = parser._find_prev_store_to_address(  # type: ignore[attr-defined]
            a, from_index_exclusive=end_idx + 1, max_steps=400000,
            same_call_id=(base_call if same_call_only else None)
        )
        if writer_idx is None:
            out.append(ByteWrite(off, a, -1, parser.events[end_idx], None, None, None, pattern="(未找到写入)"))
            continue
        ev = parser.events[writer_idx]
        src_reg = _parse_store_src_reg(parser, ev.asm)
        src_val_before = _get_reg_before(parser, writer_idx, src_reg) if src_reg else None
        # 对 strb/strh：只取低 8/16 位；否则取低 8 位展示（因为我们是按 byte 地址回溯的）
        byte_value = None
        if src_val_before is not None:
            byte_value = src_val_before & 0xFF
        bw = ByteWrite(off, a, writer_idx, ev, src_reg, src_val_before, byte_value)
        if src_reg:
            bw.pattern = _guess_pattern_eor_mvn_strb(parser, writer_idx, src_reg)
        out.append(bw)
    return out


def main() -> None:
    # 降噪：trace_parser 在缺少解码器时会打印大量 fallback warning，不影响逆推结果
    logging.getLogger().setLevel(logging.ERROR)
    ap = argparse.ArgumentParser(description="从输出 buffer 逆推 trace 中的写入链路")
    ap.add_argument("--trace", required=True, help="trace 文件路径")
    ap.add_argument("--addr", required=True, help="输出 buffer 起始地址（十六进制或十进制）")
    ap.add_argument("--len", required=True, type=int, help="输出长度（字节）")
    ap.add_argument("--end-idx", default=None, help="可选：以该事件索引作为回溯终点（默认文件末尾）")
    ap.add_argument("--same-call", action="store_true", help="仅回溯同一 call_id 内的写入")
    args = ap.parse_args()

    trace_path = args.trace
    addr = _parse_int(args.addr)
    length = int(args.len)
    end_idx = _parse_int(args.end_idx) if args.end_idx is not None else None

    rows = reverse_output(trace_path, addr, length, end_idx=end_idx, same_call_only=bool(args.same_call))
    if not rows:
        print("未解析到任何事件（trace 为空或格式不匹配）")
        return

    # 打印结果：每字节一行，便于复制到分析文档
    for r in rows:
        if r.writer_idx < 0:
            print(f"+{r.offset:02d} 0x{r.addr:08x}  ??  (未找到写入)")
            continue
        line_no = getattr(r.ev, "line_no", 0)
        pc = getattr(r.ev, "pc", 0)
        asm = (r.ev.asm or "").strip()
        b = "??" if r.byte_value is None else f"{r.byte_value:02x}"
        src = r.src_reg or "?"
        srcv = "" if r.src_val_before is None else f"0x{(r.src_val_before & 0xFFFFFFFF):08x}"
        pat = f" | {r.pattern}" if r.pattern else ""
        print(f"+{r.offset:02d} 0x{r.addr:08x}  {b}  line={line_no} pc=0x{pc:08x}  {asm}  {src}={srcv}{pat}")


if __name__ == "__main__":
    main()


