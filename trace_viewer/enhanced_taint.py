#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
增强版污点分析 - 针对 Unidbg trace 文件的专用优化

改进点：
1. 字节级内存污点追踪（而不是地址级）
2. 污点标签系统（追踪每个污点的来源）
3. 隐式流检测（条件分支影响）
4. 污点传播策略配置（宽松/严格模式）
5. 污点汇合点检测（多个污点汇聚）
"""

from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass, field
from enum import Enum


class TaintLabel:
    """污点标签 - 记录污点的来源信息"""
    
    def __init__(self, source_type: str, source_id: str, event_idx: int):
        """
        Args:
            source_type: 'reg' | 'mem' | 'input' | 'network'
            source_id: 寄存器名或内存地址
            event_idx: 产生该污点的事件索引
        """
        self.source_type = source_type
        self.source_id = source_id
        self.event_idx = event_idx
        self.generation = 0  # 传播代数（被传播了多少次）
    
    def derive(self) -> 'TaintLabel':
        """派生一个新的污点标签（代数+1）"""
        new_label = TaintLabel(self.source_type, self.source_id, self.event_idx)
        new_label.generation = self.generation + 1
        return new_label
    
    def __repr__(self):
        return f"Taint({self.source_type}:{self.source_id}@{self.event_idx},gen={self.generation})"
    
    def __hash__(self):
        return hash((self.source_type, self.source_id, self.event_idx))
    
    def __eq__(self, other):
        if not isinstance(other, TaintLabel):
            return False
        return (self.source_type == other.source_type and 
                self.source_id == other.source_id and 
                self.event_idx == other.event_idx)


class TaintPolicy(Enum):
    """污点传播策略"""
    STRICT = "strict"      # 严格模式：只传播显式数据流
    NORMAL = "normal"      # 正常模式：包含常见的隐式流
    LOOSE = "loose"        # 宽松模式：包含所有可能的污点路径


@dataclass
class ByteLevelMemoryTaint:
    """字节级内存污点状态"""
    
    # 地址 -> (字节偏移 -> 污点标签集合)
    memory: Dict[int, Dict[int, Set[TaintLabel]]] = field(default_factory=dict)
    
    def mark_tainted(self, addr: int, size: int, labels: Set[TaintLabel]):
        """标记内存区域为污点"""
        base = addr & 0xFFFFFFF0  # 对齐到16字节
        for i in range(size):
            byte_addr = addr + i
            page_base = byte_addr & 0xFFFFFFF0
            offset = byte_addr & 0xF
            
            if page_base not in self.memory:
                self.memory[page_base] = {}
            
            if offset not in self.memory[page_base]:
                self.memory[page_base][offset] = set()
            
            self.memory[page_base][offset].update(labels)
    
    def is_tainted(self, addr: int, size: int = 1) -> bool:
        """检查内存区域是否被污染"""
        for i in range(size):
            byte_addr = addr + i
            page_base = byte_addr & 0xFFFFFFF0
            offset = byte_addr & 0xF
            
            if page_base in self.memory and offset in self.memory[page_base]:
                if self.memory[page_base][offset]:
                    return True
        return False
    
    def get_labels(self, addr: int, size: int = 1) -> Set[TaintLabel]:
        """获取内存区域的所有污点标签"""
        labels = set()
        for i in range(size):
            byte_addr = addr + i
            page_base = byte_addr & 0xFFFFFFF0
            offset = byte_addr & 0xF
            
            if page_base in self.memory and offset in self.memory[page_base]:
                labels.update(self.memory[page_base][offset])
        return labels
    
    def clear_range(self, addr: int, size: int):
        """清除内存区域的污点"""
        for i in range(size):
            byte_addr = addr + i
            page_base = byte_addr & 0xFFFFFFF0
            offset = byte_addr & 0xF
            
            if page_base in self.memory and offset in self.memory[page_base]:
                self.memory[page_base][offset].clear()


class EnhancedTaintAnalyzer:
    """增强版污点分析器"""
    
    def __init__(self, policy: TaintPolicy = TaintPolicy.NORMAL):
        self.policy = policy
        
        # 寄存器污点状态：寄存器名 -> 污点标签集合
        self.reg_taints: Dict[str, Set[TaintLabel]] = {}
        
        # 内存污点状态（字节级）
        self.mem_taints = ByteLevelMemoryTaint()
        
        # 隐式流污点（条件分支影响）
        self.implicit_taints: Set[TaintLabel] = set()
        
        # 污点传播历史
        self.propagation_history: List[Tuple[int, str, Set[TaintLabel]]] = []
        
        # 污点汇合点（多个污点来源合并的位置）
        self.confluence_points: Dict[int, List[Set[TaintLabel]]] = {}
    
    def add_source(self, source_type: str, source_id: str, event_idx: int):
        """添加污点源"""
        label = TaintLabel(source_type, source_id, event_idx)
        
        if source_type == 'reg':
            reg = source_id.lower()
            if reg not in self.reg_taints:
                self.reg_taints[reg] = set()
            self.reg_taints[reg].add(label)
        
        elif source_type == 'mem':
            addr = int(source_id, 16) if isinstance(source_id, str) else source_id
            self.mem_taints.mark_tainted(addr, 1, {label})
    
    def propagate_reg_to_reg(self, event_idx: int, src_regs: List[str], 
                            dst_reg: str, is_partial: bool = False) -> bool:
        """
        传播：寄存器 -> 寄存器
        
        Args:
            event_idx: 当前事件索引
            src_regs: 源寄存器列表
            dst_reg: 目标寄存器
            is_partial: 是否部分修改（如 movk 只改16位）
        
        Returns:
            是否发生了污点传播
        """
        dst_reg = dst_reg.lower()
        src_labels = set()
        
        # 收集所有源寄存器的污点
        for src in src_regs:
            src = src.lower()
            if src in self.reg_taints:
                for label in self.reg_taints[src]:
                    src_labels.add(label.derive())
        
        # 如果有污点源
        if src_labels:
            # 检测污点汇合（多个不同来源的污点）
            if len(set(l.source_id for l in src_labels)) > 1:
                if event_idx not in self.confluence_points:
                    self.confluence_points[event_idx] = []
                self.confluence_points[event_idx].append(src_labels)
            
            # 传播到目标寄存器
            if is_partial:
                # 部分修改：保留原有污点并添加新污点
                if dst_reg not in self.reg_taints:
                    self.reg_taints[dst_reg] = set()
                self.reg_taints[dst_reg].update(src_labels)
            else:
                # 完全覆盖
                self.reg_taints[dst_reg] = src_labels
            
            # 记录传播历史
            self.propagation_history.append((event_idx, f"reg_to_reg:{dst_reg}", src_labels))
            return True
        
        # 如果没有污点源，清除目标寄存器（除非是部分修改）
        elif not is_partial and dst_reg in self.reg_taints:
            del self.reg_taints[dst_reg]
        
        return False
    
    def propagate_mem_to_reg(self, event_idx: int, mem_addr: int, 
                            mem_size: int, dst_reg: str) -> bool:
        """传播：内存 -> 寄存器"""
        dst_reg = dst_reg.lower()
        
        # 获取内存的污点标签
        mem_labels = self.mem_taints.get_labels(mem_addr, mem_size)
        
        if mem_labels:
            # 派生新标签
            new_labels = {label.derive() for label in mem_labels}
            self.reg_taints[dst_reg] = new_labels
            
            self.propagation_history.append((event_idx, f"mem_to_reg:{dst_reg}", new_labels))
            return True
        
        # 清除目标寄存器污点
        elif dst_reg in self.reg_taints:
            del self.reg_taints[dst_reg]
        
        return False
    
    def propagate_reg_to_mem(self, event_idx: int, src_reg: str, 
                            mem_addr: int, mem_size: int) -> bool:
        """传播：寄存器 -> 内存"""
        src_reg = src_reg.lower()
        
        if src_reg in self.reg_taints:
            labels = {label.derive() for label in self.reg_taints[src_reg]}
            self.mem_taints.mark_tainted(mem_addr, mem_size, labels)
            
            self.propagation_history.append((event_idx, f"reg_to_mem:0x{mem_addr:x}", labels))
            return True
        
        return False
    
    def propagate_implicit_flow(self, event_idx: int, condition_regs: List[str]):
        """处理隐式流（条件分支）"""
        if self.policy == TaintPolicy.STRICT:
            return  # 严格模式不处理隐式流
        
        # 收集条件寄存器的污点
        cond_labels = set()
        for reg in condition_regs:
            reg = reg.lower()
            if reg in self.reg_taints:
                cond_labels.update(self.reg_taints[reg])
        
        if cond_labels:
            self.implicit_taints.update(cond_labels)
    
    def is_reg_tainted(self, reg: str) -> bool:
        """检查寄存器是否被污染"""
        reg = reg.lower()
        return reg in self.reg_taints and len(self.reg_taints[reg]) > 0
    
    def get_reg_labels(self, reg: str) -> Set[TaintLabel]:
        """获取寄存器的污点标签"""
        reg = reg.lower()
        return self.reg_taints.get(reg, set())
    
    def get_taint_sources(self, reg: str) -> List[Tuple[str, str, int]]:
        """获取寄存器污点的所有源头"""
        labels = self.get_reg_labels(reg)
        return [(l.source_type, l.source_id, l.event_idx) for l in labels]
    
    def get_confluence_points(self) -> Dict[int, List[List[Tuple[str, str]]]]:
        """获取所有污点汇合点"""
        result = {}
        for idx, label_sets in self.confluence_points.items():
            result[idx] = []
            for labels in label_sets:
                sources = [(l.source_type, l.source_id) for l in labels]
                result[idx].append(sources)
        return result
    
    def get_propagation_chain(self, target_reg: str) -> List[Tuple[int, str]]:
        """获取目标寄存器的完整传播链"""
        target_reg = target_reg.lower()
        chain = []
        
        if target_reg not in self.reg_taints:
            return chain
        
        target_labels = self.reg_taints[target_reg]
        
        # 反向追踪传播历史
        for event_idx, desc, labels in self.propagation_history:
            # 检查是否与目标标签有交集
            if labels & target_labels:
                chain.append((event_idx, desc))
        
        return chain


def create_analyzer_from_trace(parser, start_idx: int, 
                               source_regs: List[str] = None,
                               source_mem_addrs: List[int] = None,
                               policy: TaintPolicy = TaintPolicy.NORMAL) -> EnhancedTaintAnalyzer:
    """
    从 trace 创建增强污点分析器
    
    使用示例：
    >>> analyzer = create_analyzer_from_trace(parser, 0, 
    ...                                       source_regs=['r0'],
    ...                                       policy=TaintPolicy.NORMAL)
    >>> # 分析会自动进行...
    """
    analyzer = EnhancedTaintAnalyzer(policy)
    
    # 添加污点源
    for reg in (source_regs or []):
        analyzer.add_source('reg', reg, start_idx)
    
    for addr in (source_mem_addrs or []):
        analyzer.add_source('mem', hex(addr), start_idx)
    
    return analyzer

