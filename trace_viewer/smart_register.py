"""
智能寄存器分析模块：自动推断寄存器用途、变化趋势、命名建议

功能：
1. 自动推断寄存器用途（指针、索引、密钥、常量等）
2. 分析变化趋势（递增、递减、不变、波动）
3. 提供人性化命名建议
4. 检测循环变量和边界值
"""

from typing import Dict, List, Tuple, Optional
from collections import Counter


class RegisterPurpose:
    """寄存器用途枚举"""
    POINTER = 'pointer'       # 指针（地址）
    INDEX = 'index'           # 索引（循环变量）
    COUNTER = 'counter'       # 计数器
    KEY = 'key'              # 密钥/常量
    DATA = 'data'            # 数据值
    LENGTH = 'length'        # 长度
    OFFSET = 'offset'        # 偏移量
    TEMP = 'temp'            # 临时变量
    UNKNOWN = 'unknown'      # 未知


class RegisterTrend:
    """寄存器变化趋势"""
    CONSTANT = 'constant'     # 常量（不变）
    INCREASING = 'increasing' # 递增
    DECREASING = 'decreasing' # 递减
    VOLATILE = 'volatile'     # 频繁变化
    PERIODIC = 'periodic'     # 周期性变化


class RegisterAnalyzer:
    """寄存器智能分析器"""
    
    # 常见的内存区域范围（ARM）
    STACK_RANGES = [(0x7000_0000, 0x8000_0000)]  # 栈区域
    HEAP_RANGES = [(0x4000_0000, 0x6000_0000)]   # 堆区域
    CODE_RANGES = [(0x1000_0000, 0x3000_0000)]   # 代码区域
    
    def __init__(self, parser=None):
        self.parser = parser
        self._analysis_cache = {}  # 缓存分析结果
    
    def analyze_register(self, reg_name: str, event_start: int, event_end: int) -> Dict:
        """分析寄存器在指定事件范围内的行为
        
        返回：
        {
            'purpose': RegisterPurpose,
            'trend': RegisterTrend,
            'suggested_name': str,
            'icon': str,
            'description': str,
            'statistics': {
                'min': int,
                'max': int,
                'changes': int,
                'distinct_values': int
            }
        }
        """
        cache_key = (reg_name, event_start, event_end)
        if cache_key in self._analysis_cache:
            return self._analysis_cache[cache_key]
        
        if not self.parser:
            return self._default_analysis(reg_name)
        
        # 收集寄存器值的历史
        values = []
        for idx in range(event_start, min(event_end + 1, len(self.parser.events))):
            try:
                regs = self.parser.restore_registers(idx)
                if reg_name in regs:
                    values.append(regs[reg_name])
            except:
                pass
        
        if not values:
            return self._default_analysis(reg_name)
        
        # 分析
        result = {
            'purpose': self._infer_purpose(reg_name, values),
            'trend': self._analyze_trend(values),
            'statistics': self._calculate_statistics(values)
        }
        
        # 生成建议名称和描述
        result['suggested_name'] = self._suggest_name(reg_name, result['purpose'], result['trend'])
        result['icon'] = self._get_icon(result['purpose'])
        result['description'] = self._generate_description(result)
        
        self._analysis_cache[cache_key] = result
        return result
    
    def _infer_purpose(self, reg_name: str, values: List[int]) -> str:
        """推断寄存器用途"""
        if not values:
            return RegisterPurpose.UNKNOWN
        
        # 检查是否为常量
        if len(set(values)) == 1:
            val = values[0]
            # 检查是否为指针
            if self._is_pointer(val):
                return RegisterPurpose.POINTER
            # 检查是否为小常量（可能是密钥、长度等）
            if 0 < val < 0x100:
                return RegisterPurpose.KEY
            return RegisterPurpose.KEY
        
        # 检查是否为指针（大部分值都是地址）
        pointer_count = sum(1 for v in values if self._is_pointer(v))
        if pointer_count > len(values) * 0.7:
            return RegisterPurpose.POINTER
        
        # 检查是否为索引/计数器（递增且值较小）
        if self._is_sequential(values):
            max_val = max(values)
            if max_val < 0x1000:  # 索引通常不会太大
                return RegisterPurpose.INDEX
            return RegisterPurpose.COUNTER
        
        # 检查是否为长度（小值且变化不大）
        if max(values) < 0x10000 and len(set(values)) < 10:
            return RegisterPurpose.LENGTH
        
        # 检查是否为偏移量（相对小的值）
        if all(v < 0x1000 for v in values):
            return RegisterPurpose.OFFSET
        
        # 频繁变化的可能是数据或临时变量
        if len(set(values)) > len(values) * 0.5:
            return RegisterPurpose.DATA
        
        return RegisterPurpose.TEMP
    
    def _analyze_trend(self, values: List[int]) -> str:
        """分析变化趋势"""
        if len(values) < 2:
            return RegisterTrend.CONSTANT
        
        # 检查是否为常量
        if len(set(values)) == 1:
            return RegisterTrend.CONSTANT
        
        # 检查是否为严格递增
        if all(values[i] < values[i+1] for i in range(len(values)-1)):
            return RegisterTrend.INCREASING
        
        # 检查是否为严格递减
        if all(values[i] > values[i+1] for i in range(len(values)-1)):
            return RegisterTrend.DECREASING
        
        # 检查是否为大致递增（允许一些波动）
        increasing_count = sum(1 for i in range(len(values)-1) if values[i] < values[i+1])
        if increasing_count > len(values) * 0.7:
            return RegisterTrend.INCREASING
        
        # 检查是否为大致递减
        decreasing_count = sum(1 for i in range(len(values)-1) if values[i] > values[i+1])
        if decreasing_count > len(values) * 0.7:
            return RegisterTrend.DECREASING
        
        # 检查是否为周期性（值重复出现）
        value_counts = Counter(values)
        if len(value_counts) < len(values) * 0.3:  # 重复率高
            return RegisterTrend.PERIODIC
        
        return RegisterTrend.VOLATILE
    
    def _calculate_statistics(self, values: List[int]) -> Dict:
        """计算统计信息"""
        return {
            'min': min(values) if values else 0,
            'max': max(values) if values else 0,
            'changes': len(values) - 1,
            'distinct_values': len(set(values))
        }
    
    def _is_pointer(self, value: int) -> bool:
        """判断是否为指针地址"""
        # 检查是否在常见内存区域
        for start, end in self.STACK_RANGES + self.HEAP_RANGES + self.CODE_RANGES:
            if start <= value <= end:
                return True
        
        # 检查是否为4字节对齐（指针通常对齐）
        if value % 4 == 0 and value > 0x1000:
            return True
        
        return False
    
    def _is_sequential(self, values: List[int]) -> bool:
        """判断是否为顺序值"""
        if len(values) < 3:
            return False
        
        # 检查差值是否相对恒定
        diffs = [values[i+1] - values[i] for i in range(len(values)-1)]
        
        # 如果所有差值都相同（如都是1或都是4）
        if len(set(diffs)) == 1 and diffs[0] > 0:
            return True
        
        # 如果大部分差值都是正数且接近
        if all(d > 0 for d in diffs):
            avg_diff = sum(diffs) / len(diffs)
            if all(abs(d - avg_diff) < avg_diff * 0.5 for d in diffs):
                return True
        
        return False
    
    def _suggest_name(self, reg_name: str, purpose: str, trend: str) -> str:
        """建议寄存器名称"""
        name_map = {
            RegisterPurpose.POINTER: 'ptr',
            RegisterPurpose.INDEX: 'idx' if trend == RegisterTrend.INCREASING else 'index',
            RegisterPurpose.COUNTER: 'cnt',
            RegisterPurpose.KEY: 'key',
            RegisterPurpose.DATA: 'data',
            RegisterPurpose.LENGTH: 'len',
            RegisterPurpose.OFFSET: 'off',
            RegisterPurpose.TEMP: 'tmp',
        }
        
        base_name = name_map.get(purpose, reg_name)
        
        # 添加寄存器编号
        if reg_name.startswith('r') or reg_name.startswith('x'):
            num = reg_name[1:]
            return f"{base_name}{num}"
        
        return base_name
    
    def _get_icon(self, purpose: str) -> str:
        """获取用途图标（ASCII字符）"""
        icon_map = {
            RegisterPurpose.POINTER: '*',   # 指针
            RegisterPurpose.INDEX: '#',     # 索引
            RegisterPurpose.COUNTER: 'C',   # 计数器
            RegisterPurpose.KEY: 'K',       # 密钥
            RegisterPurpose.DATA: 'D',      # 数据
            RegisterPurpose.LENGTH: 'L',    # 长度
            RegisterPurpose.OFFSET: '+',    # 偏移
            RegisterPurpose.TEMP: 'T',      # 临时
            RegisterPurpose.UNKNOWN: '?',   # 未知
        }
        return icon_map.get(purpose, '·')
    
    def _generate_description(self, analysis: Dict) -> str:
        """生成人性化描述"""
        purpose = analysis['purpose']
        trend = analysis['trend']
        stats = analysis['statistics']
        
        desc_parts = []
        
        # 用途描述
        purpose_desc = {
            RegisterPurpose.POINTER: '指针',
            RegisterPurpose.INDEX: '索引',
            RegisterPurpose.COUNTER: '计数器',
            RegisterPurpose.KEY: '密钥/常量',
            RegisterPurpose.DATA: '数据',
            RegisterPurpose.LENGTH: '长度',
            RegisterPurpose.OFFSET: '偏移',
            RegisterPurpose.TEMP: '临时',
            RegisterPurpose.UNKNOWN: '未知',
        }
        desc_parts.append(purpose_desc.get(purpose, ''))
        
        # 趋势描述
        trend_desc = {
            RegisterTrend.CONSTANT: '不变',
            RegisterTrend.INCREASING: '递增',
            RegisterTrend.DECREASING: '递减',
            RegisterTrend.VOLATILE: '频繁变化',
            RegisterTrend.PERIODIC: '周期性',
        }
        desc_parts.append(trend_desc.get(trend, ''))
        
        # 值范围
        if stats['min'] != stats['max']:
            desc_parts.append(f"0x{stats['min']:x}→0x{stats['max']:x}")
        else:
            desc_parts.append(f"0x{stats['min']:x}")
        
        return ' | '.join(desc_parts)
    
    def _default_analysis(self, reg_name: str) -> Dict:
        """默认分析结果"""
        return {
            'purpose': RegisterPurpose.UNKNOWN,
            'trend': RegisterTrend.CONSTANT,
            'suggested_name': reg_name,
            'icon': '❓',
            'description': '无数据',
            'statistics': {
                'min': 0,
                'max': 0,
                'changes': 0,
                'distinct_values': 0
            }
        }
    
    def get_trend_icon(self, trend: str) -> str:
        """获取趋势图标（ASCII字符）"""
        icons = {
            RegisterTrend.CONSTANT: '=',    # 常量
            RegisterTrend.INCREASING: '+',  # 递增
            RegisterTrend.DECREASING: '-',  # 递减
            RegisterTrend.VOLATILE: '~',    # 波动
            RegisterTrend.PERIODIC: '@',    # 周期
        }
        return icons.get(trend, '·')
    
    def get_trend_color(self, trend: str) -> str:
        """获取趋势颜色"""
        colors = {
            RegisterTrend.CONSTANT: '#6b7280',     # 灰色
            RegisterTrend.INCREASING: '#10b981',   # 绿色
            RegisterTrend.DECREASING: '#ef4444',   # 红色
            RegisterTrend.VOLATILE: '#f59e0b',     # 橙色
            RegisterTrend.PERIODIC: '#8b5cf6',     # 紫色
        }
        return colors.get(trend, '#6b7280')

