#!/usr/bin/env python3
"""
PyQt5 to PyQt6 AST-based 自动迁移脚本
使用 AST 精确识别和替换枚举
"""

import ast
import sys
from pathlib import Path
from typing import Dict, Set, Tuple

# Qt6 枚举迁移映射表
ENUM_MAPPINGS = {
    # QPalette.ColorRole
    'QtGui.QPalette': {
        'Window', 'WindowText', 'Base', 'AlternateBase', 'ToolTipBase', 'ToolTipText',
        'Text', 'Button', 'ButtonText', 'BrightText', 'Link', 'LinkVisited', 
        'Light', 'Midlight', 'Dark', 'Mid', 'Shadow', 'Highlight', 'HighlightedText', 'PlaceholderText'
    },
    
    # QEvent.Type
    'QtCore.QEvent': {
        'Timer', 'MouseButtonPress', 'MouseButtonRelease', 'MouseButtonDblClick',
        'MouseMove', 'KeyPress', 'KeyRelease', 'FocusIn', 'FocusOut', 'Enter', 
        'Leave', 'Paint', 'Move', 'Resize', 'Create', 'Destroy', 'Show', 'Hide', 
        'Close', 'Quit', 'ToolTip', 'WhatsThis', 'ContextMenu'
    },
    
    # Qt.ItemDataRole
    'QtCore.Qt': {
        'DisplayRole', 'DecorationRole', 'EditRole', 'ToolTipRole', 'StatusTipRole',
        'WhatsThisRole', 'FontRole', 'TextAlignmentRole', 'BackgroundRole', 
        'ForegroundRole', 'CheckStateRole', 'UserRole'
    },
    
    # Qt.Orientation
    'QtCore.Qt.Orientation': {
        'Horizontal', 'Vertical'
    },
    
    # Qt.DockWidgetArea
    'QtCore.Qt.DockWidgetArea': {
        'LeftDockWidgetArea', 'RightDockWidgetArea', 'TopDockWidgetArea', 
        'BottomDockWidgetArea', 'AllDockWidgetAreas', 'NoDockWidgetArea'
    },
    
    # Qt.ToolBarArea
    'QtCore.Qt.ToolBarArea': {
        'LeftToolBarArea', 'RightToolBarArea', 'TopToolBarArea', 
        'BottomToolBarArea', 'AllToolBarAreas', 'NoToolBarArea'
    },
    
    # Qt.ContextMenuPolicy
    'QtCore.Qt.ContextMenuPolicy': {
        'NoContextMenu', 'DefaultContextMenu', 'ActionsContextMenu', 
        'CustomContextMenu', 'PreventContextMenu'
    },
    
    # QAbstractItemView
    'QtWidgets.QAbstractItemView.SelectionMode': {
        'NoSelection', 'SingleSelection', 'MultiSelection', 
        'ExtendedSelection', 'ContiguousSelection'
    },
    'QtWidgets.QAbstractItemView.SelectionBehavior': {
        'SelectItems', 'SelectRows', 'SelectColumns'
    },
    'QtWidgets.QAbstractItemView.ScrollHint': {
        'EnsureVisible', 'PositionAtTop', 'PositionAtBottom', 'PositionAtCenter'
    },
    'QtWidgets.QAbstractItemView.EditTrigger': {
        'NoEditTriggers', 'CurrentChanged', 'DoubleClicked', 'SelectedClicked',
        'EditKeyPressed', 'AnyKeyPressed', 'AllEditTriggers'
    },
    
    # QDialog.DialogCode
    'QtWidgets.QDialog.DialogCode': {
        'Accepted', 'Rejected'
    },
    
    # QPlainTextEdit.LineWrapMode
    'QtWidgets.QPlainTextEdit.LineWrapMode': {
        'NoWrap', 'WidgetWidth'
    },
    
    # QTextEdit.LineWrapMode
    'QtWidgets.QTextEdit.LineWrapMode': {
        'NoWrap', 'WidgetWidth', 'FixedPixelWidth', 'FixedColumnWidth'
    },
    
    # QFont.Weight
    'QtGui.QFont.Weight': {
        'Thin', 'ExtraLight', 'Light', 'Normal', 'Medium', 
        'DemiBold', 'Bold', 'ExtraBold', 'Black'
    },
    
    # QTextFormat.Property
    'QtGui.QTextFormat.Property': {
        'FullWidthSelection', 'BackgroundBrush', 'ForegroundBrush', 
        'FontFamily', 'FontPointSize', 'FontWeight'
    },
    
    # QKeySequence.StandardKey
    'QtGui.QKeySequence.StandardKey': {
        'Open', 'Close', 'Save', 'New', 'Delete', 'Cut', 'Copy', 'Paste',
        'Undo', 'Redo', 'Back', 'Forward', 'Refresh', 'ZoomIn', 'ZoomOut',
        'Print', 'Find', 'SelectAll', 'Quit'
    },
    
    # QDockWidget.DockWidgetFeature
    'QtWidgets.QDockWidget.DockWidgetFeature': {
        'DockWidgetClosable', 'DockWidgetMovable', 'DockWidgetFloatable',
        'DockWidgetVerticalTitleBar', 'AllDockWidgetFeatures', 'NoDockWidgetFeatures'
    },
    
    # Qt.AlignmentFlag
    'QtCore.Qt.AlignmentFlag': {
        'AlignLeft', 'AlignRight', 'AlignHCenter', 'AlignJustify',
        'AlignTop', 'AlignBottom', 'AlignVCenter', 'AlignCenter'
    },
    
    # Qt.CursorShape
    'QtCore.Qt.CursorShape': {
        'ArrowCursor', 'WaitCursor', 'IBeamCursor', 'PointingHandCursor',
        'ForbiddenCursor', 'WhatsThisCursor', 'BusyCursor'
    },
    
    # Qt.MouseButton
    'QtCore.Qt.MouseButton': {
        'LeftButton', 'RightButton', 'MiddleButton', 'NoButton'
    },
}

# 需要检查的基础类
BASE_CLASSES = {
    'QtGui.QPalette': 'ColorRole',
    'QtCore.QEvent': 'Type',
    'QtGui.QFont': 'Weight',
    'QtGui.QTextFormat': 'Property',
    'QtGui.QKeySequence': 'StandardKey',
    'QtWidgets.QAbstractItemView': None,  # 有多个子枚举
    'QtWidgets.QDialog': 'DialogCode',
    'QtWidgets.QPlainTextEdit': 'LineWrapMode',
    'QtWidgets.QTextEdit': 'LineWrapMode',
    'QtWidgets.QDockWidget': 'DockWidgetFeature',
}

# Qt 枚举
QT_ENUMS = {
    'ItemDataRole', 'ContextMenuPolicy', 'Orientation', 'DockWidgetArea',
    'ToolBarArea', 'AlignmentFlag', 'CursorShape', 'MouseButton'
}

# QAction 等类从 QtWidgets 移到 QtGui
MOVED_CLASSES = {
    'QAction': ('QtWidgets', 'QtGui'),
    'QShortcut': ('QtWidgets', 'QtGui'),
    'QActionGroup': ('QtWidgets', 'QtGui'),
}

class Qt6Transformer(ast.NodeTransformer):
    """AST转换器，将PyQt5代码转换为PyQt6"""
    
    def __init__(self):
        self.changes = []
    
    def visit_Attribute(self, node):
        """访问属性节点，如 Qt.UserRole"""
        self.generic_visit(node)
        
        # 获取完整的属性链
        parts = self._get_attribute_chain(node)
        if not parts:
            return node
        
        full_path = '.'.join(parts[:-1])  # 除了最后一个属性
        attr_name = parts[-1]  # 最后一个属性
        
        # 检查是否需要迁移
        new_node = self._transform_enum(node, full_path, attr_name, parts)
        if new_node is not node:
            self.changes.append(f"{full_path}.{attr_name} -> 已转换")
        
        return new_node
    
    def _get_attribute_chain(self, node):
        """获取属性链，如 ['QtCore', 'Qt', 'UserRole']"""
        parts = []
        current = node
        
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        
        if isinstance(current, ast.Name):
            parts.append(current.id)
        
        return list(reversed(parts))
    
    def _transform_enum(self, node, full_path, attr_name, parts):
        """转换枚举"""
        # 处理 QAction 等类的移动
        if len(parts) >= 2:
            module, class_name = parts[0], parts[1]
            if class_name in MOVED_CLASSES:
                old_module, new_module = MOVED_CLASSES[class_name]
                if module == old_module:
                    # 替换模块名
                    new_node = ast.copy_location(
                        ast.Attribute(
                            value=ast.Name(id=new_module, ctx=ast.Load()),
                            attr=class_name,
                            ctx=node.ctx
                        ),
                        node
                    )
                    # 保留后续的属性
                    for i in range(2, len(parts)):
                        new_node = ast.copy_location(
                            ast.Attribute(
                                value=new_node,
                                attr=parts[i],
                                ctx=node.ctx
                            ),
                            node
                        )
                    return new_node
        
        # 检查基础类枚举
        if full_path in BASE_CLASSES:
            enum_type = BASE_CLASSES[full_path]
            if enum_type:
                # 创建新的属性链: QtGui.QPalette.ColorRole.Window
                new_node = node.value  # 原来的 QtGui.QPalette
                new_node = ast.copy_location(
                    ast.Attribute(
                        value=new_node,
                        attr=enum_type,
                        ctx=ast.Load()
                    ),
                    node
                )
                new_node = ast.copy_location(
                    ast.Attribute(
                        value=new_node,
                        attr=attr_name,
                        ctx=node.ctx
                    ),
                    node
                )
                return new_node
        
        # 检查 Qt 命名空间下的枚举
        if full_path == 'QtCore.Qt' and attr_name in QT_ENUMS:
            # QtCore.Qt.ItemDataRole -> 需要添加枚举类型
            # 但这里只是访问枚举类型本身，不需要转换
            return node
        
        # 检查需要添加枚举类型的情况
        # 例如: QtCore.Qt.UserRole -> QtCore.Qt.ItemDataRole.UserRole
        if full_path == 'QtCore.Qt':
            # 查找这个属性属于哪个枚举
            for enum_name in QT_ENUMS:
                enum_full_path = f'QtCore.Qt.{enum_name}'
                if enum_full_path in ENUM_MAPPINGS:
                    if attr_name in ENUM_MAPPINGS[enum_full_path]:
                        # 添加枚举类型
                        new_node = node.value  # QtCore.Qt
                        new_node = ast.copy_location(
                            ast.Attribute(
                                value=new_node,
                                attr=enum_name,
                                ctx=ast.Load()
                            ),
                            node
                        )
                        new_node = ast.copy_location(
                            ast.Attribute(
                                value=new_node,
                                attr=attr_name,
                                ctx=node.ctx
                            ),
                            node
                        )
                        return new_node
        
        # 检查 QAbstractItemView 的子枚举
        if full_path == 'QtWidgets.QAbstractItemView':
            # 需要确定属于哪个枚举
            for enum_suffix in ['SelectionMode', 'SelectionBehavior', 'ScrollHint', 'EditTrigger']:
                enum_full_path = f'QtWidgets.QAbstractItemView.{enum_suffix}'
                if enum_full_path in ENUM_MAPPINGS:
                    if attr_name in ENUM_MAPPINGS[enum_full_path]:
                        new_node = node.value
                        new_node = ast.copy_location(
                            ast.Attribute(
                                value=new_node,
                                attr=enum_suffix,
                                ctx=ast.Load()
                            ),
                            node
                        )
                        new_node = ast.copy_location(
                            ast.Attribute(
                                value=new_node,
                                attr=attr_name,
                                ctx=node.ctx
                            ),
                            node
                        )
                        return new_node
        
        return node

def migrate_file(filepath: Path, dry_run: bool = False) -> bool:
    """迁移单个文件"""
    try:
        content = filepath.read_text(encoding='utf-8')
        
        # 解析 AST
        try:
            tree = ast.parse(content, filename=str(filepath))
        except SyntaxError as e:
            print(f"  ⚠️  语法错误，跳过: {filepath} ({e})")
            return False
        
        # 转换 AST
        transformer = Qt6Transformer()
        new_tree = transformer.visit(tree)
        
        # 如果有改动
        if transformer.changes:
            # 反编译 AST
            import astor
            new_content = astor.to_source(new_tree)
            
            if dry_run:
                print(f"  [DRY RUN] 将修改: {filepath}")
                for change in transformer.changes[:5]:  # 只显示前5个
                    print(f"    - {change}")
                if len(transformer.changes) > 5:
                    print(f"    ... 还有 {len(transformer.changes) - 5} 个更改")
            else:
                filepath.write_text(new_content, encoding='utf-8')
                print(f"  ✅ 已修改: {filepath} ({len(transformer.changes)} 处更改)")
            return True
        else:
            print(f"  ⏭️  无需修改: {filepath}")
            return False
            
    except Exception as e:
        print(f"  ❌ 错误: {filepath}: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """主函数"""
    import argparse
    
    # 检查是否安装了 astor
    try:
        import astor
    except ImportError:
        print("❌ 需要安装 astor 库:")
        print("   pip install astor")
        sys.exit(1)
    
    parser = argparse.ArgumentParser(description='PyQt5 到 PyQt6 AST-based 自动迁移脚本')
    parser.add_argument('path', nargs='?', default='trace_viewer',
                        help='要迁移的目录或文件路径（默认: trace_viewer）')
    parser.add_argument('--dry-run', action='store_true',
                        help='仅显示将要做的更改，不实际修改文件')
    
    args = parser.parse_args()
    
    target_path = Path(args.path)
    
    if not target_path.exists():
        print(f"❌ 路径不存在: {target_path}")
        sys.exit(1)
    
    print(f"{'🔍 [DRY RUN] ' if args.dry_run else '🚀 '}开始迁移 PyQt5 → PyQt6 (AST mode)")
    print(f"目标路径: {target_path}\n")
    
    # 收集所有 Python 文件
    if target_path.is_file():
        files = [target_path]
    else:
        files = list(target_path.rglob('*.py'))
    
    print(f"找到 {len(files)} 个 Python 文件\n")
    
    # 迁移文件
    modified_count = 0
    for file in files:
        if migrate_file(file, args.dry_run):
            modified_count += 1
    
    print(f"\n{'[DRY RUN] ' if args.dry_run else ''}完成！")
    print(f"修改了 {modified_count}/{len(files)} 个文件")
    
    if args.dry_run:
        print("\n💡 提示: 移除 --dry-run 参数来实际执行修改")

if __name__ == '__main__':
    main()

