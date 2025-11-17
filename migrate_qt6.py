#!/usr/bin/env python3
"""
PyQt5 to PyQt6 自动迁移脚本
使用 AST 和正则表达式批量修改枚举命名空间
"""

import re
import os
import sys
from pathlib import Path

# Qt6 枚举迁移映射表
ENUM_MIGRATIONS = {
    # QPalette
    r'QtGui\.QPalette\.(Window|WindowText|Base|AlternateBase|ToolTipBase|ToolTipText|'
    r'Text|Button|ButtonText|BrightText|Link|LinkVisited|Light|Midlight|Dark|Mid|Shadow|'
    r'Highlight|HighlightedText|PlaceholderText)': 
        r'QtGui.QPalette.ColorRole.\1',
    
    # QEvent
    r'QtCore\.QEvent\.(None_|Timer|MouseButtonPress|MouseButtonRelease|MouseButtonDblClick|'
    r'MouseMove|KeyPress|KeyRelease|FocusIn|FocusOut|Enter|Leave|Paint|Move|Resize|Create|'
    r'Destroy|Show|Hide|Close|Quit|ParentChange|ParentAboutToChange|ThreadChange|WindowActivate|'
    r'WindowDeactivate|ShowToParent|HideToParent|Wheel|WindowTitleChange|WindowIconChange|'
    r'ApplicationWindowIconChange|ApplicationFontChange|ApplicationLayoutDirectionChange|'
    r'ApplicationPaletteChange|PaletteChange|Clipboard|Speech|MetaCall|SockAct|WinEventAct|'
    r'DeferredDelete|DragEnter|DragMove|DragLeave|Drop|DragResponse|ChildAdded|ChildPolished|'
    r'ChildRemoved|ShowWindowRequest|PolishRequest|Polish|LayoutRequest|UpdateRequest|'
    r'UpdateLater|EmbeddingControl|ActivateControl|DeactivateControl|ContextMenu|InputMethod|'
    r'TabletMove|LocaleChange|LanguageChange|LayoutDirectionChange|Style|TabletPress|TabletRelease|'
    r'OkRequest|HelpRequest|IconDrag|FontChange|EnabledChange|ActivationChange|StyleChange|'
    r'IconTextChange|ModifiedChange|MouseTrackingChange|WindowBlocked|WindowUnblocked|WindowStateChange|'
    r'ReadOnlyChange|ToolTip|WhatsThis|StatusTip|ActionChanged|ActionAdded|ActionRemoved|'
    r'FileOpen|Shortcut|ShortcutOverride|WhatsThisClicked|ToolBarChange|ApplicationActivate|'
    r'ApplicationActivated|ApplicationDeactivate|ApplicationDeactivated|QueryWhatsThis|EnterWhatsThisMode|'
    r'LeaveWhatsThisMode|ZOrderChange|HoverEnter|HoverLeave|HoverMove|AcceptDropsChange|'
    r'ZeroTimerEvent|GraphicsSceneMouseMove|GraphicsSceneMousePress|GraphicsSceneMouseRelease|'
    r'GraphicsSceneMouseDoubleClick|GraphicsSceneContextMenu|GraphicsSceneHoverEnter|'
    r'GraphicsSceneHoverMove|GraphicsSceneHoverLeave|GraphicsSceneHelp|GraphicsSceneDragEnter|'
    r'GraphicsSceneDragMove|GraphicsSceneDragLeave|GraphicsSceneDrop|GraphicsSceneWheel|'
    r'KeyboardLayoutChange|DynamicPropertyChange|TabletEnterProximity|TabletLeaveProximity|'
    r'NonClientAreaMouseMove|NonClientAreaMouseButtonPress|NonClientAreaMouseButtonRelease|'
    r'NonClientAreaMouseButtonDblClick|MacSizeChange|ContentsRectChange|MacGLWindowChange|'
    r'FutureCallOut|GraphicsSceneResize|GraphicsSceneMove|CursorChange|ToolTipChange|'
    r'NetworkReplyUpdated|GrabMouse|UngrabMouse|GrabKeyboard|UngrabKeyboard|'
    r'MacGLClearDrawable|StateMachineSignal|StateMachineWrapped|TouchBegin|TouchUpdate|'
    r'TouchEnd|NativeGesture|RequestSoftwareInputPanel|CloseSoftwareInputPanel|'
    r'WinIdChange|Gesture|GestureOverride|ScrollPrepare|Scroll|Expose|InputMethodQuery|'
    r'OrientationChange|TouchCancel|ThemeChange|SockClose|PlatformPanel|StyleAnimationUpdate|'
    r'ApplicationStateChange|WindowChangeInternal|ScreenChangeInternal|PlatformSurface|'
    r'Pointer|TabletTrackingChange)':
        r'QtCore.QEvent.Type.\1',
    
    # Qt.ItemDataRole
    r'QtCore\.Qt\.(DisplayRole|DecorationRole|EditRole|ToolTipRole|StatusTipRole|WhatsThisRole|'
    r'FontRole|TextAlignmentRole|BackgroundRole|ForegroundRole|CheckStateRole|AccessibleTextRole|'
    r'AccessibleDescriptionRole|SizeHintRole|InitialSortOrderRole|UserRole)':
        r'QtCore.Qt.ItemDataRole.\1',
    
    # Qt.ContextMenuPolicy
    r'QtCore\.Qt\.(NoContextMenu|DefaultContextMenu|ActionsContextMenu|CustomContextMenu|PreventContextMenu)':
        r'QtCore.Qt.ContextMenuPolicy.\1',
    
    # Qt.Orientation
    r'QtCore\.Qt\.(Horizontal|Vertical)':
        r'QtCore.Qt.Orientation.\1',
    
    # QAbstractItemView.SelectionMode
    r'QtWidgets\.QAbstractItemView\.(NoSelection|SingleSelection|MultiSelection|ExtendedSelection|ContiguousSelection)':
        r'QtWidgets.QAbstractItemView.SelectionMode.\1',
    
    # QAbstractItemView.SelectionBehavior
    r'QtWidgets\.QAbstractItemView\.(SelectItems|SelectRows|SelectColumns)':
        r'QtWidgets.QAbstractItemView.SelectionBehavior.\1',
    
    # QAbstractItemView.ScrollHint
    r'QtWidgets\.QAbstractItemView\.(EnsureVisible|PositionAtTop|PositionAtBottom|PositionAtCenter)':
        r'QtWidgets.QAbstractItemView.ScrollHint.\1',
    
    # QAbstractItemView.EditTrigger
    r'QtWidgets\.QAbstractItemView\.(NoEditTriggers|CurrentChanged|DoubleClicked|SelectedClicked|'
    r'EditKeyPressed|AnyKeyPressed|AllEditTriggers)':
        r'QtWidgets.QAbstractItemView.EditTrigger.\1',
    
    # QDialog.DialogCode
    r'QtWidgets\.QDialog\.(Accepted|Rejected)':
        r'QtWidgets.QDialog.DialogCode.\1',
    
    # QPlainTextEdit.LineWrapMode
    r'QtWidgets\.QPlainTextEdit\.(NoWrap|WidgetWidth)':
        r'QtWidgets.QPlainTextEdit.LineWrapMode.\1',
    
    # QTextEdit.LineWrapMode
    r'QtWidgets\.QTextEdit\.(NoWrap|WidgetWidth|FixedPixelWidth|FixedColumnWidth)':
        r'QtWidgets.QTextEdit.LineWrapMode.\1',
    
    # Qt.AlignmentFlag
    r'QtCore\.Qt\.(AlignLeft|AlignRight|AlignHCenter|AlignJustify|AlignTop|AlignBottom|'
    r'AlignVCenter|AlignCenter|AlignAbsolute|AlignLeading|AlignTrailing)':
        r'QtCore.Qt.AlignmentFlag.\1',
    
    # Qt.Key
    r'QtCore\.Qt\.(Key_\w+)':
        r'QtCore.Qt.Key.\1',
    
    # Qt.KeyboardModifier
    r'QtCore\.Qt\.(NoModifier|ShiftModifier|ControlModifier|AltModifier|MetaModifier|'
    r'KeypadModifier|GroupSwitchModifier|KeyboardModifierMask)':
        r'QtCore.Qt.KeyboardModifier.\1',
    
    # Qt.MouseButton
    r'QtCore\.Qt\.(NoButton|LeftButton|RightButton|MiddleButton|BackButton|ForwardButton|'
    r'TaskButton|ExtraButton\d+|AllButtons)':
        r'QtCore.Qt.MouseButton.\1',
    
    # Qt.CursorShape
    r'QtCore\.Qt\.(ArrowCursor|UpArrowCursor|CrossCursor|WaitCursor|IBeamCursor|SizeVerCursor|'
    r'SizeHorCursor|SizeBDiagCursor|SizeFDiagCursor|SizeAllCursor|BlankCursor|SplitVCursor|'
    r'SplitHCursor|PointingHandCursor|ForbiddenCursor|WhatsThisCursor|BusyCursor|OpenHandCursor|'
    r'ClosedHandCursor|DragCopyCursor|DragMoveCursor|DragLinkCursor|BitmapCursor|CustomCursor)':
        r'QtCore.Qt.CursorShape.\1',
    
    # Qt.WindowType
    r'QtCore\.Qt\.(Widget|Window|Dialog|Sheet|Drawer|Popup|Tool|ToolTip|SplashScreen|Desktop|'
    r'SubWindow|ForeignWindow|CoverWindow|WindowType_Mask|MSWindowsFixedSizeDialogHint|'
    r'MSWindowsOwnDC|BypassWindowManagerHint|X11BypassWindowManagerHint|FramelessWindowHint|'
    r'WindowTitleHint|WindowSystemMenuHint|WindowMinimizeButtonHint|WindowMaximizeButtonHint|'
    r'WindowMinMaxButtonsHint|WindowContextHelpButtonHint|WindowShadeButtonHint|'
    r'WindowStaysOnTopHint|WindowTransparentForInput|WindowOverridesSystemGestures|'
    r'WindowDoesNotAcceptFocus|MaximizeUsingFullscreenGeometryHint|CustomizeWindowHint|'
    r'WindowStaysOnBottomHint|WindowCloseButtonHint|MacWindowToolBarButtonHint|'
    r'BypassGraphicsProxyWidget|NoDropShadowWindowHint|WindowFullscreenButtonHint)':
        r'QtCore.Qt.WindowType.\1',
    
    # Qt.WindowState
    r'QtCore\.Qt\.(WindowNoState|WindowMinimized|WindowMaximized|WindowFullScreen|WindowActive)':
        r'QtCore.Qt.WindowState.\1',
    
    # Qt.FocusPolicy
    r'QtCore\.Qt\.(NoFocus|TabFocus|ClickFocus|StrongFocus|WheelFocus)':
        r'QtCore.Qt.FocusPolicy.\1',
    
    # Qt.CheckState
    r'QtCore\.Qt\.(Unchecked|PartiallyChecked|Checked)':
        r'QtCore.Qt.CheckState.\1',
    
    # Qt.SortOrder
    r'QtCore\.Qt\.(AscendingOrder|DescendingOrder)':
        r'QtCore.Qt.SortOrder.\1',
    
    # QDockWidget.DockWidgetFeature
    r'QtWidgets\.QDockWidget\.(DockWidgetClosable|DockWidgetMovable|DockWidgetFloatable|'
    r'DockWidgetVerticalTitleBar|AllDockWidgetFeatures|NoDockWidgetFeatures)':
        r'QtWidgets.QDockWidget.DockWidgetFeature.\1',
    
    # Qt.DockWidgetArea
    r'QtCore\.Qt\.(LeftDockWidgetArea|RightDockWidgetArea|TopDockWidgetArea|BottomDockWidgetArea|'
    r'AllDockWidgetAreas|NoDockWidgetArea)':
        r'QtCore.Qt.DockWidgetArea.\1',
    
    # Qt.ToolBarArea
    r'QtCore\.Qt\.(LeftToolBarArea|RightToolBarArea|TopToolBarArea|BottomToolBarArea|'
    r'AllToolBarAreas|NoToolBarArea)':
        r'QtCore.Qt.ToolBarArea.\1',
    
    # QFont.Weight
    r'QtGui\.QFont\.(Thin|ExtraLight|Light|Normal|Medium|DemiBold|Bold|ExtraBold|Black)':
        r'QtGui.QFont.Weight.\1',
    
    # QTextFormat.Property
    r'QtGui\.QTextFormat\.(ObjectIndex|CssFloat|LayoutDirection|OutlinePen|BackgroundBrush|'
    r'ForegroundBrush|BackgroundImageUrl|BlockAlignment|BlockTopMargin|BlockBottomMargin|'
    r'BlockLeftMargin|BlockRightMargin|TextIndent|TabPositions|BlockIndent|LineHeight|'
    r'LineHeightType|BlockNonBreakableLines|BlockTrailingHorizontalRulerWidth|BlockQuoteLevel|'
    r'BlockCodeLanguage|BlockCodeFence|BlockMarker|FirstFontProperty|FontFamily|FontPointSize|'
    r'FontSizeAdjustment|FontSizeIncrement|FontWeight|FontItalic|FontUnderline|FontOverline|'
    r'FontStrikeOut|FontFixedPitch|FontPixelSize|FontLetterSpacing|FontWordSpacing|'
    r'FontCapitalization|FontLetterSpacingType|FontStretch|FontStyleHint|FontStyleStrategy|'
    r'FontKerning|FontHintingPreference|FontFamilies|FontStyleName|LastFontProperty|'
    r'TextOutline|TextUnderlineColor|TextVerticalAlignment|TextUnderlineStyle|TextToolTip|'
    r'IsAnchor|AnchorHref|AnchorName|ObjectType|ListStyle|ListIndent|ListNumberPrefix|'
    r'ListNumberSuffix|FrameBorder|FrameMargin|FramePadding|FrameWidth|FrameHeight|'
    r'FrameTopMargin|FrameBottomMargin|FrameLeftMargin|FrameRightMargin|FrameBorderBrush|'
    r'FrameBorderStyle|TableColumns|TableColumnWidthConstraints|TableCellSpacing|'
    r'TableCellPadding|TableHeaderRowCount|TableBorderCollapse|ImageName|ImageWidth|'
    r'ImageHeight|ImageQuality|FullWidthSelection|PageBreakPolicy|UserProperty)':
        r'QtGui.QTextFormat.Property.\1',
    
    # QKeySequence.StandardKey
    r'QtGui\.QKeySequence\.(Open|Close|Save|New|Delete|Cut|Copy|Paste|Undo|Redo|Back|Forward|'
    r'Refresh|ZoomIn|ZoomOut|Print|AddTab|NextChild|PreviousChild|Find|FindNext|FindPrevious|'
    r'Replace|SelectAll|Bold|Italic|Underline|MoveToNextChar|MoveToPreviousChar|MoveToNextWord|'
    r'MoveToPreviousWord|MoveToNextLine|MoveToPreviousLine|MoveToNextPage|MoveToPreviousPage|'
    r'MoveToStartOfLine|MoveToEndOfLine|MoveToStartOfBlock|MoveToEndOfBlock|MoveToStartOfDocument|'
    r'MoveToEndOfDocument|SelectNextChar|SelectPreviousChar|SelectNextWord|SelectPreviousWord|'
    r'SelectNextLine|SelectPreviousLine|SelectNextPage|SelectPreviousPage|SelectStartOfLine|'
    r'SelectEndOfLine|SelectStartOfBlock|SelectEndOfBlock|SelectStartOfDocument|SelectEndOfDocument|'
    r'DeleteStartOfWord|DeleteEndOfWord|DeleteEndOfLine|InsertParagraphSeparator|InsertLineSeparator|'
    r'SaveAs|Preferences|Quit|FullScreen|Deselect|DeleteCompleteLine|Backspace|Cancel|'
    r'HelpContents|WhatsThis|Print)':
        r'QtGui.QKeySequence.StandardKey.\1',
}

def migrate_file(filepath: Path, dry_run: bool = False):
    """迁移单个文件"""
    try:
        content = filepath.read_text(encoding='utf-8')
        original_content = content
        
        # 首先处理 QAction 和 QShortcut 的移动（从 QtWidgets 到 QtGui）
        content = re.sub(r'QtWidgets\.QAction\b', 'QtGui.QAction', content)
        content = re.sub(r'QtWidgets\.QShortcut\b', 'QtGui.QShortcut', content)
        content = re.sub(r'QtWidgets\.QActionGroup\b', 'QtGui.QActionGroup', content)
        
        # 应用所有迁移规则
        for pattern, replacement in ENUM_MIGRATIONS.items():
            content = re.sub(pattern, replacement, content)
        
        # 检查是否有改动
        if content != original_content:
            if dry_run:
                print(f"  [DRY RUN] 将修改: {filepath}")
                # 显示差异
                lines_before = original_content.split('\n')
                lines_after = content.split('\n')
                for i, (before, after) in enumerate(zip(lines_before, lines_after)):
                    if before != after:
                        print(f"    Line {i+1}:")
                        print(f"      - {before}")
                        print(f"      + {after}")
            else:
                filepath.write_text(content, encoding='utf-8')
                print(f"  ✅ 已修改: {filepath}")
            return True
        else:
            print(f"  ⏭️  无需修改: {filepath}")
            return False
            
    except Exception as e:
        print(f"  ❌ 错误: {filepath}: {e}")
        return False

def main():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(description='PyQt5 到 PyQt6 自动迁移脚本')
    parser.add_argument('path', nargs='?', default='trace_viewer',
                        help='要迁移的目录或文件路径（默认: trace_viewer）')
    parser.add_argument('--dry-run', action='store_true',
                        help='仅显示将要做的更改，不实际修改文件')
    
    args = parser.parse_args()
    
    target_path = Path(args.path)
    
    if not target_path.exists():
        print(f"❌ 路径不存在: {target_path}")
        sys.exit(1)
    
    print(f"{'🔍 [DRY RUN] ' if args.dry_run else '🚀 '}开始迁移 PyQt5 → PyQt6")
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

