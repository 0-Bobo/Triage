"""Color palette, mnemonic colors, and visual constants."""

# ── UI Color Palette ────────────────────────────────────────────────
C = {
    'bg': '#0d1117', 'mantle': '#161b22', 'crust': '#0d1117',
    'surface0': '#21262d', 'surface1': '#30363d', 'surface2': '#484f58',
    'overlay0': '#6e7681', 'overlay1': '#8b949e',
    'text': '#e6edf3', 'subtext1': '#b0b8c4', 'subtext0': '#8b949e',
    'red': '#ff7b72', 'maroon': '#ffa198', 'orange': '#d29922',
    'yellow': '#d29922', 'green': '#3fb950', 'teal': '#56d4dd',
    'sky': '#79c0ff', 'blue': '#58a6ff', 'lavender': '#bc8cff',
    'mauve': '#bc8cff', 'pink': '#f778ba',
}

# ── Disassembly Mnemonic Colors (IntelliJ Dark / Ghidra style) ────
MNEMONIC_COLORS = {
    'call': '#58a6ff', 'callq': '#58a6ff',
    'ret': '#3fb950', 'retq': '#3fb950',
    'jmp': '#ff7b72', 'je': '#ff7b72', 'jne': '#ff7b72',
    'jz': '#ff7b72', 'jnz': '#ff7b72',
    'jg': '#ff7b72', 'jl': '#ff7b72', 'jge': '#ff7b72', 'jle': '#ff7b72',
    'ja': '#ff7b72', 'jb': '#ff7b72',
    'push': '#d2a8ff', 'pop': '#d2a8ff',
    'mov': '#e6edf3', 'movzx': '#e6edf3', 'movsx': '#e6edf3', 'lea': '#e6edf3',
    'xor': '#f778ba', 'add': '#79c0ff', 'sub': '#79c0ff', 'imul': '#79c0ff',
    'and': '#f778ba', 'or': '#f778ba', 'shr': '#79c0ff', 'shl': '#79c0ff',
    'cmp': '#bc8cff', 'test': '#bc8cff',
    'nop': '#484f58', 'int': '#ff7b72',
    'syscall': '#3fb950', 'hlt': '#ff7b72',
}
DEFAULT_MNEMONIC_COLOR = '#e6edf3'

# ── Vulnerability Severity Colors ─────────────────────────────────
VULN_SEVERITY_COLORS = {
    'CRITICAL': '#ff7b72',
    'HIGH': '#ffa198',
    'MEDIUM': '#d29922',
    'LOW': '#3fb950',
}


def prot_color(v: str) -> str:
    """Map protection status string to a hex color."""
    if 'Enabled' in v or 'Full' in v:
        return '#3fb950'
    if 'YES' in v:
        return '#ff7b72'
    if 'Disabled' in v or 'None' in v or 'Partial' in v:
        return '#d29922'
    return '#8b949e'
