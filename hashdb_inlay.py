"""Display-only suffix annotations for Hex-Rays pseudocode."""


import re
import traceback

import ida_hexrays as hx
import ida_kernwin as kw
import ida_lines as lines


_NUMBER = re.compile(
    r"\s*[+-]?(?:0[xX][0-9a-fA-F]+|0[bB][01]+|[0-9]+)"
    r"(?:[uU][iI]64|[iI]64|[uU][lL]{1,2}|[lL]{1,2}[uU]?|[uU])?"
    r"(?![\w.])"
)


_ANCHOR = re.compile(
    re.escape(lines.SCOLOR_ON + lines.SCOLOR_ADDR)
    + r"([0-9a-fA-F]{%d})" % lines.COLOR_ADDR_SIZE
)


_COMMENT_COLORS = {lines.SCOLOR_AUTOCMT, lines.SCOLOR_REGCMT,
                   lines.SCOLOR_RPTCMT}


def _literal_end(text, start, end):
    """Map a visible numeric token's end back to a raw tagged-line offset.

    Ignore existing comment-colored prefixes (e.g. HexInlay's argument name).
    Keep all original tags, including the number's closing color tag.
    """
    visible, offsets, stack = [], [], []
    pos = start
    while pos < end:
        ch = text[pos]
        if ch in (lines.SCOLOR_ON, lines.SCOLOR_OFF) and pos + 1 < end:
            color = text[pos + 1]
            if ch == lines.SCOLOR_ON:
                stack.append(color)
            elif color in stack:
                # Tags normally nest, but tolerate other decorators' output.
                stack.pop(len(stack) - 1 - stack[::-1].index(color))
            pos += 2
            continue
        if ch == lines.SCOLOR_INV:
            pos += 1
            continue
        quoted = ch == lines.SCOLOR_ESC and pos + 1 < end
        if quoted:
            pos += 1
            ch = text[pos]
        if not any(color in _COMMENT_COLORS for color in stack):
            visible.append(ch)
            offsets.append(pos + 1)
        pos += 1
    match = _NUMBER.match("".join(visible))
    if not match:
        return None
    pos = offsets[match.end() - 1]
    # Finish the numeric color span before starting the hint's color span.
    while text.startswith(lines.SCOLOR_OFF, pos) and pos + 1 < end:
        pos += 2
    return pos


def decorate_line(text, index_to_suffix):
    """Pure string transformation; never changes or removes ctree anchors."""
    anchors = list(_ANCHOR.finditer(text))
    edits = []
    for n, anchor in enumerate(anchors):
        value = int(anchor.group(1), 16)
        if value & hx.ANCHOR_MASK != hx.ANCHOR_CITEM:
            continue
        suffix = index_to_suffix.get(value & hx.ANCHOR_INDEX)
        if suffix is None:
            continue
        end = anchors[n + 1].start() if n + 1 < len(anchors) else len(text)
        insertion = _literal_end(text, anchor.end(), end)
        if insertion is not None:
            edits.append((insertion, suffix))
    for pos, suffix in reversed(edits):
        text = text[:pos] + suffix + text[pos:]
    return text


def _number_key(expr):
    bits = int(expr.type.get_size()) * 8
    if bits not in (8, 16, 32, 64):
        return None
    return bits, int(expr.numval()) & ((1 << bits) - 1)


def _clean_label(text):
    # Do not allow a lookup result to inject line breaks or IDA color codes.
    text = " ".join(str(text).split())
    text = "".join(ch for ch in text if ord(ch) >= 32 and ord(ch) != 127)
    if not text:
        raise ValueError("Hint text must not be empty")
    return text[:240]


class _Hooks(hx.Hexrays_Hooks):
    def __init__(self, owner):
        super().__init__()
        self.owner = owner

    def func_printed(self, cfunc):
        try:
            self.owner.decorate(cfunc)
        except Exception:
            kw.msg("HashDB Decoration failed:\n" + traceback.format_exc())
        return 0

    def refresh_pseudocode(self, vu):
        # A view can reuse cached text without printing the function again.
        # We change characters only; this event forbids changing line counts.
        return self.func_printed(vu.cfunc) if vu.cfunc else 0


class HintRenderer:
    def __init__(self):
        self.hints = {}
        self.enabled = True
        self.style = "bare"
        self._owned_spans = set()
        self._hooks = _Hooks(self)
        self._busy = False
        self._running = False
        self._visited = set()

    def _suffix(self, label):
        suffix = lines.COLSTR(" " + label, lines.SCOLOR_AUTOCMT)
        self._owned_spans.add(suffix)
        return suffix

    def decorate(self, cfunc):
        if self._busy:
            return
        self._busy = True
        try:
            entry_ea = getattr(cfunc, "entry_ea", None)
            if entry_ea is not None:
                self._visited.add(entry_ea)
            ps = cfunc.get_pseudocode()
            mapping = {}
            if self.enabled:
                for index, item in enumerate(cfunc.treeitems):
                    if item.op == hx.cot_num:
                        label = self.hints.get(_number_key(item.cexpr))
                        if label is not None:
                            mapping[index] = self._suffix(label)
            for line in ps:
                original = line.line
                clean = original
                # Remove only exact colored spans previously emitted by us.
                # This also makes repeated callbacks and changing styles safe.
                for suffix in self._owned_spans:
                    clean = clean.replace(suffix, "")
                updated = decorate_line(clean, mapping) if mapping else clean
                if updated != original:
                    line.line = updated
        finally:
            self._busy = False

    def refresh(self):
        # Refresh generated text without redecompiling or changing ctree.
        # Standard Hex-Rays windows are named Pseudocode-A through -Z.
        widgets = [kw.get_current_widget()]
        widgets.extend(kw.find_widget("Pseudocode-" + c)
                       for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        seen = set()
        for widget in widgets:
            if not widget or kw.get_widget_type(widget) != kw.BWN_PSEUDOCODE:
                continue
            vu = hx.get_widget_vdui(widget)
            if vu and vu.view_idx not in seen:
                seen.add(vu.view_idx)
                vu.refresh_ctext(False)

    def toggle(self):
        self.enabled = not self.enabled
        self.refresh()
        kw.msg("HashDB %s\n" % ("Enabled" if self.enabled else "Hidden"))
        return self.enabled

    def stop(self):
        if not self._running:
            return
        self.enabled = False
        # Closed views can leave decorated functions in the decompiler cache.
        # Clean every visited function still cached, without forcing new work.
        for ea in tuple(self._visited):
            if hx.has_cached_cfunc(ea):
                cfunc = hx.decompile(ea)
                if cfunc:
                    self.decorate(cfunc)
        self.refresh()
        self._hooks.unhook()
        self._running = False
