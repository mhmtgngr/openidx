#!/usr/bin/env bash
# Guard: a control you can click must be a control you can reach with a
# keyboard. WHY: a bare `<div onClick={...}>` works with a mouse and is
# invisible to the keyboard — no tab stop, no key handler, no focus ring — so
# a keyboard-only operator simply cannot invoke it. Five pages in this console
# had exactly that on the row you click to select an item, and on those pages
# selecting the item was the only way to see any of its detail. WCAG 2.1.1
# (Keyboard) is a Level A criterion; this is the failure it names.
#
# An element passes if it is natively interactive (button, a[href], input,
# select, textarea, summary), or if it carries the full ARIA substitute:
# a role, a tabIndex, AND a key handler. Anything decorative that is
# deliberately not a tab stop must say so with aria-hidden — a modal scrim
# whose click is a shortcut for the close button is the honest case, and
# making it focusable would only add a nameless tab stop in front of the
# dialog. The rule is that skipping the keyboard has to be declared, not
# implied by omission.
#
# Prefer components/selectable-row.tsx over hand-rolling the ARIA pattern:
# Space must be preventDefault'd or it scrolls the page instead of activating
# the control, which is the detail that goes missing every time.
#
# Default: warn (print offenders + count, exit 0). --enforce: exit 1 if any.
# SH_SRC_DIR overrides the source dir (used by the paired .test.sh).
set -uo pipefail
cd "$(dirname "$0")/.."
SRC="${SH_SRC_DIR:-web/admin-console/src}"
ENFORCE=0; [ "${1:-}" = "--enforce" ] && ENFORCE=1

if [ ! -d "$SRC" ]; then
  echo "error: source dir not found: $SRC" >&2
  exit 2
fi

python3 - "$SRC" <<'PY'
import os, re, sys

src_dir = sys.argv[1]

# Elements with no interaction semantics of their own. A click handler on one
# of these is only reachable by pointer unless the ARIA pattern is completed.
NON_INTERACTIVE = {
    'div', 'span', 'li', 'tr', 'td', 'th', 'p', 'section', 'article',
    'header', 'footer', 'nav', 'aside', 'ul', 'ol', 'img', 'svg', 'label',
    'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'figure', 'figcaption', 'main',
}

TAG_START = re.compile(r'<([a-z][a-zA-Z0-9]*)(?=[\s/>])')


def strip_comments(text):
    """Blank out // and /* */ comments, preserving offsets and line numbers.

    Without this the scanner reads prose as code: the doc comment on
    SelectableRow explains the defect by quoting `<div onClick>`, and the first
    version of this check duly reported that sentence as an offender. Quotes
    and template literals are tracked so a `https://` inside a string is not
    mistaken for a comment.
    """
    out = list(text)
    i, n = 0, len(text)
    quote = None
    while i < n:
        c = text[i]
        if quote:
            if c == '\\':
                i += 2
                continue
            if c == quote:
                quote = None
            i += 1
            continue
        if c in '"\'`':
            quote = c
            i += 1
            continue
        if c == '/' and i + 1 < n and text[i + 1] == '/':
            while i < n and text[i] != '\n':
                out[i] = ' '
                i += 1
            continue
        if c == '/' and i + 1 < n and text[i + 1] == '*':
            while i < n and not (text[i] == '*' and i + 1 < n and text[i + 1] == '/'):
                if text[i] != '\n':
                    out[i] = ' '
                i += 1
            for _ in range(2):
                if i < n:
                    out[i] = ' '
                    i += 1
            continue
        i += 1
    return ''.join(out)


def attrs_of(text, i):
    """Return the attribute text of the JSX tag whose name ends at `i`.

    A regex cannot do this. `onClick={() => close()}` contains a `>` inside the
    arrow, so any pattern that ends at the first `>` truncates the attribute
    list and every attribute after the first handler goes unseen -- which made
    the first version of this check report its own SelectableRow, whose role
    and tabIndex sit after its onClick, as an offender. So scan instead,
    tracking brace depth and string state, and stop at the `>` that actually
    closes the tag.
    """
    depth = 0
    quote = None
    j = i
    n = len(text)
    while j < n:
        c = text[j]
        if quote:
            if c == '\\':
                j += 2
                continue
            if c == quote:
                quote = None
        elif c in '"\'`':
            quote = c
        elif c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
        elif c == '>' and depth == 0:
            return text[i:j]
        j += 1
    return None  # unterminated tag; treat as unparseable rather than guess

offenders = 0
files = []
for dirpath, _, filenames in os.walk(src_dir):
    for fn in sorted(filenames):
        if fn.endswith(('.tsx', '.jsx')) and not fn.endswith(('.test.tsx', '.test.jsx')):
            files.append(os.path.join(dirpath, fn))

for path in sorted(files):
    with open(path, encoding='utf-8') as fh:
        text = strip_comments(fh.read())
    for m in TAG_START.finditer(text):
        tag = m.group(1)
        if tag not in NON_INTERACTIVE:
            continue
        attrs = attrs_of(text, m.end())
        if attrs is None or 'onClick' not in attrs:
            continue
        # Declared decorative: not a tab stop on purpose.
        if 'aria-hidden' in attrs:
            continue
        has_role = 'role=' in attrs
        has_tab = 'tabIndex' in attrs
        has_key = any(k in attrs for k in ('onKeyDown', 'onKeyUp', 'onKeyPress'))
        if has_role and has_tab and has_key:
            continue
        missing = []
        if not has_role:
            missing.append('role')
        if not has_tab:
            missing.append('tabIndex')
        if not has_key:
            missing.append('onKeyDown')
        line = text[:m.start()].count('\n') + 1
        print(f'offender: {path}:{line}  <{tag} onClick> missing {", ".join(missing)}')
        offenders += 1

print(f'keyboard-unreachable offenders: {offenders}')
sys.exit(1 if offenders else 0)
PY
rc=$?

if [ "$rc" = 2 ]; then
  echo "error: scan failed" >&2
  exit 2
fi
if [ "$ENFORCE" = 1 ] && [ "$rc" != 0 ]; then exit 1; fi
exit 0
