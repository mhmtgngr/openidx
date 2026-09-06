#!/usr/bin/env bash
# Guard: every form control must have an accessible name.
#
# WHY: a screen reader announces a control by its name and its role. With no
# name it says "combo box", "edit text", "switch" -- and nothing else. This
# console had 260 controls in that state, and the reason none of them showed up
# in the axe page sweep is that almost every form here lives inside a dialog,
# and a dialog body is not mounted until it is opened. A rendering gate cannot
# see them; a source scan can.
#
# 215 of the 260 already had a visible label sitting right beside them -- it
# simply was not associated, so a sighted user saw a labelled form and a
# screen-reader user heard an anonymous one. That is why this check accepts an
# htmlFor/id association and does not demand aria-label: the visible label IS
# the name, and tying the two together is better than adding a second, hidden
# one that can drift away from it.
#
# A control counts as named if it has any of:
#   - aria-label, aria-labelledby, or title
#   - an id that some htmlFor in the same file points at (including the
#     template-literal form, `id={`row-${item.id}`}`, which is how a control
#     inside a loop stays uniquely associated)
#   - a wrapping <label>...</label>
#   - a placeholder -- inputs and textareas only. axe's `label` rule accepts a
#     placeholder, so this stays consistent with the gate that runs in CI; it
#     is a weak name (it disappears as soon as you type) but it is a name.
#     A Radix SelectTrigger is a <button>: a placeholder inside its SelectValue
#     names nothing once a value is chosen, so it does not count here.
#
# It also reports the reverse defect: an htmlFor pointing at an id that no
# element carries. That one is worth catching on its own, because it reads as
# correct in review and names nothing at runtime.
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

# Radix triggers render a <button>; the natives are self-explanatory.
CONTROLS = ('SelectTrigger', 'Input', 'Textarea', 'Switch', 'Checkbox',
            'select', 'input', 'textarea')
CTRL = re.compile(r'<(' + '|'.join(CONTROLS) + r')(?=[\s/>])')
# A placeholder is a name for these and not for the others.
PLACEHOLDER_NAMES = {'Input', 'input', 'Textarea', 'textarea'}
# Not user-facing controls: no name to give.
SKIP_TYPES = re.compile(r'type=["\{]\s*["\']?(hidden|submit|button|checkbox|radio)')
ANY_TAG = re.compile(r'<([A-Za-z][A-Za-z0-9]*)(?=[\s/>])')
LABEL_OPEN = re.compile(r'<(Label|label)(?=[\s/>])')


def strip_comments(text):
    """Blank out // and /* */ comments, preserving offsets and line numbers.

    Without this the scanner reads prose as code -- a doc comment that quotes
    `<Input />` to explain a rule would be reported as an offender. Quotes and
    template literals are tracked so a `https://` inside a string survives.
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
    """Attribute text of the JSX tag whose name ends at `i`, plus the '>' offset.

    A regex cannot do this: `onChange={(e) => f(e)}` contains a '>' inside the
    arrow, so any pattern ending at the first '>' truncates the attribute list
    and every attribute after the first handler goes unseen -- which is exactly
    how an earlier guard in this repo reported correct code as broken.
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
            return text[i:j], j
        j += 1
    return None, None


def attr_value(attrs, name):
    """Verbatim value of one attribute: "x", {'x'} and {`row-${id}`} all work.

    The template-literal form matters. An id built in a loop is still an id,
    and the htmlFor naming it is written the same way, so comparing the
    expression TEXT is what lets the two match. A matcher that only reads
    [A-Za-z0-9_-] misses every dynamic pair and reports correctly-labelled
    controls as offenders.
    """
    m = re.search(r'\b' + re.escape(name) + r'\s*=\s*', attrs)
    if not m:
        return None
    i = m.end()
    if i >= len(attrs):
        return None
    c = attrs[i]
    if c in '"\'':
        j = attrs.find(c, i + 1)
        return attrs[i + 1:j] if j > 0 else None
    if c == '{':
        depth = 0
        j = i
        while j < len(attrs):
            if attrs[j] == '{':
                depth += 1
            elif attrs[j] == '}':
                depth -= 1
                if depth == 0:
                    break
            j += 1
        inner = attrs[i + 1:j].strip()
        if len(inner) >= 2 and inner[0] == inner[-1] and inner[0] in '"\'`' and '${' not in inner:
            inner = inner[1:-1]
        return re.sub(r'\s+', '', inner)
    return None


def all_ids(text):
    """Every id in the file, from ANY element -- a custom component such as
    <SecretField id="client_secret"> forwards its id to a real control, so a
    label pointing at it is correctly associated."""
    out = set()
    for m in ANY_TAG.finditer(text):
        a, _ = attrs_of(text, m.end())
        if a is None:
            continue
        v = attr_value(a, 'id')
        if v:
            out.add(v)
    return out


def wrapped_in_label(text, pos):
    last = max(text.rfind('<label', 0, pos), text.rfind('<Label', 0, pos))
    if last < 0:
        return False
    ends = [c for c in (text.find('</label>', last), text.find('</Label>', last)) if c >= 0]
    return bool(ends) and min(ends) > pos


files = []
for dirpath, _, filenames in os.walk(src_dir):
    for fn in sorted(filenames):
        if fn.endswith(('.tsx', '.jsx')) and not fn.endswith(('.test.tsx', '.test.jsx')):
            files.append(os.path.join(dirpath, fn))

offenders = 0
for path in sorted(files):
    with open(path, encoding='utf-8') as fh:
        text = strip_comments(fh.read())
    ids = all_ids(text)
    fors = set()
    for m in LABEL_OPEN.finditer(text):
        a, _ = attrs_of(text, m.end())
        if a is None:
            continue
        v = attr_value(a, 'htmlFor')
        if v:
            fors.add(v)
            if v not in ids:
                line = text[:m.start()].count('\n') + 1
                print(f'offender: {path}:{line}  <label htmlFor="{v}"> names no element')
                offenders += 1

    for m in CTRL.finditer(text):
        tag = m.group(1)
        attrs, _ = attrs_of(text, m.end())
        if attrs is None:
            continue
        if tag in ('Input', 'input') and SKIP_TYPES.search(attrs):
            continue
        if any(k in attrs for k in ('aria-label', 'aria-labelledby', 'title=')):
            continue
        if tag in PLACEHOLDER_NAMES and 'placeholder' in attrs:
            continue
        v = attr_value(attrs, 'id')
        if v is not None and v in fors:
            continue
        if wrapped_in_label(text, m.start()):
            continue
        line = text[:m.start()].count('\n') + 1
        print(f'offender: {path}:{line}  <{tag}> has no accessible name')
        offenders += 1

print(f'unnamed-controls offenders: {offenders}')
sys.exit(1 if offenders else 0)
PY
rc=$?

if [ "$rc" = 2 ]; then
  echo "error: scan failed" >&2
  exit 2
fi
if [ "$ENFORCE" = 1 ] && [ "$rc" != 0 ]; then exit 1; fi
exit 0
