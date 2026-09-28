#!/usr/bin/env bash
# Guard: every nginx configuration that serves the admin console sends a
# Content-Security-Policy that refuses injected script, from every location
# that answers with the console's own files.
#
# Why this is a guard. The console keeps its access and refresh tokens in
# localStorage, so any script that runs in its origin can take them. It was
# served with no policy at all, and the email-template preview put one
# administrator's HTML into the page: every other administrator who opened it,
# platform admins among them, ran that HTML's script and handed over their
# tokens. The preview is fixed, but the policy is what stops the next
# injection, wherever it comes from, and it only works where it is sent. nginx
# makes it easy to lose: add_header in a location replaces the whole set the
# location would inherit, so a block that adds Cache-Control drops the policy
# without a word. So the check is per location, computed the way nginx
# computes it.
#
# A config serves the console when one of its servers has a location whose
# try_files falls back to /index.html (the SPA's router), or proxies to the
# admin-console upstream. A config that serves some other single-page app goes
# in NOT_THE_CONSOLE below, with its reason.
#
# In such a server, a location answers with the console's files unless it
# returns, or passes the request to something other than the console (the
# APIs, OAuth and SAML pages, Guacamole: those keep their own policies, and
# the console's would break a SAML form post). For each location that does,
# the Content-Security-Policy nginx will send -- the location's own add_header
# set if it has one, the nearest enclosing level's otherwise -- must:
#   - be sent `always`: the SPA fallback answers 404s with index.html;
#   - name script-src with 'self', and nothing but ALLOWED_SCRIPT_SOURCES: no
#     'unsafe-inline' (inline script is what injected markup runs), no
#     'unsafe-eval', no wildcard, scheme or other host;
#   - carry object-src 'none', base-uri and form-action 'self' (or 'none'),
#     and frame-ancestors 'none' or 'self'.
# connect-src, img-src and the rest are left to each config: they decide what
# the console can load, not what script can run.
#
# It also checks the wiring: the file the console image copies into
# /etc/nginx (Dockerfile.admin-console), and any file a compose file mounts
# over the image's default.conf, must be files it checked.
#
# Not covered: the Helm chart runs the console image, so the image's config
# speaks for it, and ingress-nginx passes the header through. A web server an
# operator puts in front is theirs to configure; docs/THREAT-MODEL.md says so.
#
# Usage: scripts/check-console-csp.sh [--enforce]
#   CONSOLE_CSP_ROOT  tree to scan (default: the repository); the self-test
#                     points it at fixtures.
# Default: warn (exit 0). --enforce: exit 1 on any offender.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
ROOT="${CONSOLE_CSP_ROOT:-$PWD}"
ENFORCE=0; [ "${1:-}" = "--enforce" ] && ENFORCE=1

python3 - "$ROOT" "$ENFORCE" <<'PYEOF'
import os
import re
import sys

root, enforce = sys.argv[1], sys.argv[2] == "1"

SKIP_DIRS = {".git", "node_modules", "dist", "coverage", "playwright-report", "test-results"}

# Configs that serve a single-page app that is not the console.
NOT_THE_CONSOLE = {
    "cmd/simple-web/nginx.conf": "the demo web app, not the console",
}

# script-src may name these and nothing else. The second is Cloudflare
# Turnstile, which the login page renders when the bot gate asks for a
# challenge (deployments/docker/turnstile_csp_test.go keeps it where it is
# needed and nowhere else).
ALLOWED_SCRIPT_SOURCES = {"'self'", "https://challenges.cloudflare.com"}

CONSOLE_UPSTREAM = re.compile(r"^https?://admin[-_]console(?:[:/]|$)", re.I)
OTHER_HANDLERS = ("fastcgi_pass", "uwsgi_pass", "scgi_pass", "grpc_pass", "memcached_pass")


class Block:
    def __init__(self, name, args, parent):
        self.name, self.args, self.parent = name, args, parent
        self.directives = []  # (name, args)
        self.children = []

    def get(self, name):
        return [a for n, a in self.directives if n == name]


def tokenize(text):
    toks, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if c.isspace():
            i += 1
        elif c == "#":
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif c in "{};":
            toks.append(("P", c))
            i += 1
        elif c in "\"'":
            j, buf = i + 1, []
            while j < n and text[j] != c:
                if text[j] == "\\" and j + 1 < n:
                    buf.append(text[j + 1])
                    j += 2
                    continue
                buf.append(text[j])
                j += 1
            if j >= n:
                raise ValueError("unterminated string")
            toks.append(("W", "".join(buf)))
            i = j + 1
        else:
            j = i
            while j < n and not text[j].isspace() and text[j] not in "{};":
                j += 1
            toks.append(("W", text[i:j]))
            i = j
    return toks


def parse(text):
    top = Block("main", [], None)
    stack, words = [top], []
    for kind, tok in tokenize(text):
        if kind == "W":
            words.append(tok)
        elif tok == "{":
            if not words:
                raise ValueError("block without a name")
            b = Block(words[0], words[1:], stack[-1])
            stack[-1].children.append(b)
            stack.append(b)
            words = []
        elif tok == ";":
            if words:
                stack[-1].directives.append((words[0], words[1:]))
            words = []
        else:  # "}"
            if words or len(stack) == 1:
                raise ValueError("unbalanced braces")
            stack.pop()
    if words or len(stack) != 1:
        raise ValueError("unbalanced braces")
    return top


def walk(block, name):
    for ch in block.children:
        if ch.name == name:
            yield ch
        yield from walk(ch, name)


def locations(block):
    for ch in block.children:
        if ch.name == "location":
            yield ch
            yield from locations(ch)


def inherited(block, directive):
    """The value of a directive nginx inherits: the nearest level setting it."""
    b = block
    while b is not None:
        vals = b.get(directive)
        if vals:
            return vals
        b = b.parent
    return []


def headers(block):
    """The add_header set nginx sends from this block."""
    b = block
    while b is not None:
        own = b.get("add_header")
        if own:
            return own
        b = b.parent
    return []


def proxy_target(loc):
    passes = loc.get("proxy_pass")
    if not passes or not passes[-1]:
        return None
    target = passes[-1][0]
    m = re.match(r"^\$\{?(\w+)\}?", target)
    if m:  # proxy_pass $upstream: take the `set` that gives it a value
        b = loc
        while b is not None:
            for args in b.get("set"):
                if len(args) == 2 and args[0] in ("$" + m.group(1), "${%s}" % m.group(1)):
                    return args[1]
            b = b.parent
    return target


def spa_fallback(loc):
    return any(args and args[-1] == "/index.html" for args in loc.get("try_files"))


def serves_console(loc, console_roots):
    """True when this location answers with the console's own files."""
    if loc.get("return"):
        return False
    if any(loc.get(h) for h in OTHER_HANDLERS):
        return False
    target = proxy_target(loc)
    if target is not None:
        return bool(CONSOLE_UPSTREAM.match(target))
    if loc.get("alias"):
        return False
    root_args = inherited(loc, "root")
    return bool(root_args) and root_args[-1][0] in console_roots


def policy_problems(value):
    dirs = {}
    for part in value.split(";"):
        words = part.split()
        if words:
            dirs.setdefault(words[0].lower(), [w.lower() for w in words[1:]])
    probs = []
    script = dirs.get("script-src")
    if script is None:
        probs.append("no script-src")
    else:
        if "'self'" not in script:
            probs.append("script-src does not name 'self'")
        extra = [s for s in script if s not in ALLOWED_SCRIPT_SOURCES]
        if extra:
            probs.append("script-src also allows " + " ".join(extra))
    if dirs.get("object-src") != ["'none'"]:
        probs.append("object-src is not 'none'")
    for d in ("base-uri", "form-action"):
        if dirs.get(d) not in (["'self'"], ["'none'"]):
            probs.append("%s is not 'self' or 'none'" % d)
    if dirs.get("frame-ancestors") not in (["'none'"], ["'self'"]):
        probs.append("frame-ancestors is not 'none' or 'self'")
    return probs


def csp_verdict(block):
    """None when the block sends a policy that holds, else what is wrong."""
    csps = [a for a in headers(block) if a and a[0].lower() == "content-security-policy"]
    if not csps:
        return "sends no Content-Security-Policy"
    best = None
    for args in csps:
        probs = policy_problems(args[1] if len(args) > 1 else "")
        if "always" not in args[2:]:
            probs.append("not sent `always`, so error pages go without it")
        if not probs:
            return None
        if best is None or len(probs) < len(best):
            best = probs
    return "; ".join(best)


def nginx_files():
    for dp, dns, fns in os.walk(root):
        dns[:] = sorted(d for d in dns if d not in SKIP_DIRS)
        for fn in sorted(fns):
            if fn.endswith((".conf", ".conf.template")):
                yield os.path.join(dp, fn)


def rel(p):
    return os.path.relpath(p, root)


def describe(loc):
    return "location " + " ".join(loc.args) if loc.name == "location" else loc.name


offenders, checked_files, checked_locs = [], set(), 0

for path in nginx_files():
    r = rel(path)
    try:
        text = open(path, encoding="utf-8").read()
    except (OSError, UnicodeDecodeError):
        continue
    looks_like_console = ("try_files" in text and "/index.html" in text) or re.search(r"admin[-_]console", text)
    try:
        tree = parse(text)
    except ValueError as exc:
        if looks_like_console and r not in NOT_THE_CONSOLE:
            offenders.append("%s: cannot be read as nginx configuration (%s)" % (r, exc))
        continue

    servers = list(walk(tree, "server"))
    console_servers = []
    for srv in servers:
        locs = list(locations(srv))
        roots = {inherited(l, "root")[-1][0] for l in locs if spa_fallback(l) and inherited(l, "root")}
        proxied = any(CONSOLE_UPSTREAM.match(proxy_target(l) or "") for l in locs)
        if roots or proxied:
            console_servers.append((srv, locs, roots))
    if not console_servers:
        continue
    if r in NOT_THE_CONSOLE:
        continue
    checked_files.add(r)

    for srv, locs, roots in console_servers:
        for loc in locs:
            if not serves_console(loc, roots):
                continue
            checked_locs += 1
            verdict = csp_verdict(loc)
            if verdict:
                offenders.append("%s: %s: %s" % (r, describe(loc), verdict))

# The wiring: what the console image and the compose files actually install.
def wired(src, where):
    if src not in checked_files:
        offenders.append("%s installs %s as the console's nginx configuration, and this guard "
                         "does not see that file serving the console" % (where, src))

dockerfile = os.path.join(root, "deployments/docker/Dockerfile.admin-console")
if os.path.exists(dockerfile):
    for line in open(dockerfile, encoding="utf-8"):
        words = line.split()
        if len(words) >= 3 and words[0].upper() in ("COPY", "ADD") and not any(w.startswith("--from") for w in words[1:]):
            srcs, dest = [w for w in words[1:-1] if not w.startswith("--")], words[-1]
            if dest.startswith("/etc/nginx"):
                for s in srcs:
                    wired(os.path.normpath(s), rel(dockerfile))

compose_dir = os.path.join(root, "deployments/docker")
if os.path.isdir(compose_dir):
    mount = re.compile(r"^\s*-\s*[\"']?([^\s:\"']+):/etc/nginx/conf\.d/default\.conf(?::ro)?[\"']?\s*$")
    for fn in sorted(os.listdir(compose_dir)):
        if fn.startswith("docker-compose") and fn.endswith((".yml", ".yaml")):
            p = os.path.join(compose_dir, fn)
            for line in open(p, encoding="utf-8"):
                m = mount.match(line)
                if m:
                    wired(rel(os.path.normpath(os.path.join(compose_dir, m.group(1)))), rel(p))

for o in offenders:
    print("offender: " + o)
print("console-csp: %d config(s) serve the console, %d location(s) checked, %d offender(s)"
      % (len(checked_files), checked_locs, len(offenders)))

# A rule that matches nothing passes forever.
if not checked_files:
    print("console-csp: no nginx configuration serving the console was found; the guard no")
    print("  longer recognises how the console is served and is checking nothing. Update it.")
    sys.exit(1 if enforce else 0)
sys.exit(1 if enforce and offenders else 0)
PYEOF
