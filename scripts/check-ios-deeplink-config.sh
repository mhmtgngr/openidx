#!/usr/bin/env bash
# A workflow step that materializes the iOS runner must register the URL scheme
# afterwards, or the build it produces cannot receive the OAuth redirect.
#
# WHY THIS IS A GUARD AND NOT A COMMENT. `flutter create --platforms=ios …`
# regenerates ios/ from Flutter's template on every job, and the template has no
# CFBundleURLTypes. So the registration is not a property of the repository, it
# is a step someone has to remember, in five places today and six the next time
# a job needs an iOS runner. Forgetting it is silent in every direction: the
# build compiles, `flutter analyze` passes, the .ipa is produced and attached to
# the release, and the failure appears only on a device, at the end of a login,
# as a browser that never comes back.
#
# This is the same shape as check-macos-pod-priming.sh, which exists because a
# macOS Flutter build must create its CocoaPods spec source FIRST. Same rule
# here, mirrored: the configure step must come AFTER the create step, because
# there is nothing to patch before it.
#
# WHAT IS NOT A FINDING:
#   - `flutter create` without ios in --platforms (the desktop matrix).
#   - A step whose --platforms is a workflow expression the shell expands at run
#     time: it is reported, not failed, because this cannot know what it holds.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

ENFORCE=0
[ "${1:-}" = "--enforce" ] && ENFORCE=1

FILES="${CHECK_IOS_DEEPLINK_FILES:-$(ls .github/workflows/*.yml 2>/dev/null)}"

python3 - "$ENFORCE" $FILES <<'PYEOF'
import re, sys, yaml

enforce = sys.argv[1] == "1"
paths = sys.argv[2:]

CREATE = re.compile(r'flutter\s+create\b[^\n]*')
PLATFORMS = re.compile(r'--platforms[= ]([^\s]+)')
CONFIGURE = re.compile(r'scripts/ci-configure-ios-deeplinks\.sh')

findings = 0
checked = 0

for path in paths:
    try:
        doc = yaml.safe_load(open(path))
    except Exception as e:
        print("%s: could not parse (%s)" % (path, e))
        continue
    if not isinstance(doc, dict):
        continue
    for job_name, job in (doc.get("jobs") or {}).items():
        if not isinstance(job, dict):
            continue
        steps = job.get("steps") or []
        for i, step in enumerate(steps):
            run = step.get("run")
            if not isinstance(run, str):
                continue
            m = CREATE.search(run)
            if not m:
                continue
            plats = PLATFORMS.search(m.group(0))
            if not plats:
                continue
            value = plats.group(1)
            if "${{" in value:
                print("%s: job %s, step %r materializes platforms from an expression (%s);"
                      % (path, job_name, step.get("name", "?"), value))
                print("    this guard cannot tell whether iOS is among them. If it can be, call")
                print("    scripts/ci-configure-ios-deeplinks.sh after it.")
                continue
            if "ios" not in value.split(","):
                continue

            checked += 1
            # The registration must come after the create, in this step or a
            # later one in the same job. Before it there is no plist to patch.
            later = "\n".join(
                [run[m.end():]] + [s.get("run", "") for s in steps[i + 1:] if isinstance(s.get("run"), str)]
            )
            if CONFIGURE.search(later):
                continue
            findings += 1
            print("%s: job %s, step %r" % (path, job_name, step.get("name", "?")))
            print("    %s" % m.group(0).strip()[:100])
            print("    materializes the iOS runner and nothing afterwards registers the URL")
            print("    scheme, so openidx://oauth-callback cannot reach the app this job builds.")
            print("    Add, after it:  bash scripts/ci-configure-ios-deeplinks.sh")

if checked == 0 and findings == 0:
    print("check-ios-deeplink-config: no workflow step materializes an iOS runner. "
          "Either the client stopped building for iOS or this guard is looking in the "
          "wrong place; both are worth knowing, so this is not a silent pass.",
          file=sys.stderr)
    sys.exit(1 if enforce else 0)

if findings == 0:
    print("check-ios-deeplink-config: ok — %d iOS-materializing step(s), every one "
          "followed by the URL-scheme registration" % checked)
    sys.exit(0)

print()
print("check-ios-deeplink-config: %d iOS runner(s) built without a registered URL scheme"
      % findings, file=sys.stderr)
sys.exit(1 if enforce else 0)
PYEOF
