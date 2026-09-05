#!/usr/bin/env bash
# Proves check-macos-pod-priming.sh can actually go RED.
#
# The guard's whole value is that it fires on the day someone adds a fourth
# macOS Flutter build and forgets the priming step -- a day that will look like
# every other day, because the CDN is usually up. So the cases that matter most
# are the two red ones: the missing step, and the step that is present but runs
# after the build and therefore primes nothing. The green cases exist because a
# guard that flags correct workflows gets deleted, and then it guards nothing.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECK="$ROOT/scripts/check-macos-pod-priming.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fail=0

t() { # name expected_rc file
  local name="$1" exp="$2" file="$3"
  bash "$CHECK" "$file" >/dev/null 2>&1
  local rc=$?
  if [ "$rc" = "$exp" ]; then
    echo "ok   $name (rc=$rc)"
  else
    echo "FAIL $name (rc=$rc, beklenen $exp)"; fail=$((fail + 1))
  fi
}

# The real workflows must pass. If this goes red a macOS Flutter build has lost
# its priming step for real, and the guard is doing its job.
t "gercek workflow'lar temiz" 0 "$ROOT/.github/workflows"

primed() { # name -> path, a compliant macOS iOS build
  cat > "$WORK/$1" <<'EOF'
jobs:
  build-ios:
    runs-on: macos-15
    steps:
      - uses: actions/checkout@v4
      - name: Prime the CocoaPods spec source
        run: bash scripts/ci-prime-cocoapods.sh
      - name: Build iOS
        working-directory: client
        run: flutter build ios --no-codesign --debug
EOF
  echo "$WORK/$1"
}

t "priming build'den once gecerli" 0 "$(primed ok.yml)"

# MUST GO RED: the step is gone. This is the drift the guard was written for.
f="$(primed missing.yml)"
python3 - "$f" <<'PY'
import sys
p = sys.argv[1]
keep = [l for l in open(p).read().split("\n")
        if "ci-prime-cocoapods.sh" not in l and "Prime the CocoaPods" not in l]
open(p, "w").write("\n".join(keep))
PY
t "eksik priming yakalanir" 1 "$f"

# MUST GO RED: present, but after the build -- CocoaPods has already created
# the source by then, so it primes nothing while looking like it does.
cat > "$WORK/late.yml" <<'EOF'
jobs:
  build-ios:
    runs-on: macos-15
    steps:
      - name: Build iOS
        run: flutter build ios --no-codesign --debug
      - name: Prime the CocoaPods spec source
        run: bash scripts/ci-prime-cocoapods.sh
EOF
t "build'den sonra priming yakalanir" 1 "$WORK/late.yml"

# GREEN: Android and Linux builds never reach CocoaPods, so an unprimed
# `flutter build` there is correct. The macOS job keeps the guard's subject
# alive so this case tests the exemption, not the empty-file path.
cat > "$WORK/android.yml" <<'EOF'
jobs:
  build-android:
    runs-on: ubuntu-latest
    steps:
      - name: Build APK
        run: flutter build apk --debug
  build-ios:
    runs-on: macos-15
    steps:
      - run: bash scripts/ci-prime-cocoapods.sh
      - run: flutter build ios --no-codesign
EOF
t "macOS olmayan flutter build muaf" 0 "$WORK/android.yml"

# GREEN: a matrix where only one leg is macOS. The priming step is guarded by
# an `if:` the guard cannot evaluate and deliberately does not try to.
cat > "$WORK/matrix.yml" <<'EOF'
jobs:
  build:
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        include:
          - os: macos-latest
            build_target: macos
          - os: ubuntu-latest
            build_target: linux
    steps:
      - name: Prime the CocoaPods spec source
        if: matrix.os == 'macos-latest'
        run: bash scripts/ci-prime-cocoapods.sh
      - name: Build
        run: flutter build ${{ matrix.build_target }} --release
EOF
t "matris legi tek if ile gecerli" 0 "$WORK/matrix.yml"

# MUST GO RED: the same matrix without the step. The exposed leg is one line
# in an `include:` list, which is exactly why nobody notices.
python3 - "$WORK/matrix.yml" "$WORK/matrix-bare.yml" <<'PY'
import sys
src, dst = sys.argv[1], sys.argv[2]
keep = [l for l in open(src).read().split("\n")
        if "ci-prime-cocoapods.sh" not in l
        and "Prime the CocoaPods" not in l
        and "matrix.os == 'macos-latest'" not in l]
open(dst, "w").write("\n".join(keep))
PY
t "matris legi primingsiz yakalanir" 1 "$WORK/matrix-bare.yml"

# GREEN: prose is not configuration. A comment naming a macOS runner must not
# put an Android job under the rule, and a comment naming the script must not
# satisfy it -- so this file must pass on the second job alone.
cat > "$WORK/prose.yml" <<'EOF'
jobs:
  build-android:
    # Ran on macos-15 until #814; scripts/ci-prime-cocoapods.sh went with it.
    runs-on: ubuntu-latest
    steps:
      - run: flutter build apk --debug
  build-ios:
    runs-on: macos-15
    steps:
      - run: bash scripts/ci-prime-cocoapods.sh
      - run: flutter build ios --no-codesign
EOF
t "yorum satiri kurali tetiklemez" 0 "$WORK/prose.yml"

# MUST GO RED: nothing here builds Flutter on macOS, so the guard has lost its
# subject. A guard that silently watches nothing is worse than no guard.
cat > "$WORK/nothing.yml" <<'EOF'
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - run: go vet ./...
EOF
t "konusu kalmayan guard kirmizi" 1 "$WORK/nothing.yml"

echo
if [ "$fail" -eq 0 ]; then
  echo "check-macos-pod-priming.test.sh: tum durumlar gecti"
else
  echo "check-macos-pod-priming.test.sh: $fail durum basarisiz"
fi
exit $((fail > 0))
