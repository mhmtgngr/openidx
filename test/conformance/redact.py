#!/usr/bin/env python3
"""Replace this run's generated secrets with "[redacted]" in everything under
the given directories, zip members included, before the results are uploaded.

The suite exports every module's full log, and those logs carry the test
users' typed passwords and the clients' secrets (the latter also inside the
Basic authorization header, which setup_openidx.py lists in its encoded form
too). They are worthless once the throwaway stack is gone, but a published
artifact is not the place for them either way.

Usage: redact.py --secrets-file FILE DIR [DIR ...]
A missing secrets file means setup never ran, so there is nothing to remove.
Standard library only.
"""

import argparse
import pathlib
import sys
import zipfile

MARK = b"[redacted]"


def scrub(data, secrets):
    for secret in secrets:
        data = data.replace(secret, MARK)
    return data


def redact_zip(path, secrets):
    with zipfile.ZipFile(path) as src:
        members = [(info, src.read(info)) for info in src.infolist()]
    changed = False
    cleaned = []
    for info, data in members:
        new = scrub(data, secrets)
        changed |= new != data
        cleaned.append((info, new))
    if not changed:
        return False
    tmp = path.with_suffix(path.suffix + ".tmp")
    with zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_DEFLATED) as dst:
        for info, data in cleaned:
            dst.writestr(info, data)
    tmp.replace(path)
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--secrets-file", required=True)
    parser.add_argument("dirs", nargs="+")
    args = parser.parse_args()

    secrets_path = pathlib.Path(args.secrets_file)
    if not secrets_path.exists():
        print("redact: %s does not exist; no secrets were generated" % secrets_path)
        return 0
    secrets = sorted({line.strip().encode() for line in secrets_path.read_text().splitlines() if line.strip()},
                     key=len, reverse=True)
    changed = 0
    for root in args.dirs:
        for path in sorted(pathlib.Path(root).rglob("*")):
            if not path.is_file():
                continue
            if path.suffix == ".zip":
                changed += redact_zip(path, secrets)
                continue
            data = path.read_bytes()
            new = scrub(data, secrets)
            if new != data:
                path.write_bytes(new)
                changed += 1
    print("redact: removed %d secret value(s) from %d file(s)" % (len(secrets), changed))
    return 0


if __name__ == "__main__":
    sys.exit(main())
