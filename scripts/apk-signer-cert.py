#!/usr/bin/env python3
"""Print the SHA-256 of the certificate an APK is signed with (v2/v3 scheme).

    apk-signer-cert.py <app.apk>                 -> prints the digest
    apk-signer-cert.py <app.apk> --expect <hex>  -> exits 1 unless it matches

The Android build pins one debug key so a test build can update the app
already on a phone. Whether the pin took is not visible from the build log:
the build succeeds with any key. This reads the certificate out of the APK
Signing Block itself, with no Android SDK tools, so CI can check it.
"""
import hashlib
import struct
import sys

V2_ID, V3_ID = 0x7109871A, 0xF05368C0


def _lp(buf, off):
    n = struct.unpack("<I", buf[off:off + 4])[0]
    return buf[off + 4:off + 4 + n], off + 4 + n


def signer_cert_sha256(path):
    data = open(path, "rb").read()
    eocd = data.rfind(b"PK\x05\x06")
    if eocd < 0:
        raise ValueError("not a zip")
    cd_off = struct.unpack("<I", data[eocd + 16:eocd + 20])[0]
    if data[cd_off - 16:cd_off] != b"APK Sig Block 42":
        raise ValueError("no APK Signing Block (v1-only APK?)")
    size = struct.unpack("<Q", data[cd_off - 24:cd_off - 16])[0]
    block = data[cd_off - size - 8 + 8:cd_off - 24]
    i = 0
    while i < len(block):
        length = struct.unpack("<Q", block[i:i + 8])[0]
        bid = struct.unpack("<I", block[i + 8:i + 12])[0]
        val = block[i + 12:i + 8 + length]
        i += 8 + length
        if bid not in (V2_ID, V3_ID):
            continue
        signers, _ = _lp(val, 0)
        signer, _ = _lp(signers, 0)
        signed_data, _ = _lp(signer, 0)
        _, off = _lp(signed_data, 0)  # digests
        certs, _ = _lp(signed_data, off)
        cert, _ = _lp(certs, 0)
        return hashlib.sha256(cert).hexdigest()
    raise ValueError("no v2/v3 signer")


def main(argv):
    if len(argv) < 2:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    got = signer_cert_sha256(argv[1])
    print(got)
    if "--expect" in argv:
        want = argv[argv.index("--expect") + 1].lower().replace(":", "")
        if got != want:
            print(f"signer certificate {got} is not the pinned {want}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
