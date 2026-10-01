#!/usr/bin/env python3
"""Print synthetic sle_pair test vectors; no files or network operations.

Independent oracle: Python cryptography/OpenSSL, not project C or Mbed TLS.
These validate the documented byte-order candidate, NOT WS63 interoperation.
Fixed private keys/randomness below are exclusively for unit tests.
Run with system python3 (cryptography is already installed there).
"""
import argparse
from pathlib import Path

from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers.aead import AESCCM


def cmac_rev(key, message):
    c = cmac.CMAC(algorithms.AES(key[::-1]))
    c.update(message[::-1])
    return c.finalize()[::-1]


def public_le(key):
    n = key.public_key().public_numbers()
    return n.x.to_bytes(32, "little") + n.y.to_bytes(32, "little")


def vectors():
    g = ec.derive_private_key(int.from_bytes(b"\x11" * 32, "big"), ec.SECP256R1())
    t = ec.derive_private_key(int.from_bytes(b"\x22" * 32, "big"), ec.SECP256R1())
    gp, tp = public_le(g), public_le(t)
    dh = g.exchange(ec.ECDH(), t.public_key())[::-1]
    ra, rb = bytes(range(0x20, 0x30)), bytes(range(0x40, 0x50))
    ga, ta = bytes.fromhex("eeef339b8d5c"), bytes.fromhex("010203040506")
    giv_skd, tiv_skd = bytes(range(0x60, 0x6c)), bytes(range(0x70, 0x7c))
    lk = cmac_rev(dh[:16], b"kl" + ra + rb + ga + ta)
    dk = cmac_rev(dh[:16], b"kd" + ra + rb + ga + ta)
    suffix = bytes(16) + bytes([3, 3, 1, 2, 2, 2, 2, 0, 0]) + ga + ta
    gc, tc = cmac_rev(dk, ra + suffix), cmac_rev(dk, rb + suffix)
    sk = cmac_rev(lk, giv_skd[4:] + tiv_skd[4:])[::-1]
    sync = (0x1c4eac4a).to_bytes(4, "little")
    iv = bytes(a ^ b for a, b in zip(giv_skd[:4], sync)) + tiv_skd[:4]

    def enc(plain, count, tx):
        nonce = (count | (int(tx) << 39)).to_bytes(5, "little") + iv
        return AESCCM(sk, tag_length=4).encrypt(nonce, plain, b"\x00")

    return dict(gpub=gp, tpub=tp, dh=dh, lk=lk, gcheck=gc, tcheck=tc,
                confirm=cmac_rev(rb, gp + tp), sk=sk, iv=iv,
                gstart=enc(b"\x07\x00\x00", 0, True),
                tstart=enc(b"\x07\x00\x00", 0, False),
                gdata=enc(b"hello SLE", 1, True),
                tdata=enc(b"hello SLE", 1, False),
                glast=enc(b"hello SLE", (1 << 39) - 1, True),
                tlast=enc(b"hello SLE", (1 << 39) - 1, False))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="compare against test_sle_pair.c")
    args = parser.parse_args()
    declarations = [f'static const char v_{name}[] = "{value.hex()}";'
                    for name, value in vectors().items()]
    if args.check:
        source = Path(__file__).with_name("test_sle_pair.c").read_text()
        for declaration in declarations:
            if declaration not in source:
                raise SystemExit("test vector differs: " + declaration.split("[]")[0])
        print(f"independent Python/OpenSSL oracle: {len(declarations)} vectors PASS")
    else:
        print("\n".join(declarations))
