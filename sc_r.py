#!/usr/bin/env python3
# Copyright (c) 2025 Abdallah
# Licensed under the GNU GPLv3
# Repo: https://github.com/abdallahbn31/reused-r-bitcoin
"""
sc_r.py

Recover BIP-340 private key x when the *same* R (nonce) was reused in two Schnorr signatures
on two different messages (and same pubkey). Usage example below.

WARNING: Use only on keys/messages you own or have explicit permission to analyze.
"""

import argparse
import hashlib

# secp256k1 group order (n)
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
# note: same as commonly used (BN), also equal to decimal in bitcoin context.

def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def tagged_hash(tag: bytes, msg: bytes) -> bytes:
    """BIP340 tagged_hash(tag, msg) = SHA256(SHA256(tag) || SHA256(tag) || msg)"""
    tag_hash = sha256(tag)
    return sha256(tag_hash + tag_hash + msg)

def compute_challenge_e(Rx_bytes: bytes, Px_bytes: bytes, msg_bytes: bytes) -> int:
    """Compute e = int(tagged_hash('BIP0340/challenge', Rx||Px||m)) mod n"""
    th = tagged_hash(b"BIP0340/challenge", Rx_bytes + Px_bytes + msg_bytes)
    return int.from_bytes(th, "big") % n

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def base58_encode(b: bytes) -> str:
    num = int.from_bytes(b, "big")
    res = ""
    while num > 0:
        num, r = divmod(num, 58)
        res = ALPHABET[r] + res
    # leading zeros
    pad = 0
    for c in b:
        if c == 0:
            pad += 1
        else:
            break
    return ALPHABET[0] * pad + res

def base58check(payload: bytes) -> str:
    chk = sha256(sha256(payload))[:4]
    return base58_encode(payload + chk)

def priv_to_wif(priv32: bytes, compressed=True, testnet=False) -> str:
    prefix = b'\xef' if testnet else b'\x80'
    payload = prefix + priv32
    if compressed:
        payload += b'\x01'
    return base58check(payload)

def normalize_hex(s: str) -> bytes:
    s2 = s.strip()
    if s2.startswith("0x") or s2.startswith("0X"):
        s2 = s2[2:]
    if len(s2) % 2 == 1:
        s2 = "0" + s2
    return bytes.fromhex(s2)

def parse_msg_input(s: str) -> bytes:
    """
    Allow message input either as:
      - hex string (0-9a-f) (we detect if input looks like hex and length > 0)
      - plain UTF-8 text (otherwise)
    """
    s = s.strip()
    # Heuristic: if string contains only hex chars and length >= 2 -> treat as hex
    import re
    if re.fullmatch(r"(0x)?[0-9a-fA-F]+", s) and (len(s.replace("0x","")) >= 2):
        return normalize_hex(s)
    else:
        return s.encode("utf-8")

def modinv(a: int, m: int) -> int:
    """Modular inverse (Python 3.8+: pow(a, -1, m) works). Use pow for clarity."""
    return pow(a, -1, m)

def main():
    p = argparse.ArgumentParser(description="Recover BIP-340 private key x from two Schnorr sigs that reused same R.")
    p.add_argument("--Rx", required=True, help="R.x coordinate (hex, 32 bytes) of the reused nonce (hex).")
    p.add_argument("--Px", required=True, help="public key x coordinate (x-only pubkey) hex (32 bytes).")
    p.add_argument("--s1", required=True, help="signature s for message1 (hex or decimal).")
    p.add_argument("--m1", required=True, help="message1 (hex or plain text).")
    p.add_argument("--s2", required=True, help="signature s for message2 (hex or decimal).")
    p.add_argument("--m2", required=True, help="message2 (hex or plain text).")
    p.add_argument("--testnet", action="store_true", help="Output testnet WIF as well.")
    p.add_argument("--uncompressed", action="store_true", help="Output uncompressed WIF (no compressed suffix).")
    args = p.parse_args()

    try:
        Rx = normalize_hex(args.Rx)
        Px = normalize_hex(args.Px)
    except Exception as e:
        print("Error parsing Rx/Px hex:", e)
        return

    if len(Rx) != 32 or len(Px) != 32:
        print("Error: Rx and Px must be 32-byte hex values (64 hex chars).")
        return

    # parse s1/s2 either hex or decimal
    def parse_s(s):
        s0 = s.strip()
        if s0.startswith("0x") or all(c in "0123456789abcdefABCDEF" for c in s0):
            # hex
            return int(s0, 16)
        else:
            return int(s0, 10)
    try:
        s1 = parse_s(args.s1)
        s2 = parse_s(args.s2)
    except Exception as e:
        print("Error parsing s values:", e)
        return

    m1 = parse_msg_input(args.m1)
    m2 = parse_msg_input(args.m2)

    # compute e1,e2
    e1 = compute_challenge_e(Rx, Px, m1)
    e2 = compute_challenge_e(Rx, Px, m2)

    # compute differences modulo n
    sd = (s1 - s2) % n
    ed = (e1 - e2) % n

    if ed == 0:
        print("e1 - e2 ≡ 0 (mod n). Cannot invert; cannot recover x with these two signatures.")
        return

    inv_ed = modinv(ed, n)
    x = (sd * inv_ed) % n

    # output
    print("=== Result ===")
    print("e1 =", e1)
    print("e2 =", e2)
    print("s1 =", s1)
    print("s2 =", s2)
    print("s_diff (s1-s2 mod n) =", sd)
    print("e_diff (e1-e2 mod n) =", ed)
    print("")
    print("Recovered private key x (decimal):", x)
    print("Recovered private key x (hex)    :", hex(x))
    # format 32-byte private key
    priv32 = x.to_bytes(32, "big")
    print("")
    # print both compressed and uncompressed WIFs for mainnet
    wif_main_compr = priv_to_wif(priv32, compressed=True, testnet=False)
    wif_main_uncompr = priv_to_wif(priv32, compressed=False, testnet=False)
    print("WIF (mainnet, compressed):", wif_main_compr)
    print("WIF (mainnet, uncompressed):", wif_main_uncompr)
    if args.testnet:
        # print both compressed and uncompressed WIFs for testnet
        wif_test_compr = priv_to_wif(priv32, compressed=True, testnet=True)
        wif_test_uncompr = priv_to_wif(priv32, compressed=False, testnet=True)
        print("WIF (testnet, compressed):", wif_test_compr)
        print("WIF (testnet, uncompressed):", wif_test_uncompr)
    print("\nIMPORTANT: Verify the recovered key locally with your wallet software before taking further steps.")

if __name__ == "__main__":
    main()