#!/usr/bin/env python3
# Copyright (c) 2025 Abdallah
# Licensed under the GNU GPLv3
"""
wif.py
Read private key hex/decimal or file of keys -> produce WIFs and derive addresses:
  - P2PKH (legacy)
  - P2SH-P2WPKH (wrapped segwit)
  - P2WPKH (bech32 v0)
  - P2TR (bech32m taproot)
Check balances via Blockstream Esplora API (mainnet/testnet).
Output CSV with results.

Usage:
  python3 wif.py --hex <privhex>
  python3 wif.py --file keys.txt --out results.csv
  python3 wif.py --hex <privhex> --testnet
"""
import argparse, hashlib, csv, os, requests
from ecdsa import SigningKey, SECP256k1
from typing import List

# --- base58 / base58check ---
ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def base58_encode(b: bytes) -> str:
    n = int.from_bytes(b, 'big')
    res = ""
    while n > 0:
        n, r = divmod(n, 58)
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
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return base58_encode(payload + checksum)

# --- bech32 (BIP173) implementation (encode only) ---
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
def bech32_polymod(values: List[int]) -> int:
    GENERATORS = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = (chk >> 25)
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            if ((b >> i) & 1):
                chk ^= GENERATORS[i]
    return chk

def bech32_hrp_expand(hrp: str) -> List[int]:
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def bech32_create_checksum(hrp: str, data: List[int]) -> List[int]:
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0,0,0,0,0,0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

def convertbits(data: bytes, frombits: int, tobits: int, pad: bool=True):
    acc = 0; bits = 0; ret = []
    maxv = (1 << tobits) - 1
    for b in data:
        acc = (acc << frombits) | b
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    else:
        if bits >= frombits or ((acc << (tobits - bits)) & maxv):
            return None
    return ret

def bech32_encode(hrp: str, witver: int, witprog: bytes) -> str:
    data = [witver] + (convertbits(witprog, 8, 5))
    checksum = bech32_create_checksum(hrp, data)
    combined = data + checksum
    return hrp + '1' + ''.join([CHARSET[d] for d in combined])

# --- bech32m (for Taproot) ---
BECH32M_CONST = 0x2bc830a3
def bech32m_create_checksum(hrp: str, data: List[int]) -> List[int]:
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0,0,0,0,0,0]) ^ BECH32M_CONST
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

def bech32m_encode(hrp: str, witver: int, witprog: bytes) -> str:
    data = [witver] + (convertbits(witprog, 8, 5))
    checksum = bech32m_create_checksum(hrp, data)
    combined = data + checksum
    return hrp + '1' + ''.join([CHARSET[d] for d in combined])

# --- crypto helpers ---
def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()
def ripemd160(b: bytes) -> bytes:
    h = hashlib.new('ripemd160')
    h.update(b)
    return h.digest()
def hash160(b: bytes) -> bytes:
    return ripemd160(hashlib.sha256(b).digest())

# --- tagged_hash for Taproot tweak (BIP340/BIP341 style) ---
def tagged_hash(tag: bytes, msg: bytes) -> bytes:
    th = sha256(tag)
    return sha256(th + th + msg)

# --- private -> pubkey (compressed/uncompressed) ---
def priv_to_pubkey(priv_bytes: bytes, compressed: bool=True) -> bytes:
    sk = SigningKey.from_string(priv_bytes, curve=SECP256k1)
    vk = sk.verifying_key
    px = vk.to_string()[:32]
    py = vk.to_string()[32:]
    if compressed:
        prefix = b'\x02' if (py[-1] % 2 == 0) else b'\x03'
        return prefix + px
    else:
        return b'\x04' + px + py

# --- P2TR (Taproot) address derivation (key-path only, no script tree) ---
def p2tr_address(priv_bytes: bytes, testnet: bool=False) -> str:
    """
    Derive a Taproot (P2TR) address from a 32-byte private key (key-path only),
    following BIP341 (internal key tweak with empty merkle root).
    """
    # get verifying key point
    sk = SigningKey.from_string(priv_bytes, curve=SECP256k1)
    vk = sk.verifying_key
    # internal x-only pubkey (32 bytes)
    internal_x = vk.to_string()[:32]
    # compute tweak = int(tagged_hash("TapTweak", internal_x)) mod n
    # use n from curve order:
    n = SECP256k1.order
    t = int.from_bytes(tagged_hash(b"TapTweak", internal_x), "big") % n
    # points
    G = SECP256k1.generator  # generator point
    P = vk.pubkey.point       # public point
    # compute tweaked point Q = P + t*G
    if t == 0:
        Q = P
    else:
        Q = P + (t * G)
    # get x coordinate as 32-byte (x-only output key)
    xQ = Q.x()
    xQ_bytes = int(xQ).to_bytes(32, "big")
    hrp = "tb" if testnet else "bc"
    # witness version 1, 32-byte program => bech32m
    return bech32m_encode(hrp, 1, xQ_bytes)

# --- address builders ---
def p2pkh_address(pubkey: bytes, testnet: bool=False) -> str:
    vh = (b'\x6f' if testnet else b'\x00') + ripemd160(hashlib.sha256(pubkey).digest())
    return base58check(vh)

def p2sh_p2wpkh_address(pubkey: bytes, testnet: bool=False) -> str:
    # redeem script = 0x00 0x14 <20-byte-hash>
    h20 = ripemd160(hashlib.sha256(pubkey).digest())
    redeem = b'\x00' + bytes([len(h20)]) + h20  # NOTE: len(h20) == 20 -> pushes 20
    script_hash = ripemd160(hashlib.sha256(redeem).digest())
    ver = b'\xc4' if testnet else b'\x05'
    return base58check(ver + script_hash)

def p2wpkh_bech32(pubkey: bytes, testnet: bool=False) -> str:
    h20 = ripemd160(hashlib.sha256(pubkey).digest())
    hrp = "tb" if testnet else "bc"
    return bech32_encode(hrp, 0, h20)

# --- WIF ---
def make_wif(priv32: bytes, compressed: bool=True, testnet: bool=False) -> str:
    prefix = b'\xef' if testnet else b'\x80'
    payload = prefix + priv32
    if compressed:
        payload += b'\x01'
    return base58check(payload)

# --- Blockstream API (optional API key via env BLOCKSTREAM_API_KEY) ---
def blockstream_base(testnet: bool):
    return "https://blockstream.info/testnet/api" if testnet else "https://blockstream.info/api"

def get_address_balance(address: str, testnet: bool=False, timeout: int=15):
    base = blockstream_base(testnet)
    url = f"{base}/address/{address}"
    headers = {}
    key = os.environ.get("BLOCKSTREAM_API_KEY")
    if key:
        headers["Authorization"] = f"Bearer {key}"
    try:
        r = requests.get(url, headers=headers, timeout=timeout)
        if r.status_code == 200:
            j = r.json()
            chain = j.get("chain_stats", {})
            funded = chain.get("funded_txo_sum", 0)
            spent = chain.get("spent_txo_sum", 0)
            bal = int(funded) - int(spent)
            return True, bal
        else:
            return False, f"HTTP {r.status_code}: {r.text[:200]}"
    except Exception as e:
        return False, str(e)

# --- normalize input ---
def normalize_priv(value: str) -> bytes:
    v = value.strip()
    # try hex
    if v.startswith("0x"):
        v = v[2:]
    if all(c in "0123456789abcdefABCDEF" for c in v) and len(v) >= 2:
        if len(v) % 2 == 1:
            v = "0" + v
        raw = bytes.fromhex(v)
    else:
        # decimal
        raw = int(v).to_bytes((int(v).bit_length() + 7)//8 or 1, 'big')
    if len(raw) > 32:
        raise ValueError("private key too long")
    return raw.rjust(32, b'\x00')

# --- main ---
def main():
    p = argparse.ArgumentParser(description="Make WIFs + derive addresses + check balances (Blockstream)")
    p.add_argument("--hex", help="Private key hex (or decimal single value)")
    p.add_argument("--file", help="File with one private key per line (hex or decimal)")
    p.add_argument("--out", "-o", default="results.csv", help="CSV output")
    p.add_argument("--testnet", action="store_true", help="Use testnet addresses/API")
    p.add_argument("--no-check", action="store_true", help="Don't query explorer for balance")
    args = p.parse_args()

    inputs = []
    if args.hex:
        inputs.append(args.hex.strip())
    if args.file:
        with open(args.file, "r", encoding="utf-8") as f:
            for ln in f:
                s = ln.strip()
                if s:
                    inputs.append(s)
    if not inputs:
        print("No inputs provided. Use --hex or --file")
        return

    rows = []
    for v in inputs:
        try:
            priv32 = normalize_priv(v)
        except Exception as e:
            print("Skip", v, ":", e)
            continue

        # produce WIF + addresses for compressed/uncompressed
        for compressed in (False, True):
            pub = priv_to_pubkey(priv32, compressed=compressed)
            wif = make_wif(priv32, compressed=compressed, testnet=args.testnet)
            addr_p2pkh = p2pkh_address(pub, testnet=args.testnet)
            addr_p2sh = p2sh_p2wpkh_address(pub, testnet=args.testnet)
            addr_bech32 = p2wpkh_bech32(pub, testnet=args.testnet)
            # compute P2TR (taproot) using key-path only
            try:
                addr_p2tr = p2tr_address(priv32, testnet=args.testnet)
            except Exception as e:
                addr_p2tr = ""
            bal_p2pkh = bal_p2sh = bal_bech32 = bal_p2tr = None
            err_p2pkh = err_p2sh = err_p2bech = err_p2tr = ""
            if not args.no_check:
                ok, val = get_address_balance(addr_p2pkh, testnet=args.testnet)
                if ok:
                    bal_p2pkh = val
                else:
                    err_p2pkh = val
                ok, val = get_address_balance(addr_p2sh, testnet=args.testnet)
                if ok:
                    bal_p2sh = val
                else:
                    err_p2sh = val
                ok, val = get_address_balance(addr_bech32, testnet=args.testnet)
                if ok:
                    bal_p2bech = val
                else:
                    err_p2bech = val
                # try taproot balance query (may be supported)
                if addr_p2tr:
                    ok, val = get_address_balance(addr_p2tr, testnet=args.testnet)
                    if ok:
                        bal_p2tr = val
                    else:
                        err_p2tr = val

            rec = {
                "input": v,
                "priv_hex": priv32.hex(),
                "compressed": "yes" if compressed else "no",
                "wif": wif,
                "p2pkh": addr_p2pkh, "p2pkh_balance_sats": "" if bal_p2pkh is None else str(bal_p2pkh), "p2pkh_error": err_p2pkh,
                "p2sh_p2wpkh": addr_p2sh, "p2sh_balance_sats": "" if bal_p2sh is None else str(bal_p2sh), "p2sh_error": err_p2sh,
                "p2wpkh": addr_bech32, "p2wpkh_balance_sats": "" if bal_p2bech is None else str(bal_p2bech), "p2wpkh_error": err_p2bech,
                "p2tr": addr_p2tr, "p2tr_balance_sats": "" if bal_p2tr is None else str(bal_p2tr), "p2tr_error": err_p2tr
            }
            rows.append(rec)
            print(f"[{v}] compressed={rec['compressed']} WIF={wif}")
            print(f"  P2PKH: {addr_p2pkh}  bal={rec['p2pkh_balance_sats'] or '-'} err={err_p2pkh or '-'}")
            print(f"  P2SH-P2WPKH: {addr_p2sh}  bal={rec['p2sh_balance_sats'] or '-'} err={err_p2sh or '-'}")
            print(f"  P2WPKH: {addr_bech32}  bal={rec['p2wpkh_balance_sats'] or '-'} err={err_p2bech or '-'}")
            if addr_p2tr:
                print(f"  P2TR (taproot): {addr_p2tr}  bal={rec['p2tr_balance_sats'] or '-'} err={err_p2tr or '-'}")

    # write CSV
    fieldnames = [
        "input","priv_hex","compressed","wif",
        "p2pkh","p2pkh_balance_sats","p2pkh_error",
        "p2sh_p2wpkh","p2sh_balance_sats","p2sh_error",
        "p2wpkh","p2wpkh_balance_sats","p2wpkh_error",
        "p2tr","p2tr_balance_sats","p2tr_error"
    ]
    with open(args.out, "w", newline="", encoding="utf-8") as csvf:
        writer = csv.DictWriter(csvf, fieldnames=fieldnames)
        writer.writeheader()
        for r in rows:
            writer.writerow(r)

    print("Done. Results in", args.out)

if __name__ == "__main__":
    main()