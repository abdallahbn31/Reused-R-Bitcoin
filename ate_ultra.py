#!/usr/bin/env python3
# Copyright (c) 2025 Abdallah
# Licensed under the GNU GPLv3
# Repo: https://github.com/abdallahbn31/reused-r-bitcoin
# ate_ultra.py
# Read rawtxs.txt (each line = raw tx hex), parse TX structure (segwit-aware),
# extract ECDSA DER signatures and Schnorr-like signatures (64/65 bytes).
# Write CSV with details and print/produce a readable summary of duplicate r/R groups.
#
# Usage:
#   python3 ate_ultra.py rawtxs.txt
#
# No external libs required.

import sys, re, csv, time, signal
from collections import defaultdict
from hashlib import sha256

if len(sys.argv) != 2:
    print("Usage: python3 ate_ultra.py rawtxs.txt")
    sys.exit(1)

INFILE = sys.argv[1]
OUTCSV = "sigs_extracted.csv"
DUPTXT = "duplicates_summary.txt"

stop_requested = False
def handle_sigint(sig, frame):
    global stop_requested
    print("\n[!] Stop signal received - The partial report will now be completed...")
    stop_requested = True

signal.signal(signal.SIGINT, handle_sigint)

# ---------- helpers ----------
def dblsha(b: bytes) -> bytes:
    return sha256(sha256(b).digest()).digest()

def txid_from_rawhex(rawhex: str) -> str:
    bh = bytes.fromhex(rawhex)
    return dblsha(bh)[::-1].hex()

def read_varint(b: bytes, p: int):
    v = b[p]
    if v < 0xfd:
        return v, p+1
    if v == 0xfd:
        return int.from_bytes(b[p+1:p+3], "little"), p+3
    if v == 0xfe:
        return int.from_bytes(b[p+1:p+5], "little"), p+5
    return int.from_bytes(b[p+1:p+9], "little"), p+9

# DER parsing (for ECDSA signature)
def parse_der_rs(der: bytes):
    try:
        if len(der) < 6 or der[0] != 0x30:
            return None, None
        p = 1
        total_len = der[p]; p += 1
        if p >= len(der): return None, None
        if der[p] != 0x02: return None, None
        rlen = der[p+1]
        r = der[p+2:p+2+rlen]
        p = p+2+rlen
        if p >= len(der): return None, None
        if der[p] != 0x02: return None, None
        slen = der[p+1]
        s = der[p+2:p+2+slen]
        return r.hex(), s.hex()
    except Exception:
        return None, None

def detect_der_in_bytes(blob: bytes):
    """Return list of dicts with fields: pos, der_bytes, r_hex, s_hex, sighash_hex (maybe empty)"""
    found = []
    i = 0
    L = len(blob)
    while i < L:
        if blob[i] == 0x30 and i+3 < L:
            try:
                total_len = blob[i+1]
                end = i + 2 + total_len
                if end <= L:
                    der = blob[i:end]
                    if b'\x02' in der:
                        sigh = ""
                        if end < L:
                            possible = blob[end]
                            # record potential sighash byte (may be garbage sometimes)
                            sigh = "{:02x}".format(possible)
                        r,s = parse_der_rs(der)
                        if r:
                            found.append({
                                "pos": i,
                                "der": der,
                                "r_hex": r,
                                "s_hex": s,
                                "sighash_hex": sigh
                            })
                            i = end
                            continue
            except Exception:
                pass
        i += 1
    return found

# ---------- lightweight TX parser (segwit-aware) ----------
def parse_tx(rawhex: str):
    b = bytes.fromhex(rawhex)
    p = 0
    L = len(b)
    if L < 10:
        raise ValueError("raw tx too short")
    version = int.from_bytes(b[p:p+4], "little"); p += 4
    marker = None; flag = None; is_segwit = False
    if p+1 < L and b[p] == 0x00 and b[p+1] == 0x01:
        marker = b[p]; flag = b[p+1]; p += 2; is_segwit = True

    n_in, p = read_varint(b, p)
    inputs = []
    for i in range(n_in):
        prev = b[p:p+32][::-1].hex(); p += 32
        prev_index = int.from_bytes(b[p:p+4], "little"); p += 4
        slen, p = read_varint(b, p)
        scriptSig = b[p:p+slen]; p += slen
        sequence = int.from_bytes(b[p:p+4], "little"); p += 4
        inputs.append({
            "prev_txid": prev,
            "prev_index": prev_index,
            "scriptSig": scriptSig,
            "sequence": sequence
        })
    n_out, p = read_varint(b, p)
    outputs = []
    for i in range(n_out):
        value = int.from_bytes(b[p:p+8], "little"); p += 8
        olen, p = read_varint(b, p)
        scriptPubKey = b[p:p+olen]; p += olen
        outputs.append({
            "value": value,
            "scriptPubKey": scriptPubKey
        })
    witnesses = []
    if is_segwit:
        for i in range(n_in):
            wit_count, p = read_varint(b, p)
            items = []
            for wi in range(wit_count):
                ilen, p = read_varint(b, p)
                item = b[p:p+ilen]; p += ilen
                items.append(item)
            witnesses.append(items)
    locktime = int.from_bytes(b[p:p+4], "little") if p+4 <= L else 0
    return {
        "version": version,
        "is_segwit": is_segwit,
        "inputs": inputs,
        "outputs": outputs,
        "witnesses": witnesses,
        "locktime": locktime,
        "raw_bytes": b
    }

# ---------- main processing ----------
start_time = time.time()
total_txs = 0
total_sigs = 0
ecdsa_sigs = []   # list of dicts
schnorr_sigs = [] # list of dicts

# stream file (do not load all into RAM)
with open(INFILE, "r", encoding="utf-8") as f:
    for ln in f:
        if stop_requested:
            break
        h = ln.strip()
        if not h:
            continue
        # pick longest hex-like substring if extra text present
        cand = re.findall(r'[0-9a-fA-F]{40,}', h)
        if cand:
            raw = max(cand, key=len)
        else:
            raw = h
        raw = raw.lower()
        total_txs += 1
        try:
            tx = parse_tx(raw)
        except Exception as e:
            print(f"[{total_txs}] Failed parse tx: {e}")
            continue
        txid = txid_from_rawhex(raw)

        # 1) scriptSig scanning for DER (non-segwit inputs)
        for idx, inp in enumerate(tx["inputs"]):
            script = inp["scriptSig"]
            if script and len(script) > 0:
                der_found = detect_der_in_bytes(script)
                for item in der_found:
                    total_sigs += 1
                    e = {
                        "sig_type": "ecdsa",
                        "txid": txid,
                        "input_index": idx,
                        "prev_txid": inp["prev_txid"],
                        "prev_index": inp["prev_index"],
                        "r_hex": item["r_hex"],
                        "s_hex": item["s_hex"],
                        "sighash_hex": item["sighash_hex"],
                        "raw_item_hex": item["der"].hex()
                    }
                    ecdsa_sigs.append(e)

        # 2) witness scanning (if segwit) - ECDSA DER and Schnorr-like
        if tx["is_segwit"]:
            for idx, wit in enumerate(tx["witnesses"]):
                for wi_item in wit:
                    L = len(wi_item)
                    # ECDSA DER possibly inside witness item
                    if L >= 6 and wi_item[0] == 0x30:
                        der_found = detect_der_in_bytes(wi_item)
                        for item in der_found:
                            total_sigs += 1
                            e = {
                                "sig_type": "ecdsa",
                                "txid": txid,
                                "input_index": idx,
                                "prev_txid": tx["inputs"][idx]["prev_txid"],
                                "prev_index": tx["inputs"][idx]["prev_index"],
                                "r_hex": item["r_hex"],
                                "s_hex": item["s_hex"],
                                "sighash_hex": item["sighash_hex"],
                                "raw_item_hex": item["der"].hex()
                            }
                            ecdsa_sigs.append(e)
                    # Schnorr-like: 64 bytes (R||s) or 65 (R||s||flag)
                    if L == 64 or L == 65:
                        # treat as Schnorr candidate
                        R = wi_item[:32].hex()
                        s_hex = wi_item[32:64].hex()
                        flag = wi_item[64:].hex() if L == 65 else ""
                        total_sigs += 1
                        s = {
                            "sig_type": "schnorr",
                            "txid": txid,
                            "input_index": idx,
                            "prev_txid": tx["inputs"][idx]["prev_txid"],
                            "prev_index": tx["inputs"][idx]["prev_index"],
                            "R_hex": R,
                            "s_hex": s_hex,
                            "flag_hex": flag,
                            "raw_item_hex": wi_item.hex()
                        }
                        schnorr_sigs.append(s)

        # progress printing every 100 txs
        if total_txs % 100 == 0:
            elapsed = time.time() - start_time
            print(f"[{total_txs}] txs processed — signatures found so far: {total_sigs} — elapsed {int(elapsed)}s")
# end reading file

# write CSV with all records
with open(OUTCSV, "w", newline="", encoding="utf-8") as csvf:
    fieldnames = [
        "sig_type","txid","input_index","prev_txid","prev_index",
        "r_or_R_hex","s_hex","sighash_or_flag","raw_item_hex"
    ]
    writer = csv.DictWriter(csvf, fieldnames=fieldnames)
    writer.writeheader()
    for e in ecdsa_sigs:
        writer.writerow({
            "sig_type": "ecdsa",
            "txid": e["txid"],
            "input_index": e["input_index"],
            "prev_txid": e["prev_txid"],
            "prev_index": e["prev_index"],
            "r_or_R_hex": e["r_hex"],
            "s_hex": e["s_hex"],
            "sighash_or_flag": e["sighash_hex"],
            "raw_item_hex": e["raw_item_hex"]
        })
    for s in schnorr_sigs:
        writer.writerow({
            "sig_type": "schnorr",
            "txid": s["txid"],
            "input_index": s["input_index"],
            "prev_txid": s["prev_txid"],
            "prev_index": s["prev_index"],
            "r_or_R_hex": s["R_hex"],
            "s_hex": s["s_hex"],
            "sighash_or_flag": s["flag_hex"],
            "raw_item_hex": s["raw_item_hex"]
        })

# build duplicate groups
ecdsa_by_r_pub = defaultdict(list)   # key = r_hex  (pubkey not always available)
schnorr_by_R = defaultdict(list)     # key = R_hex

for e in ecdsa_sigs:
    key = e["r_hex"]
    ecdsa_by_r_pub[key].append(e)

for s in schnorr_sigs:
    key = s["R_hex"]
    schnorr_by_R[key].append(s)

# summary printing & write duplicates file
total_ecdsa = len(ecdsa_sigs)
total_schnorr = len(schnorr_sigs)
dup_ecdsa_groups = {k:v for k,v in ecdsa_by_r_pub.items() if len(v) >= 2 and k != ""}
dup_schnorr_groups = {k:v for k,v in schnorr_by_R.items() if len(v) >= 2 and k != ""}

print("\n=== PROCESSING COMPLETE (or interrupted) ===")
print(f"Total TXs scanned   : {total_txs}")
print(f"Total signatures    : {total_sigs} (ECDSA: {total_ecdsa}, Schnorr-candidates: {total_schnorr})")
print(f"ECDSA duplicate r groups (count>=2): {len(dup_ecdsa_groups)}")
print(f"Schnorr duplicate R groups (count>=2): {len(dup_schnorr_groups)}")
print(f"CSV written to: {OUTCSV}")
print(f"Detailed duplicate groups written to: {DUPTXT}")

with open(DUPTXT, "w", encoding="utf-8") as f:
    f.write("Duplicate groups summary\n\n")
    f.write(f"Total TXs scanned: {total_txs}\n")
    f.write(f"Total signatures: {total_sigs}\n\n")
    f.write("== ECDSA groups with same r (>=2 entries) ==\n")
    if not dup_ecdsa_groups:
        f.write("None\n\n")
    else:
        for r, lst in dup_ecdsa_groups.items():
            f.write(f"r = {r}  (count={len(lst)})\n")
            for it in lst:
                f.write(f"  txid={it['txid']} input={it['input_index']} prev={it['prev_txid']}:{it['prev_index']} s={it['s_hex'][:16]}... sighash={it['sighash_hex']}\n")
            f.write("\n")
    f.write("\n== Schnorr groups with same R (>=2 entries) ==\n")
    if not dup_schnorr_groups:
        f.write("None\n\n")
    else:
        for R, lst in dup_schnorr_groups.items():
            f.write(f"R = {R}  (count={len(lst)})\n")
            for it in lst:
                f.write(f"  txid={it['txid']} input={it['input_index']} prev={it['prev_txid']}:{it['prev_index']} s={it['s_hex'][:16]}... flag={it['flag_hex']}\n")
            f.write("\n")

elapsed = time.time() - start_time
print(f"\nFinished in {int(elapsed)}s — outputs: {OUTCSV}, {DUPTXT}")