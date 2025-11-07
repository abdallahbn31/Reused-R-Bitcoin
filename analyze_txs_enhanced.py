#!/usr/bin/env python3  
# Copyright (c) 2025 Abdallah
# Licensed under the GNU GPLv3
# Repo: https://github.com/abdallahbn31/reused-r-bitcoin

# analyze_txs_enhanced.py  

# Usage: python3 analyze_txs_enhanced.py rawtxs.txt  

# Input: rawtxs.txt  (each raw tx hex on its own line; blank lines ignored)  

# Output: der_full_summary.csv  

import sys, re, csv
from collections import defaultdict
from hashlib import sha256  

# ==== [New addition here] ====
try:
    from tqdm import tqdm
except ImportError:
    print("tqdm library not found, installing it automatically...")
    import os
    os.system("pip install tqdm")
    from tqdm import tqdm
# ===========================

if len(sys.argv) != 2:
    print("Usage: python3 analyze_txs_enhanced.py rawtxs.txt")
    sys.exit(1)  

infile = sys.argv[1]  

# ---------- helpers ----------  

def dblsha(b: bytes) -> bytes:
    return sha256(sha256(b).digest()).digest()  

def txid_from_rawhex(rawhex: str) -> str:
    bh = bytes.fromhex(rawhex)
    return dblsha(bh)[::-1].hex()  

def read_varint(b: bytes, p: int):
    v = b[p]
    if v < 0xfd: return v, p+1
    if v == 0xfd: return int.from_bytes(b[p+1:p+3], "little"), p+3
    if v == 0xfe: return int.from_bytes(b[p+1:p+5], "little"), p+5
    return int.from_bytes(b[p+1:p+9], "little"), p+9  

# lightweight tx parser (segwit-aware)  

def parse_tx(rawhex: str):
    b = bytes.fromhex(rawhex)
    p = 0
    L = len(b)
    if L < 10: raise ValueError("raw tx too short")
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

# DER parsing (for ECDSA sig)  

def parse_der_rs(der: bytes):
    try:
        if len(der) < 6 or der[0] != 0x30: return None, None
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
                            sigh = "{:02x}".format(possible)
                        r,s = parse_der_rs(der)
                        if r:
                            found.append({
                                "pos": i,
                                "der_bytes": der,
                                "r_hex": r,
                                "s_hex": s,
                                "sighash_hex": sigh,
                                "end": end
                            })
                    i = end
                    continue
            except Exception:
                pass
        i += 1
    return found  

def find_pubkey_in_blob_after(blob: bytes, start_pos: int, lookahead=200):
    L = len(blob)
    start = start_pos
    window = blob[start:start+lookahead]
    # compressed 33-byte pubkey
    for idx, b in enumerate(window):
        if b in (0x02, 0x03) and idx+1+32 <= len(window):
            return window[idx:idx+33].hex()
    # uncompressed 65-byte pubkey
    for idx, b in enumerate(window):
        if b == 0x04 and idx+1+64 <= len(window):
            return window[idx:idx+65].hex()
    return ""  

# ---------- main ----------  

raw_txs = []
with open(infile, 'r', encoding='utf-8') as f:
    for line in f:
        h = line.strip()
        if not h: continue
        cand = re.findall(r'[0-9a-fA-F]{40,}', h)
        if cand: raw = max(cand, key=len)
        else: raw = h
        raw_txs.append(raw.lower())  

print(f"Loaded {len(raw_txs)} raw tx(s). Parsing and extracting signatures...")  

rows = []
# ==== [tqdm added here] ====
for rawhex in tqdm(raw_txs, desc="Analyzing transactions", unit="tx"):
# =================================
    try:
        tx = parse_tx(rawhex)
    except Exception as e:
        print("Failed to parse tx:", e)
        continue
    txid = txid_from_rawhex(rawhex)
    # 1) scan scriptSig per input
    for idx, inp in enumerate(tx["inputs"]):
        script = inp["scriptSig"]
        if script and len(script) > 0:
            found = detect_der_in_bytes(script)
            for item in found:
                r_hex = item["r_hex"]
                s_hex = item["s_hex"]
                sighash = item["sighash_hex"]
                der_len = len(item["der_bytes"])
                pubkey_hex = find_pubkey_in_blob_after(script, item["pos"] + der_len)
                rows.append({
                    "r_hex": r_hex,
                    "s_hex": s_hex,
                    "txid": txid,
                    "input_index": idx,
                    "pubkey_hex": pubkey_hex,
                    "prev_txid": inp["prev_txid"],
                    "prev_vout": inp["prev_index"],
                    "sighash_type": sighash,
                    "raw_tx_hex": rawhex
                })
    # 2) scan witness if segwit
    if tx["is_segwit"]:
        for idx, wit_items in enumerate(tx["witnesses"]):
            for wi_item in wit_items:
                if not wi_item: continue
                if wi_item[0] == 0x30:
                    found = detect_der_in_bytes(wi_item)
                    for item in found:
                        r_hex = item["r_hex"]
                        s_hex = item["s_hex"]
                        sighash = item["sighash_hex"]
                        pubkey_hex = ""
                        if len(wit_items) >= 2:
                            for possible in wit_items:
                                if len(possible) in (33,65) and possible[0] in (0x02,0x03,0x04):
                                    pubkey_hex = possible.hex()
                                    break
                        if not pubkey_hex:
                            pubkey_hex = find_pubkey_in_blob_after(wi_item, item["pos"] + len(item["der_bytes"]))
                        rows.append({
                            "r_hex": r_hex,
                            "s_hex": s_hex,
                            "txid": txid,
                            "input_index": idx,
                            "pubkey_hex": pubkey_hex,
                            "prev_txid": tx["inputs"][idx]["prev_txid"],
                            "prev_vout": tx["inputs"][idx]["prev_index"],
                            "sighash_type": sighash,
                            "raw_tx_hex": rawhex
                        })  

# group by r and pubkey (for summary) but CSV will include all rows  
by_r_pub = defaultdict(list)
for row in rows:
    key = (row['r_hex'], row['pubkey_hex'] if row['pubkey_hex'] else "NOPUB")
    by_r_pub[key].append(row)

# === Add only r_hex iteration calculation ===
r_count = defaultdict(int)
for row in rows:
    r_count[row['r_hex']] += 1
for row in rows:
    row['r_repeats'] = r_count[row['r_hex']]
# =================================

# write CSV  
outname = "der_full_summary.csv"
with open(outname, "w", newline='', encoding='utf-8') as csvfile:
    fieldnames = ["r_hex","r_repeats","s_hex","txid","input_index","pubkey_hex","prev_txid","prev_vout","sighash_type","raw_tx_hex"]
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()

    total_rows = sum(len(pubs) for pubs in by_r_pub.values())
    print(f"📝 Writing {total_rows:,} rows to {outname} ...")

    for r, pubs in tqdm(by_r_pub.items(), total=len(by_r_pub), desc="Writing CSV", unit="group"):
        for item in pubs:
            writer.writerow(item)

# print summary  
print("Summary: candidate groups with same r and same pubkey (count >=2):")
found_flag = False
for key, lst in by_r_pub.items():
    if len(lst) >= 2 and key[0] != "":
        found_flag = True
        print(f"r={key[0]} pubkey={key[1]} count={len(lst)}")
        for item in lst:
            print("  txid", item['txid'], "input", item['input_index'], "prev", f"{item['prev_txid']}:{item['prev_vout']}", "s", item['s_hex'][:16]+"...", "sighash", item['sighash_type'])
if not found_flag:
    print("No candidate duplicate r found in parsed DER signatures. Check der_full_summary.csv for all signatures extracted.")  

print("Wrote", outname)