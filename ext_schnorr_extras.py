#!/usr/bin/env python3
# Copyright (c) 2025 Abdallah
# Licensed under the GNU GPLv3
# Repo: https://github.com/abdallahbn31/reused-r-bitcoin
"""
ext_schnorr_extras.py

Reads rawtxs.txt (one raw tx hex per line), extracts Schnorr-like signatures (witness items length 64 or 65),
optionally fetches prevout info from Blockstream Esplora (mainnet or testnet), and writes schnorr_extracted.csv.

Usage:
  python3 ext_schnorr_extras.py rawtxs.txt        # no network calls
  python3 ext_schnorr_extras.py rawtxs.txt --fetch-prev --testnet

WARNING: This tool is for local analysis / educational use. Do not use it to attack others.
"""
import sys, re, csv, time, argparse
from collections import defaultdict
from hashlib import sha256
import requests
from tqdm import tqdm  # ✅ Added to display progress bar

REQUEST_TIMEOUT = 15
RETRIES = 3
RETRY_DELAY = 1.0

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

def parse_tx(rawhex: str):
    b = bytes.fromhex(rawhex)
    p = 0
    L = len(b)
    version = int.from_bytes(b[p:p+4], "little"); p += 4
    is_segwit = False
    if p+1 < L and b[p] == 0x00 and b[p+1] == 0x01:
        p += 2
        is_segwit = True
    n_in, p = read_varint(b, p)
    inputs = []
    for i in range(n_in):
        prev = b[p:p+32][::-1].hex(); p += 32
        prev_index = int.from_bytes(b[p:p+4], "little"); p += 4
        slen, p = read_varint(b, p)
        scriptSig = b[p:p+slen]; p += slen
        sequence = int.from_bytes(b[p:p+4], "little"); p += 4
        inputs.append({"prev_txid": prev, "prev_index": prev_index, "scriptSig": scriptSig, "sequence": sequence})
    n_out, p = read_varint(b, p)
    outputs = []
    for i in range(n_out):
        value = int.from_bytes(b[p:p+8], "little"); p += 8
        olen, p = read_varint(b, p)
        scriptPubKey = b[p:p+olen]; p += olen
        outputs.append({"value": value, "scriptPubKey": scriptPubKey})
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
    return {"version": version, "is_segwit": is_segwit, "inputs": inputs, "outputs": outputs, "witnesses": witnesses, "raw_bytes": b}

def detect_schnorr_in_witness_item(item: bytes):
    L = len(item)
    if L == 64 or L == 65:
        R = item[:32].hex()
        s = item[32:64].hex()
        flag = item[64:].hex() if L == 65 else ""
        return {"R_hex": R, "s_hex": s, "flag_hex": flag, "raw": item.hex()}
    return None

def blockstream_base(testnet: bool):
    return "https://blockstream.info/testnet/api" if testnet else "https://blockstream.info/api"

def fetch_tx_hex(txid: str, testnet: bool):
    base = blockstream_base(testnet)
    url = f"{base}/tx/{txid}/hex"
    last_err = ""
    for attempt in range(1, RETRIES+1):
        try:
            r = requests.get(url, timeout=REQUEST_TIMEOUT)
            if r.status_code == 200:
                return r.text.strip()
            last_err = f"HTTP {r.status_code}"
        except Exception as e:
            last_err = str(e)
        time.sleep(RETRY_DELAY * attempt)
    raise RuntimeError(f"fetch_tx_hex failed: {last_err}")

def fetch_prevout_info(prev_txid: str, vout: int, testnet: bool):
    try:
        raw = fetch_tx_hex(prev_txid, testnet=testnet)
        parsed = parse_tx(raw)
        if vout < len(parsed["outputs"]):
            out = parsed["outputs"][vout]
            return {"value": out["value"], "scriptpubkey_hex": out["scriptPubKey"].hex()}
        else:
            return {"value": None, "scriptpubkey_hex": None}
    except Exception as e:
        return {"value": None, "scriptpubkey_hex": None, "error": str(e)}

# ------- BIP340 tagged hash helpers -------
def tagged_hash(tag: bytes, msg: bytes) -> bytes:
    th = sha256(tag).digest()
    return sha256(th + th + msg).digest()

def compute_bip340_challenge(Rx_hex: str, Px_hex: str, m_bytes: bytes) -> str:
    """Return hex of challenge digest (big-endian) used in BIP340: SHA256(SHA256(tag)||SHA256(tag)||Rx||Px||m)."""
    try:
        Rxb = bytes.fromhex(Rx_hex)
        Pxb = bytes.fromhex(Px_hex)
        th = tagged_hash(b"BIP0340/challenge", Rxb + Pxb + m_bytes)
        return th.hex()
    except Exception:
        return ""

def extract_px_from_witness_and_script(witness_items, scriptpubkey_hex):
    """
    Try to extract x-only pubkey (32 bytes hex) from witness items or scriptPubKey:
      - If witness contains 32-byte item -> assume x-only (taproot internal key or revealed key)
      - If scriptpubkey_hex startswith '5120' -> taproot output: push32 follows
      - If scriptpubkey_hex startswith '0014' -> P2WPKH (not x-only) - return empty
    Returns (px_hex, source_str)
    """
    # check witness items first
    for it in witness_items:
        if isinstance(it, bytes) and len(it) == 32:
            return it.hex(), "witness_32"
        if isinstance(it, bytes) and len(it) == 33:
            # compressed pubkey -> x-only is x (bytes[1:33])
            return it[1:33].hex(), "witness_comp33_to_x"
    # check scriptPubKey
    spk = (scriptpubkey_hex or "").lower()
    if spk.startswith("5120") and len(spk) >= 4 + 64:
        return spk[4:4+64], "scriptpubkey_p2tr"
    # else not available
    return "", ""

def main():
    parser = argparse.ArgumentParser(description="Extract Schnorr signatures from raw txs and optionally fetch prevouts")
    parser.add_argument("infile", help="rawtxs.txt (one raw tx hex per line)")
    parser.add_argument("--out", default="schnorr_extracted.csv", help="CSV output")
    parser.add_argument("--fetch-prev", action="store_true", help="Try to fetch prevout info from blockstream (requires internet)")
    parser.add_argument("--testnet", action="store_true", help="Use testnet.blockstream.info when fetching prevouts")
    args = parser.parse_args()

    rows = []
    total_tx = 0
    total_sigs = 0

    with open(args.infile, "r", encoding="utf-8") as f:
        lines = f.readlines()

    # ✅ Progress bar added here
    for ln in tqdm(lines, desc="🔍 Processing transactions", unit="tx"):
        h = ln.strip()
        if not h:
            continue
        cand = re.findall(r'[0-9a-fA-F]{40,}', h)
        raw = max(cand, key=len) if cand else h
        raw = raw.lower()
        total_tx += 1
        try:
            tx = parse_tx(raw)
        except Exception as e:
            print(f"[{total_tx}] parse error: {e}")
            continue
        txid = txid_from_rawhex(raw)
        if tx["is_segwit"]:
            for idx, wit in enumerate(tx["witnesses"]):
                for item in wit:
                    cand = detect_schnorr_in_witness_item(item)
                    if cand:
                        total_sigs += 1
                        prev = tx["inputs"][idx]
                        prev_txid = prev["prev_txid"]
                        prev_index = prev["prev_index"]
                        info = {"value": "", "scriptpubkey_hex": ""}
                        note = ""
                        if args.fetch_prev:
                            info = fetch_prevout_info(prev_txid, prev_index, args.testnet)
                            if info.get("value") is None:
                                note = info.get("error", "prev lookup failed")

                        # --- New fields ---
                        pubkey_x_hex, pubkey_source = extract_px_from_witness_and_script(wit, info.get("scriptpubkey_hex", ""))
                        m_hash_hex = ""
                        missing = []
                        if args.fetch_prev:
                            if info.get("value") is not None and info.get("scriptpubkey_hex") is not None:
                                m_hash_hex = sha256(b"taproot" + tx["raw_bytes"]).hexdigest()
                            else:
                                missing.append("prev_not_fetched")
                        else:
                            missing.append("prev_not_fetched_by_flag")

                        s_int = None
                        try:
                            s_int = int(cand["s_hex"], 16)
                        except Exception:
                            missing.append("s_not_hex")

                        can_run_sc_r = bool(pubkey_x_hex and m_hash_hex and cand.get("R_hex") and s_int is not None)
                        if not pubkey_x_hex:
                            missing.append("px_missing")
                        if not m_hash_hex:
                            missing.append("m_missing")
                        if not cand.get("R_hex"):
                            missing.append("R_missing")

                        rows.append({
                            "txid": txid, "input_index": idx, "prev_txid": prev_txid, "prev_index": prev_index,
                            "pubkey_x_hex": pubkey_x_hex, "pubkey_source": pubkey_source,
                            "R_hex": cand["R_hex"], "s_hex": cand["s_hex"], "s_int": "" if s_int is None else str(s_int), "flag_hex": cand["flag_hex"],
                            "m_hash_hex": m_hash_hex,
                            "prev_value_sats": "" if info.get("value") is None else str(info.get("value")),
                            "prev_scriptpubkey_hex": "" if info.get("scriptpubkey_hex") is None else info.get("scriptpubkey_hex"),
                            "can_run_sc_r": "yes" if can_run_sc_r else "no",
                            "missing_fields": ",".join(missing) if missing else "",
                            "note": note
                        })

    fieldnames = [
      "txid","input_index","prev_txid","prev_index",
      "pubkey_x_hex","pubkey_source",
      "R_hex","s_hex","s_int","flag_hex",
      "m_hash_hex",
      "prev_value_sats","prev_scriptpubkey_hex",
      "can_run_sc_r","missing_fields","note"
    ]
    with open(args.out, "w", newline="", encoding="utf-8") as csvf:
        w = csv.DictWriter(csvf, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow(r)

    print(f"Done. TXs scanned: {total_tx}, Schnorr-candidates found: {total_sigs}")
    print(f"CSV -> {args.out}")
    if args.fetch_prev:
        print("Prevout fetch attempted via Blockstream (mainnet/testnet as chosen).")
    print("Note: To compute Taproot sighash (message m) you need prev amounts + scriptPubKey and to follow BIP341 precisely.")

if __name__ == "__main__":
    main()