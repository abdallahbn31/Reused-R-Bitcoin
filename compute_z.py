#!/usr/bin/env python3
# Copyright (c) 2025 Abdallah
# Licensed under the GNU GPLv3
"""
compute_z.py (extended support for P2PKH, P2SH-P2WPKH, P2WPKH, P2WSH, P2TR)

Usage:
  python3 compute_z.py --input der_summary.csv --output der_with_z.csv [--fetch-prevouts]

Notes:
 - Supports Legacy (SIGHASH_ALL), SegWit v0 (BIP143) for P2WPKH/P2WSH and wrapped P2SH-P2WPKH.
 - Added best-effort support for Taproot (P2TR) key-path SIGHASH_ALL (BIP341-like).
 - If prev_value / prev_scriptPubKey missing, use --fetch-prevouts to query blockstream.info for prev txs.
"""
import argparse
import csv
csv.field_size_limit(10_000_000)
import requests
import time
from hashlib import sha256

# secp256k1 curve order n (constant)
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# configure input column names your CSV uses (change if your CSV uses other names)
INPUT_COLUMNS = {
    "txid": "txid",
    "raw_tx": "raw_tx_hex",
    "input_index": "input_index",
    "prev_txid": "prev_txid",
    "prev_vout": "prev_vout",
    "prev_value": "prev_value",               # satoshis (int)
    "prev_script": "prev_scriptPubKey",       # hex
    "sighash": "sighash_hex"
}

BLOCKSTREAM_BASE = "https://blockstream.info/api"

# ---------- helpers ----------
def dblsha(b: bytes) -> bytes:
    return sha256(sha256(b).digest()).digest()

def to_hex(b: bytes) -> str:
    return b.hex()

def read_varint_bytes(b: bytes, p: int):
    v = b[p]
    if v < 0xfd:
        return v, p+1
    if v == 0xfd:
        return int.from_bytes(b[p+1:p+3], "little"), p+3
    if v == 0xfe:
        return int.from_bytes(b[p+1:p+5], "little"), p+5
    return int.from_bytes(b[p+1:p+9], "little"), p+9

def serialize_varint(n: int) -> bytes:
    if n < 0xfd:
        return bytes([n])
    if n <= 0xffff:
        return b'\xfd' + n.to_bytes(2, "little")
    if n <= 0xffffffff:
        return b'\xfe' + n.to_bytes(4, "little")
    return b'\xff' + n.to_bytes(8, "little")

# lightweight parser to get fields needed (we will also use to reserialize for legacy)
def parse_tx(rawhex: str):
    b = bytes.fromhex(rawhex)
    p = 0
    L = len(b)
    version = int.from_bytes(b[p:p+4], "little"); p += 4
    is_segwit = False
    marker = None; flag = None
    if p+1 < L and b[p] == 0x00 and b[p+1] == 0x01:
        is_segwit = True
        marker = b[p]; flag = b[p+1]; p += 2
    n_in, p = read_varint_bytes(b, p)
    inputs = []
    for i in range(n_in):
        prev = b[p:p+32][::-1].hex(); p += 32
        prev_index = int.from_bytes(b[p:p+4], "little"); p += 4
        slen, p = read_varint_bytes(b, p)
        scriptSig = b[p:p+slen]; p += slen
        sequence = int.from_bytes(b[p:p+4], "little"); p += 4
        inputs.append({
            "prev_txid": prev,
            "prev_index": prev_index,
            "scriptSig": scriptSig,
            "sequence": sequence
        })
    n_out, p = read_varint_bytes(b, p)
    outputs = []
    for i in range(n_out):
        value = int.from_bytes(b[p:p+8], "little"); p += 8
        olen, p = read_varint_bytes(b, p)
        scriptPubKey = b[p:p+olen]; p += olen
        outputs.append({
            "value": value,
            "scriptPubKey": scriptPubKey
        })
    witnesses = []
    if is_segwit:
        for i in range(n_in):
            wit_count, p = read_varint_bytes(b, p)
            items = []
            for _ in range(wit_count):
                ilen, p = read_varint_bytes(b, p)
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
        "locktime": locktime
    }

# reserialize tx for legacy SIGHASH_ALL preimage (modified scriptSigs)
def serialize_tx_for_legacy_preimage(tx_struct, replace_script_for_index, script_to_put: bytes):
    # clone and replace script for that input; set others to empty
    version = tx_struct["version"].to_bytes(4, "little")
    n_in = len(tx_struct["inputs"])
    vin = b''
    vin += serialize_varint(n_in)
    for i, inp in enumerate(tx_struct["inputs"]):
        prev = bytes.fromhex(inp["prev_txid"])[::-1]
        prev_index = inp["prev_index"].to_bytes(4, "little")
        if i == replace_script_for_index:
            s = script_to_put
        else:
            s = b''
        vin += prev + prev_index + serialize_varint(len(s)) + s + inp["sequence"].to_bytes(4, "little")
    # outputs
    vout = b''
    vout += serialize_varint(len(tx_struct["outputs"]))
    for out in tx_struct["outputs"]:
        vout += out["value"].to_bytes(8, "little")
        vout += serialize_varint(len(out["scriptPubKey"])) + out["scriptPubKey"]
    locktime = tx_struct["locktime"].to_bytes(4, "little")
    return version + vin + vout + locktime

# Build BIP143 preimage (segwit v0) for a specific input index
def build_bip143_preimage(tx_struct, input_index, scriptCode: bytes, value_sats: int, sighash_type_int=1):
    # hashPrevouts
    buf = b''
    for inp in tx_struct["inputs"]:
        buf += bytes.fromhex(inp["prev_txid"])[::-1] + inp["prev_index"].to_bytes(4, "little")
    hashPrevouts = dblsha(buf)
    # hashSequence
    seq_buf = b''
    for inp in tx_struct["inputs"]:
        seq_buf += inp["sequence"].to_bytes(4, "little")
    hashSequence = dblsha(seq_buf)
    # outpoint
    inp = tx_struct["inputs"][input_index]
    outpoint = bytes.fromhex(inp["prev_txid"])[::-1] + inp["prev_index"].to_bytes(4, "little")
    # scriptCode (push-style) is provided as bytes (should be scriptPubKey of prevout or scriptCode)
    # value
    value = value_sats.to_bytes(8, "little")
    sequence = inp["sequence"].to_bytes(4, "little")
    # hashOutputs
    out_buf = b''
    for out in tx_struct["outputs"]:
        out_buf += out["value"].to_bytes(8, "little")
        out_buf += serialize_varint(len(out["scriptPubKey"])) + out["scriptPubKey"]
    hashOutputs = dblsha(out_buf)
    version = tx_struct["version"].to_bytes(4, "little")
    locktime = tx_struct["locktime"].to_bytes(4, "little")
    sighash = sighash_type_int.to_bytes(4, "little")
    preimage = (
        version + hashPrevouts + hashSequence + outpoint +
        serialize_varint(len(scriptCode)) + scriptCode + value + sequence +
        hashOutputs + locktime + sighash
    )
    return preimage

# fetch prevout info from blockstream: returns {value:int, scriptPubKey:hex}
def fetch_prevout_from_blockstream(txid: str, vout: int):
    # fetch tx hex then parse outputs
    url = f"{BLOCKSTREAM_BASE}/tx/{txid}/hex"
    r = requests.get(url, timeout=15)
    if r.status_code != 200:
        raise RuntimeError(f"Blockstream fetch failed {r.status_code}")
    raw = r.text.strip()
    tx = parse_tx(raw)
    if vout < 0 or vout >= len(tx["outputs"]):
        raise RuntimeError("vout out of range")
    out = tx["outputs"][vout]
    return {"value": out["value"], "scriptPubKey": out["scriptPubKey"].hex()}

# ----------------- new helpers for script type detection -----------------
def hex_to_bytes(h):
    if h is None:
        return None
    if isinstance(h, bytes):
        return h
    return bytes.fromhex(h)

def is_p2wpkh(spk):
    return len(spk) == 22 and spk[0] == 0x00 and spk[1] == 0x14

def is_p2wsh(spk):
    return len(spk) == 34 and spk[0] == 0x00 and spk[1] == 0x20

def is_p2sh(spk):
    return len(spk) >= 3 and spk[0] == 0xa9 and spk[-1] == 0x87

def is_p2pkh(spk):
    return len(spk) == 25 and spk[0] == 0x76 and spk[1] == 0xa9 and spk[-2] == 0x88 and spk[-1] == 0xac

def is_p2tr(spk):
    # P2TR scriptPubKey bytes are OP_1 (0x51) PUSH32 (0x20) <32>
    return len(spk) == 34 and spk[0] == 0x51 and spk[1] == 0x20

def construct_p2pkh_scriptcode_from_pubkeyhash(pubkey_hash20: bytes) -> bytes:
    # OP_DUP OP_HASH160 PUSH20 <20> OP_EQUALVERIFY OP_CHECKSIG
    return b'\x76\xa9\x14' + pubkey_hash20 + b'\x88\xac'

def extract_redeem_from_scriptsig(scriptsig_bytes: bytes):
    # scriptsig typically: <push(redeemScript)> possibly with more pushes
    if not scriptsig_bytes:
        return b''
    p = 0
    L = len(scriptsig_bytes)
    # try to parse first push
    try:
        opcode = scriptsig_bytes[0]
        if opcode <= 0x4b:
            ln = opcode
            return scriptsig_bytes[1:1+ln]
        if opcode == 0x4c:  # OP_PUSHDATA1
            ln = scriptsig_bytes[1]
            return scriptsig_bytes[2:2+ln]
        if opcode == 0x4d:  # OP_PUSHDATA2
            ln = int.from_bytes(scriptsig_bytes[1:3], "little")
            return scriptsig_bytes[3:3+ln]
    except Exception:
        pass
    return b''

# ------- helpers for Taproot sighash (BIP341-like for key-path SIGHASH_ALL) -------
def tagged_hash_bytes(tag: bytes, msg: bytes) -> bytes:
    th = sha256(tag).digest()
    return sha256(th + th + msg).digest()

def compute_taproot_sighash(tx_struct, input_index, prevouts_info, sighash_type_int=1):
    """
    Build a BIP341-like Taproot key-path sighash for SIGHASH_ALL (sighash_type_int==1).
    prevouts_info: list/dict of tuples for each input -> (value:int, scriptPubKey:bytes)
    This function builds the components (hashPrevouts, hashAmounts, hashScriptPubKeys, hashSequences, hashOutputs)
    and constructs a preimage similar to BIP341 key-path sighash for SIGHASH_ALL.
    NOTE: This function is focused on SIGHASH_ALL key-path; annex/script-path/special sighash variants not fully supported.
    """
    # Collect hashPrevouts
    hp = b''
    for inp in tx_struct["inputs"]:
        hp += bytes.fromhex(inp["prev_txid"])[::-1] + inp["prev_index"].to_bytes(4, "little")
    hashPrevouts = dblsha(hp)

    # hashAmounts
    ha = b''
    for i, inp in enumerate(tx_struct["inputs"]):
        val = prevouts_info.get(i, (None, None))[0]
        if val is None:
            raise ValueError("missing_prev_value_for_taproot")
        ha += int(val).to_bytes(8, "little")
    hashAmounts = dblsha(ha)

    # hashScriptPubKeys
    hspk = b''
    for i, inp in enumerate(tx_struct["inputs"]):
        spk = prevouts_info.get(i, (None, None))[1]
        if spk is None:
            raise ValueError("missing_prev_script_for_taproot")
        # pushvar(script length) + script bytes
        hspk += serialize_varint(len(spk)) + spk
    hashScriptPubKeys = dblsha(hspk)

    # hashSequences
    hs = b''
    for inp in tx_struct["inputs"]:
        hs += inp["sequence"].to_bytes(4, "little")
    hashSequences = dblsha(hs)

    # hashOutputs
    hout = b''
    for out in tx_struct["outputs"]:
        hout += out["value"].to_bytes(8, "little")
        hout += serialize_varint(len(out["scriptPubKey"])) + out["scriptPubKey"]
    hashOutputs = dblsha(hout)

    # input being spent
    inp = tx_struct["inputs"][input_index]
    outpoint = bytes.fromhex(inp["prev_txid"])[::-1] + inp["prev_index"].to_bytes(4, "little")
    amount = prevouts_info[input_index][0].to_bytes(8, "little")
    scriptPubKey = prevouts_info[input_index][1]
    seq = inp["sequence"].to_bytes(4, "little")

    # annex (not handled) -> empty
    annex_hash = dblsha(b'')

    # Build the sighash message (BIP341-like structure for key-path)
    # Fields order (adapted): tx_version || locktime || hashPrevouts || hashAmounts || hashScriptPubKeys ||
    # hashSequences || hashOutputs || outpoint || amount || scriptPubKey_len+scriptPubKey || sequence || annex_hash || sighash_type
    msg = (
        tx_struct["version"].to_bytes(4, "little") +
        tx_struct["locktime"].to_bytes(4, "little") +
        hashPrevouts + hashAmounts + hashScriptPubKeys + hashSequences + hashOutputs +
        outpoint + amount + serialize_varint(len(scriptPubKey)) + scriptPubKey + seq +
        annex_hash + sighash_type_int.to_bytes(4, "little")
    )
    # Tagged hash as BIP341 style
    return tagged_hash_bytes(b"TapSighash", msg)

# fetch all prevouts for a tx (returns dict index -> (value, scriptPubKey_bytes))
def fetch_all_prevouts_for_tx(tx_struct):
    prevs = {}
    for i, inp in enumerate(tx_struct["inputs"]):
        prev_txid = inp["prev_txid"]
        prev_vout = inp["prev_index"]
        info = fetch_prevout_from_blockstream(prev_txid, prev_vout)
        prevs[i] = (info["value"], bytes.fromhex(info["scriptPubKey"]))
    return prevs

# compute z for a row (tries segwit first if tx is segwit; falls back to legacy)
def compute_z_for_row(row, fetch_prevouts=False):
    # read fields from row dict with fallback names
    txid = row.get(INPUT_COLUMNS["txid"]) or row.get("txid")
    rawhex = row.get(INPUT_COLUMNS["raw_tx"]) or row.get("raw_tx")
    input_index = int(row.get(INPUT_COLUMNS["input_index"] or "0") or 0)
    prev_txid = row.get(INPUT_COLUMNS["prev_txid"]) or row.get("prev_txid")
    prev_vout = row.get(INPUT_COLUMNS["prev_vout"]) or row.get("prev_vout")
    prev_value = row.get(INPUT_COLUMNS["prev_value"]) or row.get("prev_value")
    prev_script = row.get(INPUT_COLUMNS["prev_script"]) or row.get("prev_scriptPubKey")
    sighash_hex = row.get(INPUT_COLUMNS["sighash"]) or row.get("sighash_hex") or ""
    sighash_int = int(sighash_hex, 16) if sighash_hex else 1  # default SIGHASH_ALL

    # try parse raw tx if available
    if rawhex:
        try:
            tx = parse_tx(rawhex)
        except Exception as e:
            return (None, "unknown", f"parse_raw_tx_failed: {e}")
    else:
        tx = None

    # Helper: get prev_script bytes (may come from CSV or via fetch)
    prev_script_bytes = None
    if isinstance(prev_script, str) and prev_script != "":
        try:
            prev_script_bytes = bytes.fromhex(prev_script)
        except Exception:
            prev_script_bytes = None

    # We'll determine detected script type (for CSV column)
    detected_script_type = "unknown"

    # If tx is segwit (or parsed as segwit) and we have prev_value and script info, build BIP143 preimage
    if tx and tx["is_segwit"]:
        # ensure prev_value available
        if prev_value is None or prev_value == "":
            # try fetch from blockstream if allowed
            if fetch_prevouts and prev_txid and prev_vout is not None and prev_vout != "":
                try:
                    info = fetch_prevout_from_blockstream(prev_txid, int(prev_vout))
                    prev_value = info["value"]
                    prev_script_bytes = bytes.fromhex(info["scriptPubKey"])
                except Exception as e:
                    return (None, "unknown", f"missing_prev_value_and_fetch_failed: {e}")
            else:
                return (None, "unknown", "missing_prev_value_for_segwit")
        try:
            value_sats = int(prev_value)
        except:
            return (None, "unknown", "invalid_prev_value")

        # if prev_script_bytes not present, try fetch if allowed
        if prev_script_bytes is None and fetch_prevouts and prev_txid and prev_vout not in (None, ""):
            try:
                info = fetch_prevout_from_blockstream(prev_txid, int(prev_vout))
                prev_script_bytes = bytes.fromhex(info["scriptPubKey"])
            except Exception as e:
                return (None, "unknown", f"missing_prev_script_and_fetch_failed: {e}")

        if prev_script_bytes is None:
            return (None, "unknown", "missing_prev_script_for_segwit")

        # decide scriptCode depending on scriptPubKey type
        scriptCode = None
        spk = prev_script_bytes

        # P2WPKH: 0x00 0x14 <20>
        if is_p2wpkh(spk):
            detected_script_type = "native_P2WPKH"
            prog20 = spk[2:22]
            scriptCode = construct_p2pkh_scriptcode_from_pubkeyhash(prog20)
        # P2WSH: 0x00 0x20 <32> -> need witness script from tx
        elif is_p2wsh(spk):
            detected_script_type = "P2WSH"
            # witness script should be last item in tx["witnesses"][input_index]
            try:
                wit_stack = tx["witnesses"][input_index]
                if not wit_stack or len(wit_stack) == 0:
                    return (None, detected_script_type, "missing_witness_stack_for_p2wsh")
                witness_script = wit_stack[-1]
                if not witness_script:
                    return (None, detected_script_type, "empty_witness_script_for_p2wsh")
                scriptCode = witness_script
            except Exception:
                return (None, detected_script_type, "unable_to_get_witness_for_p2wsh")
        # P2SH: try to extract redeemScript from scriptSig of spending tx
        elif is_p2sh(spk):
            detected_script_type = "nested_P2WPKH_or_P2SH"
            scriptsig = tx["inputs"][input_index]["scriptSig"]
            redeem = extract_redeem_from_scriptsig(scriptsig)
            if not redeem or len(redeem) == 0:
                return (None, detected_script_type, "missing_redeem_in_scriptsig_for_p2sh")
            # if redeem is 0x00 0x14 <20> -> it's wrapped P2WPKH
            if len(redeem) >= 2 and redeem[0] == 0x00 and redeem[1] == 0x14:
                prog20 = redeem[2:22]
                scriptCode = construct_p2pkh_scriptcode_from_pubkeyhash(prog20)
                detected_script_type = "nested_P2WPKH"
            else:
                # fallback: use redeem script as scriptCode (legacy P2SH redeem)
                scriptCode = redeem
        # P2PKH direct
        elif is_p2pkh(spk):
            detected_script_type = "legacy_P2PKH"
            scriptCode = spk
        # P2TR (Taproot) detection: OP_1 PUSH32 (0x51 0x20)
        elif is_p2tr(spk):
            detected_script_type = "P2TR"
            # For Taproot we will compute Taproot sighash (requires all prevouts)
            if not fetch_prevouts:
                return (None, detected_script_type, "taproot_requires_fetch_prevouts")
            # need to fetch all prevouts for full Taproot sighash
            try:
                prevs_info = fetch_all_prevouts_for_tx(tx)
            except Exception as e:
                return (None, detected_script_type, f"fetch_all_prevouts_failed: {e}")
            try:
                th = compute_taproot_sighash(tx, input_index, prevs_info, sighash_type_int=sighash_int)
                z = int.from_bytes(th, "big") % N
                return (z, detected_script_type, "ok (taproot key-path)")
            except Exception as e:
                return (None, detected_script_type, f"taproot_sighash_failed: {e}")
        else:
            # unknown scriptPubKey form — try using as-is (best-effort)
            detected_script_type = "unknown_segwit_spk"
            scriptCode = spk

        # now have scriptCode, build preimage for bip143
        if scriptCode is None:
            return (None, detected_script_type, "could_not_construct_scriptCode")
        try:
            preimage = build_bip143_preimage(tx, input_index, scriptCode, value_sats, sighash_int)
            hz = dblsha(preimage)
            z = int.from_bytes(hz, "big") % N
            return (z, detected_script_type, "ok (bip143 segwit)")
        except Exception as e:
            return (None, detected_script_type, f"bip143_build_failed: {e}")

    # else try legacy path (or segwit tx but no prev_value -> try legacy style)
    if tx:
        # need prev_script for the input index
        if prev_script is None or prev_script == "":
            # try to obtain prev_script from tx.inputs' scriptSig (not reliable) or fetch
            if tx["inputs"][input_index]["scriptSig"]:
                # not reliable: scriptSig contains signature+pubkey, not scriptPubKey; we still try
                pass
            if fetch_prevouts and prev_txid and prev_vout not in (None, ""):
                try:
                    info = fetch_prevout_from_blockstream(prev_txid, int(prev_vout))
                    prev_script = info["scriptPubKey"]
                except Exception as e:
                    return (None, "unknown", f"missing_prev_script_and_fetch_failed: {e}")
            else:
                return (None, "unknown", "missing_prev_script_for_legacy")
        script_bytes = bytes.fromhex(prev_script) if isinstance(prev_script, str) else prev_script
        # detect type for CSV
        if is_p2pkh(script_bytes):
            detected_script_type = "legacy_P2PKH"
        elif is_p2sh(script_bytes):
            detected_script_type = "P2SH"
        else:
            detected_script_type = "legacy_unknown"

        # build modified serialized tx with other inputs' scriptSigs empty and current input's script = script_bytes
        serialized = serialize_tx_for_legacy_preimage(tx, input_index, script_bytes)
        sighash_bytes = (sighash_int).to_bytes(4, "little")
        preimage = serialized + sighash_bytes
        hz = dblsha(preimage)
        z = int.from_bytes(hz, "big") % N
        return (z, detected_script_type, "ok (legacy)")

    # if no raw tx and no prev info, try fetch raw tx from blockstream if allowed
    if fetch_prevouts and txid:
        # fetch raw tx then recurse once
        try:
            r = requests.get(f"{BLOCKSTREAM_BASE}/tx/{txid}/hex", timeout=15)
            if r.status_code == 200:
                row2 = dict(row)
                row2[INPUT_COLUMNS["raw_tx"]] = r.text.strip()
                return compute_z_for_row(row2, fetch_prevouts=fetch_prevouts)
            else:
                return (None, "unknown", f"fetch_raw_tx_failed_http_{r.status_code}")
        except Exception as e:
            return (None, "unknown", f"fetch_raw_tx_failed_exception_{e}")
    return (None, "unknown", "insufficient_data")

# ---------- main ----------
def main():
    p = argparse.ArgumentParser(description="Compute z (message hash) for ECDSA signatures from der-summary CSV (extended, with Taproot)")
    p.add_argument("--input", "-i", required=True)
    p.add_argument("--output", "-o", default="der_with_z.csv")
    p.add_argument("--fetch-prevouts", action="store_true", help="If missing prevout info, fetch from blockstream")
    args = p.parse_args()

    rows = []
    with open(args.input, newline='', encoding='utf-8') as csvf:
        reader = csv.DictReader(csvf)
        for r in reader:
            rows.append(r)

    out_rows = []
    for idx, r in enumerate(rows, start=1):
        z_val, script_type, note = compute_z_for_row(r, fetch_prevouts=args.fetch_prevouts)
        out = dict(r)
        out["script_type"] = script_type
        if z_val is None:
            out["z_hex"] = ""
            out["z_int"] = ""
            out["z_mod_n"] = ""
            out["note"] = note
        else:
            z_hex = format(z_val, '064x')
            out["z_hex"] = z_hex
            out["z_int"] = str(z_val)
            out["z_mod_n"] = str(z_val % N)
            out["note"] = note
        out_rows.append(out)
        print(f"[{idx}/{len(rows)}] txid={r.get(INPUT_COLUMNS['txid'],'-')} type={script_type} note={out['note']}")

    # write output CSV
    fieldnames = list(out_rows[0].keys()) if out_rows else []
    with open(args.output, "w", newline='', encoding='utf-8') as csvf:
        writer = csv.DictWriter(csvf, fieldnames=fieldnames)
        writer.writeheader()
        for orow in out_rows:
            writer.writerow(orow)
    print("Wrote", args.output)

if __name__ == "__main__":
    main()