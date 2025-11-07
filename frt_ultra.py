#!/usr/bin/env python3
# Copyright (c) 2025 Abdallah
# Licensed under the GNU GPLv3
# Repo: https://github.com/abdallahbn31/reused-r-bitcoin
"""
frt_ultra_resumable.py

Fetch raw Bitcoin tx hex from AtomicWallet Explorer pages, supports:
- --start-page : first page to fetch
- --end-page   : last page to fetch
- --resume     : read state file and continue where left off (now resumes inside page)
- --state-file : JSON file for saving progress
- --append     : append to existing files
"""
import argparse
import csv
import time
import requests
import json
import os
import threading
import re

REQUEST_TIMEOUT = 20
MAX_RETRIES = 4
RETRY_DELAY = 1.0
STATE_SAVE_EVERY = 10  # not strictly required now, we save every tx

stop_flag = False

def listen_for_stop():
    global stop_flag
    try:
        input("↩️ Press Enter at any time to stop the download and save the results...\n")
        stop_flag = True
    except:
        stop_flag = True

def save_state(state_file, state):
    try:
        tmp = state_file + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False, indent=2)
        os.replace(tmp, state_file)
    except Exception as e:
        print("[WARN] could not save state:", e)

def load_state(state_file):
    if not os.path.exists(state_file):
        return None
    try:
        with open(state_file, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print("[WARN] could not read state file:", e)
        return None

def fetch_page_txs(address, page):
    url = f"https://bitcoin.atomicwallet.io/address/{address}?page={page}"
    last_err = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            r = requests.get(url, timeout=REQUEST_TIMEOUT)
            if r.status_code == 200:
                html = r.text
                # Extract all txids from the page (approx.)
                txids = re.findall(r"/tx/([0-9a-fA-F]{64})", html)
                # preserve order, remove duplicates while keeping first occurrence
                return list(dict.fromkeys(txids))
            last_err = f"HTTP {r.status_code}"
        except Exception as e:
            last_err = str(e)
        if attempt < MAX_RETRIES:
            time.sleep(RETRY_DELAY * (2 ** (attempt-1)))
    print(f"[ERROR] Failed to fetch page {page}: {last_err}")
    return []

def fetch_raw_tx_hex(txid):
    url = f"https://mempool.space/api/tx/{txid}/hex"
    last_err = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            r = requests.get(url, timeout=REQUEST_TIMEOUT)
            if r.status_code == 200:
                return r.text.strip()
            last_err = f"HTTP {r.status_code}"
        except Exception as e:
            last_err = str(e)
        if attempt < MAX_RETRIES:
            time.sleep(RETRY_DELAY * (2 ** (attempt-1)))
    print(f"[ERROR] Failed to fetch raw hex {txid}: {last_err}")
    return None

def safe_flush_and_sync(f):
    try:
        f.flush()
        os.fsync(f.fileno())
    except Exception:
        # best-effort, ignore if not supported
        pass

def main():
    global stop_flag
    p = argparse.ArgumentParser(description="Fetch raw Bitcoin tx hex from AtomicWallet pages (resumable inside pages)")
    p.add_argument("--address", "-a", required=True)
    p.add_argument("--output", "-o", default="txs_raw.csv")
    p.add_argument("--rawtxt", default="rawtxs.txt")
    p.add_argument("--start-page", type=int, default=1)
    p.add_argument("--end-page", type=int, default=0)
    p.add_argument("--resume", action="store_true")
    p.add_argument("--state-file", default="fetch_state_atomic.json")
    p.add_argument("--append", action="store_true")
    args = p.parse_args()

    address = args.address.strip()
    start_page = args.start_page
    end_page = args.end_page if args.end_page > 0 else start_page
    state_file = args.state_file

    # load resume state if requested
    resume_state = None
    if args.resume:
        st = load_state(state_file)
        if st:
            resume_state = st
            # If last_page is greater than requested end_page, adjust end_page to continue where left
            resumed_page = st.get("last_page", start_page)
            print(f"[INFO] Found state: last_page={resumed_page}, last_page_index={st.get('last_page_index')}, last_txid={st.get('last_txid')}")
            # If the user supplied a smaller end_page than where we left off, we continue from resume page
            if resumed_page > end_page:
                print(f"[INFO] Adjusting end_page {end_page} -> {resumed_page} to continue resume")
                end_page = resumed_page
            # Start from the page where we left off if that page is >= start_page
            if resumed_page >= start_page:
                start_page = resumed_page

    threading.Thread(target=listen_for_stop, daemon=True).start()

    mode_csv = "a" if args.append and os.path.exists(args.output) else "w"
    mode_raw = "a" if args.append and os.path.exists(args.rawtxt) else "w"

    with open(args.output, mode_csv, newline="", encoding="utf-8") as csvf, open(args.rawtxt, mode_raw, encoding="utf-8") as rawf:
        writer = csv.writer(csvf)
        if mode_csv == "w":
            writer.writerow(["txid", "raw_hex"])

        # processed_total counts rows written in this run plus previous runs if append; we can also trust resume_state.processed_count
        processed_total = resume_state.get("processed_count", 0) if resume_state else 0

        for page in range(start_page, end_page + 1):
            if stop_flag:
                print("⏹️ Stopped by user.")
                break

            print(f"[INFO] Fetching page {page}...")
            txids = fetch_page_txs(address, page)
            if not txids:
                print(f"[INFO] page {page} contains no txids or failed to fetch.")
                # still save state that page was attempted
                save_state(state_file, {"last_page": page, "last_page_index": 0, "last_txid": None, "processed_count": processed_total, "timestamp": int(time.time())})
                continue

            # determine start index for this page based on resume state (if any)
            start_idx = 0
            if resume_state and page == resume_state.get("last_page"):
                # prefer to locate last_txid in the freshly fetched txids
                last_txid = resume_state.get("last_txid")
                last_idx = resume_state.get("last_page_index", 0)
                if last_txid and last_txid in txids:
                    start_idx = txids.index(last_txid) + 1
                    print(f"[RESUME] Found last_txid on page {page} at index {start_idx-1}; resuming at {start_idx}")
                else:
                    # if last_txid not present, fall back to last_page_index (if provided) or 0
                    start_idx = int(last_idx) if last_idx is not None else 0
                    print(f"[RESUME] last_txid not found on page {page}; resuming at index {start_idx} (last_page_index)")
            else:
                start_idx = 0

            # clamp start_idx
            if start_idx < 0:
                start_idx = 0
            if start_idx >= len(txids):
                print(f"[INFO] Nothing to do on page {page} (start_idx >= tx count).")
                # still update state to mark page processed
                save_state(state_file, {"last_page": page, "last_page_index": len(txids), "last_txid": txids[-1] if txids else None, "processed_count": processed_total, "timestamp": int(time.time())})
                continue

            # process txids from start_idx
            for i in range(start_idx, len(txids)):
                if stop_flag:
                    break
                txid = txids[i]
                raw = fetch_raw_tx_hex(txid) or ""
                writer.writerow([txid, raw])
                rawf.write((raw + "\n") if raw else "\n")
                processed_total += 1

                # flush & fsync so data is durable
                safe_flush_and_sync(csvf)
                safe_flush_and_sync(rawf)

                # save state after each processed tx (atomic save via save_state)
                state = {
                    "last_page": page,
                    "last_page_index": i + 1,   # next index to process on resume
                    "last_txid": txid,
                    "processed_count": processed_total,
                    "timestamp": int(time.time())
                }
                save_state(state_file, state)

                print(f"[{processed_total}] page={page} idx={i} txid={txid} raw_len={len(raw)}")

            # end of page

        # end of pages loop

    print("✅ Done.")
    print(" CSV:", args.output)
    print(" Raw lines:", args.rawtxt)
    print(" State file:", state_file)

if __name__ == "__main__":
    main()