#!/usr/bin/env python3
# Copyright (c) 2025 Abdallah
# Licensed under the GNU GPLv3
# Repo: https://github.com/abdallahbn31/reused-r-bitcoin
"""
fetch_raw_txs.py

Like fetch_raw_txs.py but adds resume/start controls:
 - --resume : read state file and continue where left off
 - --state-file : path to JSON state file (default: fetch_state.json)
 - --start-after TXID : skip until this txid is seen, then start writing subsequent txids
 - --start-index N : skip first N txids from generator
 - --append : append to existing CSV/raw files instead of overwriting
 - periodic saving of state so you can start later and continue

Usage examples:
  python3 fetch_raw_txs.py -a 1Feex... -o txs_raw.csv --rawtxt rawtxs.txt --limit 300
  python3 fetch_raw_txs.py -a 1Feex... --resume
  python3 fetch_raw_txs.py -a 1Feex... --start-after <last_txid_from_previous_run> --limit 300
"""
import argparse
import csv
import time
import requests
import threading
import json
import os
from typing import Generator, Optional

REQUEST_TIMEOUT = 20
MAX_RETRIES = 4
RETRY_DELAY = 1.0
STATE_SAVE_EVERY = 10  # save state every N processed txs

stop_flag = False

def mempool_base(testnet: bool):
    return "https://mempool.space/testnet/api" if testnet else "https://mempool.space/api"

def _get_json_with_retries(url: str) -> Optional[object]:
    last_err = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            r = requests.get(url, timeout=REQUEST_TIMEOUT)
            if r.status_code == 200:
                return r.json()
            else:
                last_err = f"HTTP {r.status_code}"
        except Exception as e:
            last_err = str(e)
        if attempt < MAX_RETRIES:
            time.sleep(RETRY_DELAY * (2 ** (attempt-1)))
    print(f"[ERROR] GET {url} failed after {MAX_RETRIES} attempts: {last_err}")
    return None

def txids_generator_mempool(address: str, testnet: bool) -> Generator[str, None, None]:
    """
    Yield txids for address using Mempool Esplora API page-by-page.
    """
    base = mempool_base(testnet)
    url = f"{base}/address/{address}/txs"
    while True:
        if stop_flag:
            return
        j = _get_json_with_retries(url)
        if j is None:
            # stop generator on error
            return
        page_txids = [t.get("txid") for t in j if isinstance(t, dict) and "txid" in t]
        if not page_txids:
            return
        for txid in page_txids:
            if stop_flag:
                return
            yield txid
        # if fewer than page-size => finished
        if len(page_txids) < 25:
            return
        last = page_txids[-1]
        url = f"{base}/address/{address}/txs/chain/{last}"

def fetch_raw_tx_hex_mempool(txid: str, testnet: bool) -> Optional[str]:
    base = mempool_base(testnet)
    url = f"{base}/tx/{txid}/hex"
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

def listen_for_stop():
    global stop_flag
    try:
        input("↩️ Press Enter at any time to stop the download and save the results...\n")
        stop_flag = True
    except Exception:
        stop_flag = True

def save_state(state_file: str, state: dict):
    try:
        tmp = state_file + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False, indent=2)
        os.replace(tmp, state_file)
    except Exception as e:
        print("[WARN] could not save state:", e)

def load_state(state_file: str):
    if not os.path.exists(state_file):
        return None
    try:
        with open(state_file, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print("[WARN] could not read state file:", e)
        return None

def main():
    global stop_flag
    p = argparse.ArgumentParser(description="Stream fetch raw tx hex for a Bitcoin address (mempool) with resume support.")
    p.add_argument("--address", "-a", required=True, help="Bitcoin address")
    p.add_argument("--output", "-o", default="txs_raw.csv", help="CSV file (txid,raw_hex)")
    p.add_argument("--rawtxt", default="rawtxs.txt", help="raw hex per line")
    p.add_argument("--testnet", action="store_true", help="Use mempool testnet API")
    p.add_argument("--delay", type=float, default=0.25, help="Delay between raw tx fetches (s)")
    p.add_argument("--limit", type=int, default=0, help="Optional: max number of txids to process (0 = no limit)")
    p.add_argument("--start-index", type=int, default=0, help="Skip first N txids from generator")
    p.add_argument("--start-after", help="Skip until this txid is seen, then start from next one")
    p.add_argument("--resume", action="store_true", help="Read state file and continue where left off")
    p.add_argument("--state-file", default="fetch_state.json", help="State file path (JSON)")
    p.add_argument("--append", action="store_true", help="Append to output files instead of overwriting")
    args = p.parse_args()

    address = args.address.strip()
    testnet = args.testnet
    delay = max(0.0, args.delay)
    limit = args.limit if args.limit is not None and args.limit > 0 else 0
    start_index = max(0, args.start_index)
    start_after = args.start_after
    state_file = args.state_file

    # handle resume
    if args.resume:
        st = load_state(state_file)
        if st:
            print("[INFO] Loaded state from", state_file)
            # if state contains last_txid and last_count, continue from next
            start_after = st.get("last_txid", start_after)
            # preserve start_index as the count already processed
            start_index = max(start_index, st.get("processed_count", 0))
            print(f"[INFO] will start after txid={start_after}, start_index={start_index}")
        else:
            print("[INFO] resume requested but no valid state file found; starting fresh.")

    print(f"Start fetching txids for {address} (testnet={testnet}). Limit={limit or 'none'}")
    # start stop listener
    threading.Thread(target=listen_for_stop, daemon=True).start()

    tx_gen = txids_generator_mempool(address, testnet=testnet)

    # open files (append or write)
    mode_csv = "a" if args.append and os.path.exists(args.output) else "w"
    mode_raw = "a" if args.append and os.path.exists(args.rawtxt) else "w"

    with open(args.output, mode_csv, newline="", encoding="utf-8") as csvf, open(args.rawtxt, mode_raw, encoding="utf-8") as rawf:
        writer = csv.writer(csvf)
        # if new file (write mode) write header
        if mode_csv == "w":
            writer.writerow(["txid", "raw_hex"])
        count = 0
        processed = 0  # number of txids written in this run
        skipped_by_index = 0
        skipped_by_start_after = False
        # if start_after provided we skip until we see it; if not provided start immediately
        need_skip_until_txid = start_after is not None
        # if start_index > 0 skip that many yields
        to_skip_index = start_index

        for txid in tx_gen:
            if stop_flag:
                print("⏹️ Stopped at your request.")
                break

            # apply start-index skip
            if to_skip_index > 0:
                to_skip_index -= 1
                skipped_by_index += 1
                count += 1
                continue

            # apply start-after skip
            if need_skip_until_txid:
                if not skipped_by_start_after:
                    # still skipping until we find the marker txid
                    if txid == start_after:
                        # found the marker; next txid will be first we save
                        skipped_by_start_after = True
                        print(f"[INFO] found start-after marker txid {start_after}; next txid will be saved.")
                        # do not save this marker txid; continue to next yield
                        continue
                    else:
                        count += 1
                        continue
                # else: already found marker; proceed normally

            # optional limit
            if limit and processed >= limit:
                print(f"[INFO] reached requested limit {limit}. Stopping.")
                break

            count += 1
            # fetch raw hex
            raw = fetch_raw_tx_hex_mempool(txid, testnet=testnet)
            if raw is None:
                raw = ""
            # write immediate
            writer.writerow([txid, raw])
            rawf.write((raw + "\n") if raw else ("\n"))
            processed += 1

            # update state periodically
            if processed % STATE_SAVE_EVERY == 0 or stop_flag or (limit and processed >= limit):
                state = {
                    "address": address,
                    "last_txid": txid,
                    "processed_count": start_index + processed,
                    "timestamp": int(time.time())
                }
                try:
                    save_state(state_file, state)
                except Exception as e:
                    print("[WARN] cannot save state:", e)

            print(f"[{count}] txid={txid}  raw_len={len(raw)}  (saved #{processed})")

            # polite delay (allow quick stop)
            if delay:
                # sleep in small chunks to respond to Enter quickly
                slept = 0.0
                chunk = 0.1
                while slept < delay:
                    if stop_flag:
                        break
                    time.sleep(min(chunk, delay - slept))
                    slept += chunk

        # final state save
        if processed > 0:
            last_saved_txid = txid
            final_state = {
                "address": address,
                "last_txid": last_saved_txid,
                "processed_count": start_index + processed,
                "timestamp": int(time.time())
            }
            save_state(state_file, final_state)

    print("✅ Done. Files saved:")
    print(" CSV:", args.output)
    print(" Raw lines:", args.rawtxt)
    print(" State file:", state_file)
    if stop_flag:
        print("Note: This was stopped manually — you can run the script later with --resume to resume.")
    else:
        print("You can run again with --resume or --start-after <last_txid> to capture the next batches.")

if __name__ == "__main__":
    main()