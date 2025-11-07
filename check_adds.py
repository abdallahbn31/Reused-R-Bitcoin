#!/usr/bin/env python3
# Copyright (c) 2025 Abdallah
# Licensed under the GNU GPLv3
# Repo: https://github.com/abdallahbn31/reused-r-bitcoin
import argparse
import csv
import time
import requests
import os  # [ADDED for resume feature]
import threading  # [ADDED for stop-on-enter]
from typing import Tuple, Optional

REQUEST_TIMEOUT = 15
MAX_RETRIES = 3
RETRY_DELAY = 1.0

SOCHAIN_NETS = {
    "btc": ("BTCTEST", "BTC"),
    "ltc": ("LTCTEST", "LTC"),
    "doge": ("DOGETEST", "DOGE"),
}

# [ADDED for stop-on-enter]
stop_requested = False
def wait_for_enter():
    global stop_requested
    try:
        input("Press ENTER at any time to stop safely...\n")
        stop_requested = True
    except Exception:
        pass
threading.Thread(target=wait_for_enter, daemon=True).start()

def mempool_base(testnet: bool) -> str:
    return "https://mempool.space/testnet/api" if testnet else "https://mempool.space/api"

def get_btc_balance_mempool(address: str, testnet: bool, retries=MAX_RETRIES) -> Tuple[bool, Optional[int], Optional[str]]:
    base = mempool_base(testnet)
    url = f"{base}/address/{address}"
    last_err = None
    for attempt in range(1, retries + 1):
        try:
            r = requests.get(url, timeout=REQUEST_TIMEOUT)
            if r.status_code == 200:
                j = r.json()
                chain = j.get("chain_stats", {})
                funded = int(chain.get("funded_txo_sum", 0))
                spent = int(chain.get("spent_txo_sum", 0))
                balance = funded - spent
                return True, balance, None
            else:
                last_err = f"HTTP {r.status_code}: {r.text[:200]}"
        except Exception as e:
            last_err = str(e)
        if attempt < retries:
            time.sleep(RETRY_DELAY * (2 ** (attempt - 1)))
    return False, None, last_err

def get_sochain_balance(address: str, coin: str, testnet: bool, retries=MAX_RETRIES) -> Tuple[bool, Optional[float], Optional[str]]:
    params = SOCHAIN_NETS.get(coin)
    if not params:
        return False, None, "unsupported coin for sochain"
    net_name = params[0] if testnet else params[1]
    url = f"https://sochain.com/api/v2/get_address_balance/{net_name}/{address}"
    last_err = None
    for attempt in range(1, retries + 1):
        try:
            r = requests.get(url, timeout=REQUEST_TIMEOUT)
            if r.status_code != 200:
                last_err = f"HTTP {r.status_code}"
            else:
                j = r.json()
                if j.get("status") != "success":
                    last_err = f"sochain error: {j}"
                else:
                    data = j.get("data", {})
                    bal_str = data.get("confirmed_balance") or data.get("balance") or "0"
                    try:
                        bal = float(bal_str)
                    except Exception:
                        bal = 0.0
                    return True, bal, None
        except Exception as e:
            last_err = str(e)
        if attempt < retries:
            time.sleep(RETRY_DELAY * (2 ** (attempt - 1)))
    return False, None, last_err

def get_balance(address: str, coin: str, testnet: bool):
    coin = coin.lower()
    if coin == "btc":
        ok, bal_sats, err = get_btc_balance_mempool(address, testnet)
        if ok:
            return True, bal_sats / 1e8, bal_sats, None
        else:
            return False, None, None, err
    elif coin in ("ltc", "doge"):
        ok, bal, err = get_sochain_balance(address, coin, testnet)
        if ok:
            return True, bal, None, None
        else:
            return False, None, None, err
    else:
        return False, None, None, f"unsupported coin: {coin}"

def process_file(input_path, output_path, coin, testnet, delay):
    # read all addresses from input
    with open(input_path, "r", encoding="utf-8") as f:
        addrs = [ln.strip() for ln in f if ln.strip()]
    total = len(addrs)

    # [ADDED for resume feature] read already-processed addresses from output csv if exists
    processed_addrs = set()
    if os.path.exists(output_path):
        try:
            with open(output_path, "r", encoding="utf-8") as existing:
                reader = csv.DictReader(existing)
                for row in reader:
                    # assume fieldname "address" exists as in original output
                    a = row.get("address")
                    if a:
                        processed_addrs.add(a.strip())
        except Exception:
            pass

    remaining = [a for a in addrs if a not in processed_addrs]
    print(f"Found {total} addresses. Coin={coin} testnet={testnet}")
    print(f"{len(processed_addrs)} already processed, {len(remaining)} remaining.")

    if not remaining:
        print("All addresses already processed. Nothing to do.")
        return

    # open output in append mode and write header if needed
    write_header = not os.path.exists(output_path)
    with open(output_path, "a", newline="", encoding="utf-8") as csvf:
        fieldnames = ["address", "coin", "testnet", "checked_ok", "balance", "balance_sats", "error"]
        writer = csv.DictWriter(csvf, fieldnames=fieldnames)
        if write_header:
            writer.writeheader()

        total_remaining = len(remaining)
        for idx, a in enumerate(remaining, start=1):
            # before processing each address, allow immediate stop if requested
            if stop_requested:
                print("\nStop requested by user (ENTER). Progress saved. Exiting safely...")
                return

            success, bal_coin, bal_sats, error = get_balance(a, coin, testnet)
            row = {
                "address": a,
                "coin": coin.lower(),
                "testnet": "yes" if testnet else "no",
                "checked_ok": "yes" if success else "no",
                "balance": "" if bal_coin is None else f"{bal_coin:.8f}",
                "balance_sats": "" if bal_sats is None else str(bal_sats),
                "error": "" if error is None else error
            }
            writer.writerow(row)
            csvf.flush()  # [ADDED for resume feature]
            processed_addrs.add(a)

            print(f"[{idx}/{total_remaining}] {a} -> ok={row['checked_ok']} balance={row['balance']} err={row['error'] or '-'}")

            # check stop request after finishing this address row (ensure safe exit after writing)
            if stop_requested:
                print("\nStop requested by user (ENTER). Progress saved. Exiting safely...")
                return

            if idx != total_remaining and delay > 0:
                time.sleep(delay)

    print(f"✅ The results were saved in: {output_path}")
    print("Progress saved. You can safely rerun this script anytime to continue.")

if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Check balances for addresses from a file and write CSV.")
    p.add_argument("--input", "-i", default="adds.txt", help="Input file with one address per line")
    p.add_argument("--output", "-o", default="balances.csv", help="CSV output file")
    p.add_argument("--coin", default="btc", help="Coin: btc, ltc, doge (default: btc)")
    p.add_argument("--testnet", action="store_true", help="Use testnet")
    p.add_argument("--delay", type=float, default=0.5, help="Delay between requests")
    args = p.parse_args()

    process_file(args.input, args.output, coin=args.coin, testnet=args.testnet, delay=args.delay)