#!/usr/bin/env python3
# Copyright (c) 2025 Abdallah
# Licensed under the GNU GPLv3
"""
hex_to_number.py

Reads an input file (default: hex.txt) where each line contains a hex value
(or arbitrary text that includes a hex substring). For each line the script:
 - extracts the longest contiguous hex substring (0-9, a-f, A-F),
 - strips optional "0x" prefix,
 - converts the hex to an integer,
 - writes a line to the output file with: original_hex, decimal_value

Usage:
  python3 hex_to_number.py            # uses hex.txt -> hextonumber.txt
  python3 hex_to_number.py in.txt out.txt
"""

import sys
import re
import os

HEX_RE = re.compile(r'[0-9a-fA-F]+')

def extract_hex_from_line(line: str):
    """Return the longest hex substring from the line (or None)."""
    line = line.strip()
    if not line:
        return None
    # remove common 0x prefix occurrences so regex finds the body easily
    line2 = line.replace('0x', ' ').replace('0X', ' ')
    candidates = HEX_RE.findall(line2)
    if not candidates:
        return None
    # choose the longest candidate (heuristic)
    best = max(candidates, key=len)
    return best

def hex_to_int(hexstr: str):
    """Convert hex string to int, raise ValueError if invalid."""
    # remove any leftover whitespace and ensure lower-case
    hs = hexstr.strip()
    # allow hex strings that might include spaces or separators? we keep simple:
    return int(hs, 16)

def process_file(input_path: str, output_path: str):
    if not os.path.isfile(input_path):
        print(f"[ERROR] input file not found: {input_path}")
        return 1

    total = 0
    converted = 0
    with open(input_path, 'r', encoding='utf-8', errors='replace') as fin, \
         open(output_path, 'w', encoding='utf-8') as fout:
        fout.write("hex_value,decimal_value\n")
        for ln in fin:
            total += 1
            original = ln.rstrip("\n")
            hex_candidate = extract_hex_from_line(original)
            if not hex_candidate:
                fout.write(f"{original},\n")  # no hex found -> blank decimal
                continue
            try:
                val = hex_to_int(hex_candidate)
                fout.write(f"{hex_candidate},{val}\n")
                converted += 1
            except Exception as e:
                fout.write(f"{hex_candidate},ERROR: {e}\n")

    print(f"Processed {total} lines. Converted {converted} hex values. Output: {output_path}")
    return 0

def main():
    args = sys.argv[1:]
    if len(args) == 0:
        infile = "hex.txt"
        outfile = "hextonumber.txt"
    elif len(args) == 1:
        infile = args[0]
        outfile = "hextonumber.txt"
    else:
        infile, outfile = args[0], args[1]
    sys.exit(process_file(infile, outfile))

if __name__ == "__main__":
    main()