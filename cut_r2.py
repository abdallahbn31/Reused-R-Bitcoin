#!/usr/bin/env python3
# Copyright (c) 2025 Abdallah
# Licensed under the GNU GPLv3
import csv
from collections import defaultdict
csv.field_size_limit(10**9)

# ====== tqdm progress bar ======
try:
    from tqdm import tqdm
except ImportError:
    print("tqdm library not found, installing it automatically...")
    import os
    os.system("pip install tqdm")
    from tqdm import tqdm
# ================================

input_file = "der_full_summary.csv"
output_file = "repeated_r.csv"

r_counts = defaultdict(int)

# ---Step 1: Count the repetitions ---
print("🧮 Counting r_hex repetitions...")

with open(input_file, "r", newline="", encoding="utf-8") as f:
    reader = csv.DictReader(f)
    for row in tqdm(reader, desc="Counting", unit="row", mininterval=1.0):
        r_counts[row["r_hex"]] += 1

# ---Step 2: Writing the repeated results ---
print("✍️ Writing rows with duplicate r ...")
with open(input_file, "r", newline="", encoding="utf-8") as f_in, \
     open(output_file, "w", newline="", encoding="utf-8") as f_out:

    reader = csv.DictReader(f_in)
    writer = csv.DictWriter(f_out, fieldnames=reader.fieldnames)
    writer.writeheader()

    for row in tqdm(reader, desc="Writing", unit="row", mininterval=1.0):
        if r_counts[row["r_hex"]] > 1:
            writer.writerow(row)

print(f"✅ Lines with duplicate r were extracted to: {output_file}")