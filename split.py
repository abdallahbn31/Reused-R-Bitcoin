#!/usr/bin/env python3
# Copyright (c) 2025 Abdallah
# Licensed under the GNU GPLv3
# Repo: https://github.com/abdallahbn31/reused-r-bitcoin
import sys

def split_file(input_file, lines_per_file):
    with open(input_file, "rb") as f:  # We read raw bytes so that no character is lost.
        lines = f.read().splitlines(keepends=True)  # Split with preserving line breaks

    total_lines = len(lines)
    part_num = 1

    for i in range(0, total_lines, lines_per_file):
        part_lines = lines[i:i+lines_per_file]
        output_file = f"part_{part_num}.txt"
        with open(output_file, "wb") as out:
            out.writelines(part_lines)
        print(f"✔ Created: {output_file} ({len(part_lines)} line)")
        part_num += 1


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("⚠️ Usage: python3 split.py <input_file> <lines_per_file>")
        sys.exit(1)

    input_file = sys.argv[1]
    lines_per_file = int(sys.argv[2])

    split_file(input_file, lines_per_file)