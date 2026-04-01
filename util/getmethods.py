#!/usr/bin/env python3
"""
DiamondEye — HTTP Methods Fetcher
Генерирует списки стандартных и fuzz-методов.
Сохраняет в wordlists/http_methods.txt и wordlists/http_methods_fuzz.txt
"""

import os
import argparse

current_dir = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(current_dir, "..", "wordlists")
os.makedirs(OUTPUT_DIR, exist_ok=True)

STANDARD_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD']
FUZZ_METHODS = ['PROPFIND', 'REPORT', 'MKCOL', 'LOCK', 'UNLOCK', 'TRACE', 'COPY', 'MOVE', 'PROPPATCH']

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default=OUTPUT_DIR)
    args = parser.parse_args()

    with open(os.path.join(args.output, "http_methods.txt"), "w") as f:
        for m in STANDARD_METHODS:
            f.write(m + "\n")
    print(f"✅ Standard methods: {len(STANDARD_METHODS)}")

    with open(os.path.join(args.output, "http_methods_fuzz.txt"), "w") as f:
        for m in FUZZ_METHODS:
            f.write(m + "\n")
    print(f"✅ Fuzz methods: {len(FUZZ_METHODS)}")

if __name__ == "__main__":
    main()