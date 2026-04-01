#!/usr/bin/env python3
"""
DiamondEye — Large Domains Fetcher
Домены с большими DNS-ответами (для амплификации).
Сохраняет в wordlists/large_domains.txt
"""

import os
import argparse

current_dir = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(current_dir, "..", "wordlists")
os.makedirs(OUTPUT_DIR, exist_ok=True)

LARGE_DOMAINS = [
    'ripe.net',
    'isc.org',
    'arin.net',
    'lacnic.net',
    'afrinic.net',
    'dns.google',
]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default=OUTPUT_DIR)
    args = parser.parse_args()

    with open(os.path.join(args.output, "large_domains.txt"), "w") as f:
        for dom in LARGE_DOMAINS:
            f.write(dom + "\n")

    print(f"✅ Large domains saved: {len(LARGE_DOMAINS)}")

if __name__ == "__main__":
    main()