#!/usr/bin/env python3
"""
DiamondEye — Bypass Headers Fetcher
Создаёт JSON с шаблонами заголовков для обхода WAF/Cloudflare.
Сохраняет в res/lists/bypass_headers.json
"""

import os
import json
import argparse

current_dir = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(current_dir, "..", "res", "lists")
os.makedirs(OUTPUT_DIR, exist_ok=True)

BYPASS_TEMPLATES = {
    "cloudflare": {
        "CF-Connecting-IP": "RANDOM_IP",
        "X-Forwarded-For": "RANDOM_IP",
        "X-Real-IP": "RANDOM_IP",
        "True-Client-IP": "RANDOM_IP",
        "CF-RAY": "RANDOM_16_HEX",
        "CF-IPCountry": "RANDOM_COUNTRY"
    },
    "ovh": {
        "X-Forwarded-Proto": "https",
        "X-Forwarded-Ssl": "on",
        "X-Forwarded-Port": "443",
        "X-Forwarded-Host": "RANDOM_LOCALHOST",
        "X-Client-IP": "RANDOM_IP",
        "X-Originating-IP": "RANDOM_IP"
    },
    "waf": {
        "X-CSRFToken": "RANDOM_16_HEX",
        "X-Requested-With": "XMLHttpRequest",
        "X-Ajax-Navigation": "true",
        "X-Request-ID": "RANDOM_32_HEX"
    },
    "legit_session": {
        "Cookie": "session=RANDOM_32_HEX; _csrf=RANDOM_16_HEX",
        "X-CSRF-Token": "RANDOM_16_HEX",
        "Authorization": "Bearer RANDOM_32_HEX"
    }
}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default=OUTPUT_DIR)
    args = parser.parse_args()

    output_file = os.path.join(args.output, "bypass_headers.json")
    with open(output_file, "w") as f:
        json.dump(BYPASS_TEMPLATES, f, indent=2)

    print(f"✅ Bypass headers saved to {output_file}")

if __name__ == "__main__":
    main() 