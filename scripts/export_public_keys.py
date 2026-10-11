#!/usr/bin/env python3
"""Export public-only peer key files for least-privilege Qurion containers.

Run after scripts/generate_keys.py, or against existing hss_keys.json and
mme_keys.json. This script does not generate or change keypairs.
"""
import base64
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KEY_DIR = ROOT / "configs" / "qurion"


def export(role: str) -> None:
    source = KEY_DIR / f"{role}_keys.json"
    target = KEY_DIR / f"{role}_public.json"
    if not source.is_file():
        raise FileNotFoundError(f"Missing {source}; generate or provision keys first")
    data = json.loads(source.read_text())
    required = ("operator_id", "realm", "kem_public_key", "signing_public_key")
    missing = [field for field in required if not data.get(field)]
    if missing:
        raise ValueError(f"{source} missing fields: {', '.join(missing)}")
    public_data = {field: data[field] for field in required}
    for field in ("kem_algorithm", "sig_algorithm", "generated_at"):
        if field in data:
            public_data[field] = data[field]
    target.write_text(json.dumps(public_data, indent=2) + "\n")
    os.chmod(target, 0o644)
    print(f"Wrote public-only peer key file: {target}")


if __name__ == "__main__":
    export("hss")
    export("mme")
