#!/usr/bin/env python3

from crypto_utils import encrypt_patch
from pathlib import Path

DEVICE_AES_KEY = bytes([
    0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,
    0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF
])

encrypted_patch = Path("storage/patches/patch_1.0.0_to_1.0.1.bsdiff.enc")
if encrypted_patch.exists():
    with open(encrypted_patch, "rb") as f:
        data = f.read()
    print(f"Encrypted patch size: {len(data)} bytes")
    print(f"First 32 bytes (hex): {data[:32].hex()}")
    print(f"Format: REM1 (4) + nonce (16) + ciphertext + tag (32)")
    print(f"Magic: {data[:4]}")
    print(f"Nonce: {data[4:20].hex()}")
    print(f"Ciphertext length: {len(data) - 4 - 16 - 32} bytes")
else:
    print("ERROR: Encrypted patch not found!")
    print("Run: curl -X POST 'http://192.168.8.136:8000/make_patch/' -F 'old_version=1.0.0' -F 'new_version=1.0.1'")

