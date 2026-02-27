#!/usr/bin/env python3

from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from pathlib import Path

def test_signature_verification():
    print("=== Testing Signature Verification ===\n")
    
    patch_file = Path("storage/patches/patch_1.0.0_to_1.0.1.bsdiff")
    sig_file = Path("storage/signatures/patch_1.0.0_to_1.0.1.sig")
    pubkey_file = Path("ecc_public.pem")
    
    if not patch_file.exists():
        print(f"ERROR: Patch file not found: {patch_file}")
        return False
    
    if not sig_file.exists():
        print(f"ERROR: Signature file not found: {sig_file}")
        return False
    
    if not pubkey_file.exists():
        print(f"ERROR: Public key not found: {pubkey_file}")
        return False
    
    print(f"1. Reading patch file: {patch_file}")
    with open(patch_file, 'rb') as f:
        patch_data = f.read()
    
    print(f"   Patch size: {len(patch_data)} bytes")
    
    print(f"\n2. Computing SHA-256 hash...")
    h = SHA256.new(patch_data)
    hash_hex = h.hexdigest()
    print(f"   Hash (hex): {hash_hex}")
    print(f"   Hash (first 8 bytes): {hash_hex[:16]}")
    
    print(f"\n3. Reading signature file: {sig_file}")
    with open(sig_file, 'rb') as f:
        signature = f.read()
    
    print(f"   Signature size: {len(signature)} bytes")
    print(f"   Signature (first 16 bytes hex): {signature[:16].hex() if len(signature) >= 16 else signature.hex()}")
    
    print(f"\n4. Loading public key: {pubkey_file}")
    with open(pubkey_file, 'rb') as f:
        public_key = ECC.import_key(f.read())
    
    print(f"   Key curve: {public_key.curve}")
    print(f"   Key size: {public_key.pointQ.size_in_bits()} bits")
    
    print(f"\n5. Verifying signature...")
    verifier = DSS.new(public_key, 'fips-186-3', encoding='der')
    try:
        verifier.verify(h, signature)
        print("   ✓ SIGNATURE VERIFICATION SUCCESSFUL!")
        print("\n   The signature is valid on the server side.")
        print("   If ESP32 verification fails, possible causes:")
        print("   - Public key on ESP32 doesn't match")
        print("   - Patch file on ESP32 is different (corrupted download)")
        print("   - Hash calculation mismatch on ESP32")
        return True
    except ValueError as e:
        print(f"   ✗ SIGNATURE VERIFICATION FAILED!")
        print(f"   Error: {e}")
        print("\n   The signature is invalid even on the server.")
        print("   This means the patch or signature is corrupted.")
        return False

if __name__ == "__main__":
    test_signature_verification()

