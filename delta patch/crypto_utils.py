from Crypto.Cipher import AES
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
import os

REM_MAGIC = b"REM1"
REM_SALT = b"REM1-OTA-PATCH"
REM_CONTEXT = b"REM1"
REM_TAG_SIZE = 32
REM_NONCE_SIZE = 16

def _rem_derive_keys(device_key):
    keys = HKDF(device_key, 32, REM_SALT, SHA256, num_keys=2, context=REM_CONTEXT)
    return keys[0], keys[1]

def rem_encrypt_patch(patch_bytes, device_key):
    aes_key, hmac_key = _rem_derive_keys(device_key)
    nonce = os.urandom(REM_NONCE_SIZE)
    cipher = AES.new(aes_key, AES.MODE_CFB, iv=nonce, segment_size=128)
    ciphertext = cipher.encrypt(patch_bytes)
    from Crypto.Hash import HMAC
    h = HMAC.new(hmac_key, digestmod=SHA256)
    h.update(nonce)
    h.update(ciphertext)
    tag = h.digest()
    return REM_MAGIC + nonce + ciphertext + tag

def rem_decrypt_patch(enc_bytes, device_key):
    if len(enc_bytes) < 4 + REM_NONCE_SIZE + REM_TAG_SIZE:
        raise ValueError("REM payload too short")
    if enc_bytes[:4] != REM_MAGIC:
        raise ValueError("Invalid REM magic")
    nonce = enc_bytes[4:4+REM_NONCE_SIZE]
    tag = enc_bytes[-REM_TAG_SIZE:]
    ciphertext = enc_bytes[4+REM_NONCE_SIZE:-REM_TAG_SIZE]
    aes_key, hmac_key = _rem_derive_keys(device_key)
    from Crypto.Hash import HMAC
    h = HMAC.new(hmac_key, digestmod=SHA256)
    h.update(nonce)
    h.update(ciphertext)
    expected_tag = h.digest()
    if expected_tag != tag:
        raise ValueError("REM tag verification failed")
    cipher = AES.new(aes_key, AES.MODE_CFB, iv=nonce, segment_size=128)
    return cipher.decrypt(ciphertext)

def encrypt_patch(patch_bytes, device_key):
    return rem_encrypt_patch(patch_bytes, device_key)

def sign_patch(patch_bytes):
    with open('ecc_private.pem', 'rb') as f:
        private_key = ECC.import_key(f.read())
    h = SHA256.new(patch_bytes)
    signer = DSS.new(private_key, 'fips-186-3', encoding='der')
    signature = signer.sign(h)
    return signature
