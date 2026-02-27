"""
crypto.py - Minimal demo server to explain:
  - AES-256-CFB encryption/decryption (stream-friendly)
  - ECC (P-256) ECDSA signing/verification (DER signatures)

Run:
  python3 -m uvicorn crypto:app --host 0.0.0.0 --port 8001

Quick demo (copy/paste):

  # 0) (Optional) Generate demo ECC keys if you don't already have them
  curl -s -X POST "http://127.0.0.1:8001/generate_keys" | python3 -m json.tool

  # 1) Encrypt plaintext with AES-CFB
  curl -s -X POST "http://127.0.0.1:8001/encrypt" \
    -H "Content-Type: application/json" \
    -d '{"plaintext":"Hello Supervisor - OTA Delta Patch Demo"}' | python3 -m json.tool

  # 2) Sign the SAME plaintext (ECDSA, DER)
  curl -s -X POST "http://127.0.0.1:8001/sign" \
    -H "Content-Type: application/json" \
    -d '{"message":"Hello Supervisor - OTA Delta Patch Demo"}' | python3 -m json.tool

  # 3) Verify signature (ECDSA verify)
  #    (Paste "signature_b64" value from step 2 into SIGNATURE_B64 below)
  SIGNATURE_B64="PASTE_SIGNATURE_B64_HERE"
  curl -s -X POST "http://127.0.0.1:8001/verify" \
    -H "Content-Type: application/json" \
    -d "{\"message\":\"Hello Supervisor - OTA Delta Patch Demo\",\"signature_b64\":\"${SIGNATURE_B64}\"}" | python3 -m json.tool

  # 4) Decrypt ciphertext produced by /encrypt
  #    (Paste "enc_b64" value from step 1 into ENC_B64 below)
  ENC_B64="PASTE_ENC_B64_HERE"
  curl -s -X POST "http://127.0.0.1:8001/decrypt" \
    -H "Content-Type: application/json" \
    -d "{\"enc_b64\":\"${ENC_B64}\"}" | python3 -m json.tool

Notes:
  - In the main OTA project, the server signs the *patch bytes* and encrypts those bytes.
  - The ESP32 decrypts in chunks (CFB) and verifies the DER signature using the public key.
"""

from __future__ import annotations

import base64
from pathlib import Path

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

from crypto_utils import rem_encrypt_patch, rem_decrypt_patch

app = FastAPI(title="Crypto Demo (REM + ECDSA)")


DEVICE_AES_KEY = bytes(
    [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    ]
)


PRIV_KEY_PATH = Path("ecc_private.pem")
PUB_KEY_PATH = Path("ecc_public.pem")


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    try:
        return base64.b64decode(s.encode("ascii"), validate=True)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid base64: {e}")


def _load_private_key() -> ECC.EccKey:
    if not PRIV_KEY_PATH.exists():
        raise HTTPException(
            status_code=400,
            detail="ecc_private.pem not found. Create it (see index.html) or POST /generate_keys.",
        )
    return ECC.import_key(PRIV_KEY_PATH.read_bytes())


def _load_public_key() -> ECC.EccKey:
    if PUB_KEY_PATH.exists():
        return ECC.import_key(PUB_KEY_PATH.read_bytes())
    # If only private key exists, derive public key from it.
    priv = _load_private_key()
    return priv.public_key()


class EncryptReq(BaseModel):
    plaintext: str = Field(..., description="UTF-8 text to encrypt")


class EncryptResp(BaseModel):
    iv_b64: str
    ciphertext_b64: str
    enc_b64: str
    iv_hex: str
    ciphertext_hex_prefix: str


class DecryptReq(BaseModel):
    enc_b64: str = Field(..., description="Base64 of (IV || ciphertext)")


class DecryptResp(BaseModel):
    plaintext: str
    plaintext_b64: str


class SignReq(BaseModel):
    message: str = Field(..., description="UTF-8 text to sign")


class SignResp(BaseModel):
    signature_b64: str
    signature_hex_prefix: str
    signature_len: int


class VerifyReq(BaseModel):
    message: str
    signature_b64: str


class VerifyResp(BaseModel):
    valid: bool


@app.get("/")
def root():
    return {
        "message": "Crypto demo server (REM 1.0)",
        "encryption": "REM 1.0 (AES-256-CFB + HMAC-SHA256, HKDF key derivation)",
        "ecdsa_curve": "NIST P-256",
        "ecdsa_encoding": "DER",
        "endpoints": ["/encrypt", "/decrypt", "/sign", "/verify", "/generate_keys"],
    }


@app.post("/generate_keys")
def generate_keys():
    """
    Generates ecc_private.pem and ecc_public.pem if they don't exist.
    Safe: will NOT overwrite existing files.
    """
    created = []
    if not PRIV_KEY_PATH.exists():
        key = ECC.generate(curve="P-256")
        PRIV_KEY_PATH.write_bytes(key.export_key(format="PEM").encode("utf-8"))
        created.append(str(PRIV_KEY_PATH))
        # Derive public key
        PUB_KEY_PATH.write_bytes(key.public_key().export_key(format="PEM").encode("utf-8"))
        created.append(str(PUB_KEY_PATH))
    else:
        # Ensure public key exists too (derive if missing)
        if not PUB_KEY_PATH.exists():
            priv = ECC.import_key(PRIV_KEY_PATH.read_bytes())
            PUB_KEY_PATH.write_bytes(priv.public_key().export_key(format="PEM").encode("utf-8"))
            created.append(str(PUB_KEY_PATH))

    return {
        "status": "ok",
        "created": created,
        "private_key": str(PRIV_KEY_PATH),
        "public_key": str(PUB_KEY_PATH),
        "note": "Private key stays on server; public key is what you upload to ESP32 (/server_pub.pem).",
    }


@app.post("/encrypt", response_model=EncryptResp)
def encrypt(req: EncryptReq):
    pt = req.plaintext.encode("utf-8")
    enc = rem_encrypt_patch(pt, DEVICE_AES_KEY)
    ct = enc[52:len(enc)-32]
    return EncryptResp(
        iv_b64=_b64e(enc[4:20]),
        ciphertext_b64=_b64e(ct),
        enc_b64=_b64e(enc),
        iv_hex=enc[4:20].hex(),
        ciphertext_hex_prefix=ct[:16].hex(),
    )


@app.post("/decrypt", response_model=DecryptResp)
def decrypt(req: DecryptReq):
    enc = _b64d(req.enc_b64)
    if len(enc) < 53:
        raise HTTPException(status_code=400, detail="enc_b64 too short for REM (need REM1 + nonce + ciphertext + tag)")
    if enc[:4] == b"REM1":
        try:
            pt = rem_decrypt_patch(enc, DEVICE_AES_KEY)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
    else:
        if len(enc) < 17:
            raise HTTPException(status_code=400, detail="enc_b64 must contain at least 16 bytes IV + 1 byte ciphertext")
        from Crypto.Cipher import AES
        cipher = AES.new(DEVICE_AES_KEY, AES.MODE_CFB, iv=enc[:16], segment_size=128)
        pt = cipher.decrypt(enc[16:])
    try:
        text = pt.decode("utf-8")
    except Exception:
        text = "<non-utf8-bytes>"
    return DecryptResp(plaintext=text, plaintext_b64=_b64e(pt))


@app.post("/sign", response_model=SignResp)
def sign(req: SignReq):
    private_key = _load_private_key()
    msg = req.message.encode("utf-8")
    h = SHA256.new(msg)
    signer = DSS.new(private_key, "fips-186-3", encoding="der")
    sig = signer.sign(h)
    return SignResp(
        signature_b64=_b64e(sig),
        signature_hex_prefix=sig[:16].hex(),
        signature_len=len(sig),
    )


@app.post("/verify", response_model=VerifyResp)
def verify(req: VerifyReq):
    public_key = _load_public_key()
    sig = _b64d(req.signature_b64)
    msg = req.message.encode("utf-8")
    h = SHA256.new(msg)
    verifier = DSS.new(public_key, "fips-186-3", encoding="der")
    try:
        verifier.verify(h, sig)
        return VerifyResp(valid=True)
    except ValueError:
        return VerifyResp(valid=False)


