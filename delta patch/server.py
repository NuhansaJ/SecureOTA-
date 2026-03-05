from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import os
import shutil
import httpx
from pathlib import Path
from crypto_utils import encrypt_patch, sign_patch
from patch_utils import generate_patch

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

STORAGE_DIR = Path("storage")
FIRMWARE_DIR = STORAGE_DIR / "firmware"
PATCHES_DIR = STORAGE_DIR / "patches"
SIGNATURES_DIR = STORAGE_DIR / "signatures"

DEVICE_AES_KEY = bytes([
    0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,
    0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF
])

# ─── Zero Trust integration ──────────────────────────────────────────────────
ZERO_TRUST_URL = os.environ.get("ZERO_TRUST_URL", "http://localhost:5000")
ZERO_TRUST_TIMEOUT = 5.0          # seconds; fail-closed if ZT server is slow
RBAC_TRUST_THRESHOLD = 70         # must match zero_trust_server.py
# ─────────────────────────────────────────────────────────────────────────────

DEVICES = {
    "esp32_01": {
        "version": "1.0.0",
        "pending_update": None
    }
}

for directory in [FIRMWARE_DIR, PATCHES_DIR, SIGNATURES_DIR]:
    directory.mkdir(parents=True, exist_ok=True)


# ─── Helper: ask Zero Trust server whether this device may fetch a patch ─────

async def check_rbac(device_id: str, action: str = "get_patch", trust_score: int | None = None) -> dict:
    """
    Call /rbac/verify on the Zero Trust server.

    Returns a dict like:
        {"allowed": True, "trust_score": 85, "device_status": "active", "reason": "..."}

    On any network/timeout error the call *fails closed* (allowed=False).
    """
    payload: dict = {"device_id": device_id, "action": action}
    if trust_score is not None:
        payload["trust_score"] = trust_score

    try:
        async with httpx.AsyncClient(timeout=ZERO_TRUST_TIMEOUT) as client:
            resp = await client.post(f"{ZERO_TRUST_URL}/rbac/verify", json=payload)
            return resp.json()
    except httpx.TimeoutException:
        return {"allowed": False, "trust_score": 0, "reason": "Zero Trust server timeout"}
    except Exception as e:
        return {"allowed": False, "trust_score": 0, "reason": f"Zero Trust unreachable: {str(e)}"}

# ─────────────────────────────────────────────────────────────────────────────


@app.post("/upload_firmware/")
async def upload_firmware(version: str = Form(...), file: UploadFile = File(...)):
    firmware_path = FIRMWARE_DIR / f"firmware_{version}.bin"
    with open(firmware_path, "wb") as f:
        shutil.copyfileobj(file.file, f)
    return {"status": "ok", "stored": str(firmware_path)}


@app.post("/make_patch/")
async def make_patch(old_version: str = Form(...), new_version: str = Form(...)):
    old_firmware = FIRMWARE_DIR / f"firmware_{old_version}.bin"
    new_firmware = FIRMWARE_DIR / f"firmware_{new_version}.bin"

    if not old_firmware.exists():
        raise HTTPException(status_code=404, detail=f"Old firmware {old_version} not found")
    if not new_firmware.exists():
        raise HTTPException(status_code=404, detail=f"New firmware {new_version} not found")

    patch_path = PATCHES_DIR / f"patch_{old_version}_to_{new_version}.bsdiff"

    if not generate_patch(str(old_firmware), str(new_firmware), str(patch_path)):
        raise HTTPException(status_code=500, detail="Failed to generate patch")

    with open(patch_path, "rb") as f:
        patch_bytes = f.read()

    signature = sign_patch(patch_bytes)
    signature_path = SIGNATURES_DIR / f"patch_{old_version}_to_{new_version}.sig"
    with open(signature_path, "wb") as f:
        f.write(signature)

    encrypted_patch = encrypt_patch(patch_bytes, DEVICE_AES_KEY)
    encrypted_patch_path = PATCHES_DIR / f"patch_{old_version}_to_{new_version}.bsdiff.enc"
    with open(encrypted_patch_path, "wb") as f:
        f.write(encrypted_patch)

    return {
        "status": "ok",
        "patch": str(encrypted_patch_path),
        "signature": str(signature_path)
    }


@app.post("/instruct_update/")
async def instruct_update(
    device_id: str = Form(...),
    old_version: str = Form(...),
    new_version: str = Form(...)
):
    if device_id not in DEVICES:
        DEVICES[device_id] = {"version": old_version, "pending_update": None}

    DEVICES[device_id]["pending_update"] = {
        "old_version": old_version,
        "new_version": new_version
    }
    return {"status": "update_queued"}


@app.get("/check_update/")
async def check_update(device_id: str, version: str):
    if device_id not in DEVICES:
        return {"update_available": False}

    device = DEVICES[device_id]
    pending = device.get("pending_update")

    if pending and pending["old_version"] == version:
        return {
            "update_available": True,
            "old_version": pending["old_version"],
            "new_version": pending["new_version"],
            "patch_url": f"/get_patch/{pending['old_version']}/{pending['new_version']}/{device_id}",
            "signature_url": f"/get_signature/{pending['old_version']}/{pending['new_version']}"
        }

    return {"update_available": False}


# ─── PATCHED endpoint — now gated by Zero Trust RBAC ─────────────────────────

@app.get("/get_patch/{old}/{new}/{device_id}")
async def get_patch(old: str, new: str, device_id: str, request: Request):
    """
    Serve an encrypted delta patch only after the Zero Trust server confirms
    the device is active and has a sufficient Phase-5 trust score (≥ 70).

    The optional query parameter ?trust_score=<int> lets the device forward
    the score it received from /auth/verify-context so the RBAC call can
    skip a DB lookup.  If omitted, the Zero Trust server will look it up from
    its phase5_verification_log table.

    Flow:
        Device  →  GET /get_patch/1.0/1.1/esp32_01?trust_score=85
        FastAPI →  POST http://localhost:5000/rbac/verify  {"device_id": "esp32_01", "trust_score": 85}
        ZT      →  {"allowed": true, "trust_score": 85, ...}
        FastAPI →  FileResponse(patch file)   ✓
    """
    # ── 1. Parse optional forwarded trust score ──────────────────────────────
    raw_score = request.query_params.get("trust_score")
    forwarded_score: int | None = None
    if raw_score is not None:
        try:
            forwarded_score = int(raw_score)
        except ValueError:
            pass  # ignore malformed value; ZT server will do DB lookup instead

    # ── 2. RBAC check via Zero Trust server ──────────────────────────────────
    rbac = await check_rbac(device_id, action="get_patch", trust_score=forwarded_score)

    if not rbac.get("allowed", False):
        raise HTTPException(
            status_code=403,
            detail={
                "error": "Zero Trust RBAC denied",
                "device_id": device_id,
                "trust_score": rbac.get("trust_score", 0),
                "reason": rbac.get("reason", "Unknown"),
            }
        )

    # ── 3. Serve the patch ───────────────────────────────────────────────────
    patch_path = PATCHES_DIR / f"patch_{old}_to_{new}.bsdiff.enc"

    if not patch_path.exists():
        raise HTTPException(status_code=404, detail="Patch not found")

    return FileResponse(
        path=str(patch_path),
        media_type="application/octet-stream",
        filename=f"patch_{old}_to_{new}.bsdiff.enc",
        headers={
            "X-Trust-Score": str(rbac.get("trust_score", 0)),
            "X-ZT-Result": "allowed"
        }
    )

# ─────────────────────────────────────────────────────────────────────────────


@app.get("/get_signature/{old}/{new}")
async def get_signature(old: str, new: str):
    signature_path = SIGNATURES_DIR / f"patch_{old}_to_{new}.sig"

    if not signature_path.exists():
        raise HTTPException(status_code=404, detail="Signature not found")

    return FileResponse(
        path=str(signature_path),
        media_type="application/octet-stream",
        filename=f"patch_{old}_to_{new}.sig"
    )


@app.get("/")
async def root():
    return RedirectResponse(url="/dashboard/")


DASHBOARD_DIR = Path(__file__).resolve().parent / "dashboard" / "dist"
if DASHBOARD_DIR.exists():
    app.mount("/dashboard", StaticFiles(directory=str(DASHBOARD_DIR), html=True), name="dashboard")


@app.get("/api/devices")
async def api_devices():
    return {"devices": dict(DEVICES)}


@app.get("/api/firmware")
async def api_firmware():
    versions = []
    for f in FIRMWARE_DIR.glob("firmware_*.bin"):
        name = f.stem.replace("firmware_", "")
        versions.append({"version": name, "size": f.stat().st_size})
    return {"firmware": sorted(versions, key=lambda x: x["version"])}


@app.get("/api/patches")
async def api_patches():
    patches = []
    seen = set()
    for f in PATCHES_DIR.glob("patch_*_to_*.bsdiff.enc"):
        parts = f.stem.replace("patch_", "").replace(".bsdiff", "").split("_to_")
        if len(parts) == 2:
            key = (parts[0], parts[1])
            if key not in seen:
                seen.add(key)
                sig = SIGNATURES_DIR / f"patch_{key[0]}_to_{key[1]}.sig"
                patches.append({
                    "old_version": key[0],
                    "new_version": key[1],
                    "enc_size": f.stat().st_size,
                    "has_signature": sig.exists(),
                })
    return {"patches": sorted(patches, key=lambda x: (x["old_version"], x["new_version"]))}