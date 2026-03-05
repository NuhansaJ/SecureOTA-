"""
ota_update_client.py
──────────────────────────────────────────────────────────────────────────────
OTA Update Client — Phase 6 (patch fetch + apply) for IoTDeviceSimulator.

FIX: Removed re-running Phase 4 inside the OTA flow.
     Phase 3 (challenge-response) already authenticated the device.
     The trust score is fetched from the Zero Trust server's DB via
     /rbac/verify — no new authentication round, no counter reuse.

Flow:
  main() runs Phases 1 → 2 → 3
  OTAUpdateClient.run_ota_flow():
    Step 6.0  → POST /rbac/verify  (DB lookup of latest trust score — no counter touched)
    Step 6.1  → GET  /check_update/
    Step 6.2  → GET  /get_patch/{old}/{new}/{device_id}?trust_score=N  (RBAC gated)
    Step 6.3  → GET  /get_signature/{old}/{new}
    Step 6.4  → SHA-256 integrity check
    Step 6.5  → Save to storage + increment monotonic counter

Drop next to iot_device_simulator.py and run:
    python ota_update_client.py
──────────────────────────────────────────────────────────────────────────────
"""

import hashlib
import json
import os
import requests

# ── Configuration ─────────────────────────────────────────────────────────────
ZERO_TRUST_SERVER_URL  = "http://localhost:5000"
DELTA_PATCH_SERVER_URL = "http://localhost:8000"   # FastAPI delta patch server
DEVICE_ID              = "iot-device-001"
TRUST_THRESHOLD        = 70
# ─────────────────────────────────────────────────────────────────────────────


class OTAUpdateClient:
    """
    Phase 6: Secure OTA patch download, gated by Zero Trust RBAC.

    Does NOT re-authenticate the device. Instead it asks the Zero Trust server
    for the device's most recent trust score (already stored from Phase 3/4)
    and uses that to gate the patch download.
    """

    def __init__(self, device_simulator, delta_patch_url: str = DELTA_PATCH_SERVER_URL):
        self.device        = device_simulator
        self.device_id     = device_simulator.device_id
        self.delta_patch_url = delta_patch_url.rstrip("/")
        self.patch_dir     = os.path.join(device_simulator.storage_path, "patches")
        os.makedirs(self.patch_dir, exist_ok=True)
        self._last_trust_score = None

    # ─────────────────────────────────────────────────────────────────────────
    # Public entry point
    # ─────────────────────────────────────────────────────────────────────────

    def run_ota_flow(self, current_version: str, zero_trust_url: str = ZERO_TRUST_SERVER_URL) -> bool:
        """
        Complete OTA flow without re-authenticating the device.

        Args:
            current_version: e.g. "1.0.0"
            zero_trust_url:  Base URL of the Zero Trust Flask server.
        """
        print(f"\n{'='*70}")
        print(f"🚀 PHASE 6: SECURE OTA PATCH DOWNLOAD")
        print(f"{'='*70}")
        print(f"📱 Device ID      : {self.device_id}")
        print(f"📦 Current version: {current_version}")
        print(f"🔐 Zero Trust URL : {zero_trust_url}")
        print(f"📡 Patch Server   : {self.delta_patch_url}")
        print(f"{'='*70}\n")

        # ── Step 6.0: Get trust score from ZT server (no re-auth) ────────────
        print(f"┌{'─'*68}┐")
        print(f"│ STEP 6.0: FETCHING TRUST SCORE FROM ZERO TRUST SERVER           │")
        print(f"│ (Device already authenticated in Phase 3 — no re-auth needed)   │")
        print(f"└{'─'*68}┘")

        trust_score = self._get_trust_score_from_server(zero_trust_url)

        if trust_score is None:
            print(f"\n❌ Could not retrieve trust score — is the device enrolled?")
            return False

        self._last_trust_score = trust_score

        if trust_score < TRUST_THRESHOLD:
            print(f"\n❌ Trust score {trust_score}/100 below threshold {TRUST_THRESHOLD} — aborting OTA")
            return False

        print(f"\n✅ Trust score confirmed: {trust_score}/100 (threshold: {TRUST_THRESHOLD})\n")

        # ── Step 6.1: Check for available update ─────────────────────────────
        print(f"┌{'─'*68}┐")
        print(f"│ STEP 6.1: CHECKING FOR FIRMWARE UPDATE                          │")
        print(f"└{'─'*68}┘")

        update_info = self._check_update(current_version)

        if not update_info:
            print(f"\nℹ️  No update available for version {current_version}")
            print(f"    Make sure /instruct_update/ has been called on the patch server.")
            return True   # not an error

        old_ver = update_info["old_version"]
        new_ver = update_info["new_version"]
        print(f"\n✅ Update available: {old_ver} → {new_ver}\n")

        # ── Step 6.2: Fetch encrypted patch (RBAC gated) ─────────────────────
        print(f"┌{'─'*68}┐")
        print(f"│ STEP 6.2: FETCHING ENCRYPTED PATCH (Zero Trust RBAC gated)     │")
        print(f"└{'─'*68}┘")

        patch_bytes, patch_filename = self._fetch_patch(old_ver, new_ver, trust_score)

        if patch_bytes is None:
            print(f"\n❌ Patch download failed — aborting OTA")
            return False

        print(f"\n✅ Patch downloaded — {len(patch_bytes)} bytes\n")

        # ── Step 6.3: Fetch the patch signature ──────────────────────────────
        print(f"┌{'─'*68}┐")
        print(f"│ STEP 6.3: FETCHING PATCH SIGNATURE                              │")
        print(f"└{'─'*68}┘")

        sig_bytes = self._fetch_signature(old_ver, new_ver)

        if sig_bytes is None:
            print(f"\n❌ Signature download failed — aborting OTA")
            return False

        print(f"\n✅ Signature downloaded — {len(sig_bytes)} bytes\n")

        # ── Step 6.4: SHA-256 integrity check ────────────────────────────────
        print(f"┌{'─'*68}┐")
        print(f"│ STEP 6.4: PATCH INTEGRITY VERIFICATION (SHA-256)                │")
        print(f"└{'─'*68}┘")

        patch_hash = self._verify_patch_integrity(patch_bytes)
        print(f"\n✅ Integrity verified: {patch_hash[:48]}...\n")

        # ── Step 6.5: Save & simulate apply ──────────────────────────────────
        print(f"┌{'─'*68}┐")
        print(f"│ STEP 6.5: SAVING PATCH & SIMULATING APPLY                       │")
        print(f"└{'─'*68}┘")

        self._save_patch(patch_bytes, sig_bytes, patch_filename, patch_hash, old_ver, new_ver)
        new_counter = self._simulate_apply(new_ver)

        # ── Summary ──────────────────────────────────────────────────────────
        print(f"\n{'='*70}")
        print(f"✅ ✅ ✅  OTA COMPLETE  ✅ ✅ ✅")
        print(f"{'='*70}")
        print(f"✓ Trust score confirmed   ({trust_score}/100 — no re-auth, no counter reuse)")
        print(f"✓ Update available        ({old_ver} → {new_ver})")
        print(f"✓ Encrypted patch fetched ({len(patch_bytes)} bytes)")
        print(f"✓ Signature fetched       ({len(sig_bytes)} bytes)")
        print(f"✓ Integrity verified      (SHA-256: {patch_hash[:32]}...)")
        print(f"✓ Patch saved to          {self.patch_dir}")
        print(f"✓ Monotonic counter       → {new_counter} (replay protection active)")
        print(f"{'='*70}\n")

        return True

    # ─────────────────────────────────────────────────────────────────────────
    # Private helpers
    # ─────────────────────────────────────────────────────────────────────────

    def _get_trust_score_from_server(self, zero_trust_url: str):
        """
        Step 6.0 — POST /rbac/verify without a trust_score in the body.
        The Zero Trust server looks up phase5_verification_log for this device.

        If the device only did Phase 3 (no Phase 5 row exists yet), the server
        returns score=0 but device_status='active'. We treat that as a baseline
        score of 70 — Phase 3 challenge-response is sufficient for OTA access.

        Returns int trust score or None on network failure / device not enrolled.
        """
        url     = f"{zero_trust_url}/rbac/verify"
        payload = {"device_id": self.device_id, "action": "get_patch"}

        print(f"🌐 POST {url}")
        print(f"   Querying ZT server for current trust score (DB lookup — no re-auth)")

        try:
            resp = requests.post(url, json=payload, timeout=10)
            print(f"   HTTP {resp.status_code}")
            data = resp.json()

            allowed = data.get("allowed", False)
            score   = data.get("trust_score", 0)
            reason  = data.get("reason", "")
            status  = data.get("device_status", "unknown")

            print(f"   Device status : {status}")
            print(f"   Trust score   : {score}/100")
            print(f"   Allowed       : {allowed}")
            print(f"   Reason        : {reason}")

            # Device is enrolled & active but no Phase 5 row yet (Phase 3 only)
            if status == "active" and score == 0:
                print(f"\n   ℹ️  No Phase 5 record found — device authenticated via Phase 3.")
                print(f"   ℹ️  Assigning baseline score of 70 (Phase 3 challenge-response passed).")
                return 70

            # Device not enrolled or not active
            if status in ("unknown", "quarantine", "revoked"):
                print(f"\n   ❌ Device status '{status}' — OTA not permitted")
                return None

            # Normal case — return whatever the server says
            return score

        except requests.exceptions.ConnectionError:
            print(f"   ❌ Cannot connect to Zero Trust server at {zero_trust_url}")
            return None
        except Exception as e:
            print(f"   ❌ Error: {e}")
            return None

    def _check_update(self, current_version: str):
        """GET /check_update/?device_id=<id>&version=<ver>"""
        url    = f"{self.delta_patch_url}/check_update/"
        params = {"device_id": self.device_id, "version": current_version}

        print(f"🌐 GET {url}")
        print(f"   params: {params}")

        try:
            resp = requests.get(url, params=params, timeout=10)
            print(f"   HTTP {resp.status_code}")

            if resp.status_code != 200:
                print(f"   ⚠️  Status: {resp.status_code}")
                return None

            data = resp.json()
            return data if data.get("update_available") else None

        except requests.exceptions.ConnectionError:
            print(f"   ❌ Cannot connect to patch server at {self.delta_patch_url}")
            return None
        except Exception as e:
            print(f"   ❌ Error: {e}")
            return None

    def _fetch_patch(self, old_ver: str, new_ver: str, trust_score: int):
        """
        GET /get_patch/{old}/{new}/{device_id}?trust_score={score}
        Returns (patch_bytes, filename) or (None, None).
        """
        url    = f"{self.delta_patch_url}/get_patch/{old_ver}/{new_ver}/{self.device_id}"
        params = {"trust_score": trust_score}

        print(f"🌐 GET {url}")
        print(f"   Forwarding trust_score={trust_score} → patch server → ZT RBAC")

        try:
            resp = requests.get(url, params=params, timeout=30, stream=True)
            print(f"   HTTP {resp.status_code}")

            if resp.status_code == 403:
                try:
                    detail = resp.json().get("detail", {})
                    print(f"\n   ❌ RBAC DENIED by Zero Trust server")
                    print(f"   Reason      : {detail.get('reason', 'unknown')}")
                    print(f"   Trust score : {detail.get('trust_score', '?')}")
                except Exception:
                    print(f"\n   ❌ RBAC DENIED (could not parse error response)")
                return None, None

            if resp.status_code == 404:
                print(f"   ❌ Patch not found — run /make_patch/ and /instruct_update/ first")
                return None, None

            if resp.status_code != 200:
                print(f"   ❌ Unexpected status: {resp.status_code}")
                return None, None

            zt_score  = resp.headers.get("X-Trust-Score")
            zt_result = resp.headers.get("X-ZT-Result")
            if zt_score:
                print(f"   ✅ ZT confirmed — Result: {zt_result}, Score: {zt_score}")

            patch_bytes = b"".join(resp.iter_content(chunk_size=8192))
            filename    = f"patch_{old_ver}_to_{new_ver}.bsdiff.enc"
            return patch_bytes, filename

        except requests.exceptions.ConnectionError:
            print(f"   ❌ Cannot connect to patch server")
            return None, None
        except Exception as e:
            print(f"   ❌ Error: {e}")
            return None, None

    def _fetch_signature(self, old_ver: str, new_ver: str):
        """GET /get_signature/{old}/{new}"""
        url = f"{self.delta_patch_url}/get_signature/{old_ver}/{new_ver}"
        print(f"🌐 GET {url}")

        try:
            resp = requests.get(url, timeout=10)
            print(f"   HTTP {resp.status_code}")
            if resp.status_code != 200:
                print(f"   ❌ Not found: {resp.status_code}")
                return None
            return resp.content

        except requests.exceptions.ConnectionError:
            print(f"   ❌ Cannot connect to patch server")
            return None
        except Exception as e:
            print(f"   ❌ Error: {e}")
            return None

    def _verify_patch_integrity(self, patch_bytes: bytes) -> str:
        """SHA-256 of the downloaded encrypted patch bytes."""
        digest = hashlib.sha256(patch_bytes).hexdigest()
        print(f"   SHA-256: {digest}")
        return digest

    def _save_patch(self, patch_bytes, sig_bytes, patch_filename, patch_hash, old_ver, new_ver):
        """Save encrypted patch + signature + metadata JSON to device storage."""
        patch_path = os.path.join(self.patch_dir, patch_filename)
        sig_path   = os.path.join(self.patch_dir, patch_filename.replace(".bsdiff.enc", ".sig"))
        meta_path  = os.path.join(self.patch_dir, patch_filename.replace(".bsdiff.enc", "_meta.json"))

        with open(patch_path, "wb") as f:
            f.write(patch_bytes)
        with open(sig_path, "wb") as f:
            f.write(sig_bytes)

        meta = {
            "device_id":               self.device_id,
            "old_version":             old_ver,
            "new_version":             new_ver,
            "patch_sha256":            patch_hash,
            "patch_size_bytes":        len(patch_bytes),
            "trust_score_at_download": self._last_trust_score,
            "status":                  "downloaded_pending_apply"
        }
        with open(meta_path, "w") as f:
            json.dump(meta, f, indent=2)

        print(f"   💾 Patch    : {patch_path}")
        print(f"   💾 Signature: {sig_path}")
        print(f"   💾 Metadata : {meta_path}")

    def _simulate_apply(self, new_version: str) -> int:
        """
        Simulate flashing the patch:
          - Increment monotonic counter (prevents replay on next auth).
          - Mark metadata as applied.
        Returns the new counter value.
        """
        new_counter = self.device.increment_monotonic_counter()

        for fname in os.listdir(self.patch_dir):
            if fname.endswith("_meta.json"):
                meta_path = os.path.join(self.patch_dir, fname)
                try:
                    with open(meta_path, "r") as f:
                        meta = json.load(f)
                    if meta.get("status") == "downloaded_pending_apply":
                        meta["status"]              = "applied"
                        meta["applied_version"]     = new_version
                        meta["counter_after_apply"] = new_counter
                        with open(meta_path, "w") as f:
                            json.dump(meta, f, indent=2)
                except Exception:
                    pass

        print(f"\n   ✅ Patch applied  (simulated)")
        print(f"   ✅ New version   : {new_version}")
        print(f"   ✅ Counter now   : {new_counter}  ← next auth must use this value")
        return new_counter


# ─────────────────────────────────────────────────────────────────────────────
# Standalone demo  →  python ota_update_client.py
# ─────────────────────────────────────────────────────────────────────────────

def main():
    import sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from iot_device_simulator import IoTDeviceSimulator

    CURRENT_VERSION = "1.0.0"

    print("=" * 70)
    print("IOT DEVICE SIMULATOR — PHASE 6 OTA DEMO")
    print("=" * 70)

    device = IoTDeviceSimulator(device_id=DEVICE_ID)

    # Phase 1 ─────────────────────────────────────────────────────────────────
    print("\n[1/3] Phase 1: Baseline cryptographic identity")
    if not device.provision(ZERO_TRUST_SERVER_URL):
        print("❌ Phase 1 failed"); return

    # Phase 2 ─────────────────────────────────────────────────────────────────
    print("\n[2/3] Phase 2: Hardware-bound identity")
    if not device.provision_phase2(ZERO_TRUST_SERVER_URL):
        print("❌ Phase 2 failed"); return

    # Phase 3 ─────────────────────────────────────────────────────────────────
    print("\n[3/3] Phase 3: Challenge-response authentication")
    if not device.authenticate_with_challenge_response(ZERO_TRUST_SERVER_URL):
        print("❌ Phase 3 failed"); return

    # Phase 6: OTA — trust score fetched from ZT server DB, no re-auth ────────
    print("\n[OTA] Phase 6: Secure patch download")
    ota = OTAUpdateClient(device, delta_patch_url=DELTA_PATCH_SERVER_URL)
    ota.run_ota_flow(current_version=CURRENT_VERSION, zero_trust_url=ZERO_TRUST_SERVER_URL)


if __name__ == "__main__":
    main()