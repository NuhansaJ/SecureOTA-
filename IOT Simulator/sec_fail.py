"""
security_failure_demo.py
──────────────────────────────────────────────────────────────────────────────
Zero Trust Security Failure Demonstration

Intentionally triggers failure scenarios to prove the security system works:

  Scenario 1 — Hardware Fingerprint Tampered
    Sends a corrupted hardware fingerprint during Phase 2 enrollment.
    → Server detects HW_MISMATCH → device quarantined → logged as failed attempt.

  Scenario 2 — Counter Replay Attack
    Replays an old (already-used) monotonic counter value during Phase 4/5.
    → Server detects replay → rejects with "Counter reused" → logged.

  Scenario 3 — Invalid Signature
    Corrupts the cryptographic signature before sending to server.
    → Server rejects with "Invalid signature" → logged.

  Scenario 4 — Counter Rollback Attack
    Sends a counter value lower than the last accepted value.
    → Server detects rollback → rejects → logged.

Each scenario prints a clear PASS/FAIL banner showing the security system
caught the attack, and the failure is recorded in the Zero Trust server's
audit logs (device_failed_attempt_log, phase5_verification_log, etc.)
──────────────────────────────────────────────────────────────────────────────
"""

import hashlib
import json
import os
import sys
import time
import requests
from datetime import datetime, timezone

# ── Point to the same server ──────────────────────────────────────────────────
ZERO_TRUST_SERVER_URL = "http://13.63.176.124:5000"
DEVICE_ID             = "iot-device-001"

# Anchor storage to this script's directory (same fix as iot_device_simulator)
STORAGE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "device_storage")

# ─────────────────────────────────────────────────────────────────────────────

def separator(title="", char="═", width=70):
    if title:
        pad = (width - len(title) - 2) // 2
        print(f"\n{'═'*pad} {title} {'═'*pad}")
    else:
        print("═" * width)

def result_banner(passed: bool, scenario: str):
    """Print a big PASS or FAIL banner."""
    if passed:
        print(f"\n{'✅'*5}  SECURITY SYSTEM CORRECTLY REJECTED: {scenario}  {'✅'*5}\n")
    else:
        print(f"\n{'❌'*5}  UNEXPECTED: {scenario} was NOT caught  {'❌'*5}\n")

def load_device_keys():
    """Load the device's real private key from storage."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend

    key_file = os.path.join(STORAGE_PATH, f"{DEVICE_ID}_private_key.pem")
    if not os.path.exists(key_file):
        print(f"❌ No key file found at {key_file}")
        print(f"   Run ota_update_client.py (Phase 1) first to provision the device.")
        return None
    with open(key_file, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=b"device_secure_password",
            backend=default_backend()
        )
    return private_key

def load_counter():
    """Load current local monotonic counter."""
    counter_file = os.path.join(STORAGE_PATH, f"{DEVICE_ID}_counter.json")
    try:
        with open(counter_file, "r") as f:
            return json.load(f).get("counter", 0)
    except Exception:
        return 0

def request_contextual_challenge(required_contexts=None):
    """Ask the server for a Phase 4/5 challenge."""
    if required_contexts is None:
        required_contexts = ["hw", "counter", "time"]
    resp = requests.post(
        f"{ZERO_TRUST_SERVER_URL}/auth/challenge-context",
        json={"device_id": DEVICE_ID, "required_contexts": required_contexts},
        timeout=10
    )
    if resp.status_code != 200:
        raise RuntimeError(f"Challenge request failed: {resp.status_code} {resp.text}")
    return resp.json()["challenge"]

def build_and_sign_payload(private_key, nonce, hw_hash, counter, timestamp=None):
    """Build a context payload and sign it with the real private key."""
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes

    if timestamp is None:
        timestamp = datetime.now(timezone.utc).isoformat()

    parts = [nonce, hw_hash, str(counter), timestamp]
    payload_string = "||".join(parts)
    signature = private_key.sign(
        payload_string.encode("utf-8"),
        ec.ECDSA(hashes.SHA256())
    )
    return payload_string, signature.hex(), timestamp

def send_context_proof(challenge_id, nonce, signature_hex,
                       hw_hash, counter, timestamp):
    """Submit the context proof to the server."""
    resp = requests.post(
        f"{ZERO_TRUST_SERVER_URL}/auth/verify-context",
        json={
            "device_id":    DEVICE_ID,
            "challenge_id": challenge_id,
            "nonce":        nonce,
            "signature":    signature_hex,
            "context_proof": {
                "hardware_state_hash": hw_hash,
                "monotonic_counter":   counter,
                "device_timestamp":    timestamp,
            }
        },
        timeout=10
    )
    return resp

def get_real_hw_hash():
    """Return the real hardware fingerprint hash (same fixed values as simulator)."""
    mcu_uid          = "1234567890abcdef"
    flash_size       = 268435456
    bootloader_crc   = "5f4d6c3b"
    secure_boot_flag = "Enabled"
    hw_data = f"{mcu_uid}||{flash_size}||{bootloader_crc}||{secure_boot_flag}"
    return hashlib.sha256(hw_data.encode()).hexdigest()

# =============================================================================
# SCENARIO 1 — Hardware Fingerprint Tampered
# =============================================================================

def scenario_1_hw_fingerprint_tampered():
    separator("SCENARIO 1: HARDWARE FINGERPRINT TAMPERED")
    print("📋 What we're doing:")
    print("   Sending a FAKE hardware fingerprint during Phase 2 enrollment.")
    print("   The server compares it against the stored binding.")
    print("   Expected result: HW_MISMATCH → device quarantined → failure logged.\n")

    fake_hw_fingerprint = hashlib.sha256(b"this_is_a_fake_hardware_id").hexdigest()
    print(f"   Real HW fingerprint : {get_real_hw_hash()[:32]}...")
    print(f"   Fake HW fingerprint : {fake_hw_fingerprint[:32]}...")

    # Load real public key PEM from stored config
    config_file = os.path.join(STORAGE_PATH, f"{DEVICE_ID}_config.json")
    if not os.path.exists(config_file):
        print("❌ Device not provisioned. Run ota_update_client.py first.")
        return False

    with open(config_file, "r") as f:
        config = json.load(f)

    # We need the public key — reload from private key
    private_key = load_device_keys()
    if not private_key:
        return False

    from cryptography.hazmat.primitives import serialization
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")

    payload = {
        "device_id":            DEVICE_ID,
        "public_key":           public_key_pem,
        "hardware_fingerprint": fake_hw_fingerprint,   # ← TAMPERED
        "network_fingerprint":  hashlib.sha256(
            b"SimulatedNetwork||aa:bb:cc:dd:ee:ff||Ethernet||0"
        ).hexdigest(),
        "enrollment_timestamp": datetime.utcnow().isoformat(),
        "device_type":          "IoT_Simulator",
        "firmware_version":     "1.0.0",
        "phase":                "2",
        "hardware_info":        {"mcu_uid_preview": "TAMPERED_DEVICE"},
        "network_info":         {
            "ssid": "SimulatedNetwork",
            "gateway_mac": "aa:bb:cc:dd:ee:ff",
            "interface_type": "Ethernet",
            "vlan_id": "0"
        }
    }

    print(f"\n🌐 POST {ZERO_TRUST_SERVER_URL}/enroll-phase2  (with fake HW fingerprint)")
    try:
        resp = requests.post(
            f"{ZERO_TRUST_SERVER_URL}/enroll-phase2",
            json=payload,
            timeout=10
        )
        print(f"   HTTP {resp.status_code}")
        data = resp.json()
        print(f"   Response: {json.dumps(data, indent=4)}")

        # Success means server rejected it (400/403) or flagged HW_MISMATCH
        caught = (
            resp.status_code in (400, 403) or
            "mismatch" in str(data).lower() or
            "hw_mismatch" in str(data).lower() or
            data.get("hardware_binding_status") == "HW_MISMATCH"
        )
        result_banner(caught, "Hardware Fingerprint Tampering")
        return caught

    except Exception as e:
        print(f"   ❌ Request error: {e}")
        return False

# =============================================================================
# SCENARIO 2 — Counter Replay Attack
# =============================================================================

def scenario_2_counter_replay():
    separator("SCENARIO 2: COUNTER REPLAY ATTACK")
    print("📋 What we're doing:")
    print("   Re-sending an OLD counter value that the server has already seen.")
    print("   A real attacker would capture a previous auth message and replay it.")
    print("   Expected result: 'Counter reused' → 401 → failure logged.\n")

    private_key = load_device_keys()
    if not private_key:
        return False

    current_counter = load_counter()
    # Use the CURRENT counter value (already accepted by server on last run)
    replay_counter = current_counter
    real_hw_hash   = get_real_hw_hash()

    print(f"   Current local counter : {current_counter}")
    print(f"   Replaying counter     : {replay_counter}  ← already used by server")

    try:
        challenge = request_contextual_challenge()
        nonce        = challenge["nonce"]
        challenge_id = challenge["challenge_id"]

        _, sig_hex, ts = build_and_sign_payload(
            private_key, nonce, real_hw_hash, replay_counter
        )

        print(f"\n🌐 POST {ZERO_TRUST_SERVER_URL}/auth/verify-context  (replayed counter={replay_counter})")
        resp = send_context_proof(challenge_id, nonce, sig_hex,
                                   real_hw_hash, replay_counter, ts)
        print(f"   HTTP {resp.status_code}")
        data = resp.json()
        print(f"   Message: {data.get('message', '')}")
        vd = data.get("verification_details", {})
        if vd:
            for k, v in vd.items():
                icon = "✅" if v else "❌"
                print(f"   {icon} {k}: {v}")

        caught = resp.status_code == 401 and not vd.get("counter_valid", True)
        result_banner(caught, "Counter Replay Attack")
        return caught

    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False

# =============================================================================
# SCENARIO 3 — Invalid / Corrupted Signature
# =============================================================================

def scenario_3_invalid_signature():
    separator("SCENARIO 3: INVALID / CORRUPTED SIGNATURE")
    print("📋 What we're doing:")
    print("   Building a valid payload but corrupting the signature bytes.")
    print("   Simulates an attacker trying to forge an authentication message.")
    print("   Expected result: 'Invalid signature' → 401 → failure logged.\n")

    private_key = load_device_keys()
    if not private_key:
        return False

    current_counter = load_counter()
    next_counter    = current_counter + 1
    real_hw_hash    = get_real_hw_hash()

    try:
        challenge = request_contextual_challenge()
        nonce        = challenge["nonce"]
        challenge_id = challenge["challenge_id"]

        _, real_sig_hex, ts = build_and_sign_payload(
            private_key, nonce, real_hw_hash, next_counter
        )

        # Corrupt the signature — flip the last 8 hex chars
        corrupted_sig = real_sig_hex[:-8] + "deadbeef"
        print(f"   Real signature    : ...{real_sig_hex[-16:]}")
        print(f"   Forged signature  : ...{corrupted_sig[-16:]}  ← corrupted")

        print(f"\n🌐 POST {ZERO_TRUST_SERVER_URL}/auth/verify-context  (corrupted signature)")
        resp = send_context_proof(challenge_id, nonce, corrupted_sig,
                                   real_hw_hash, next_counter, ts)
        print(f"   HTTP {resp.status_code}")
        data = resp.json()
        print(f"   Message: {data.get('message', '')}")
        vd = data.get("verification_details", {})
        if vd:
            for k, v in vd.items():
                icon = "✅" if v else "❌"
                print(f"   {icon} {k}: {v}")

        caught = resp.status_code == 401 and not vd.get("signature_valid", True)
        result_banner(caught, "Invalid Signature / Forgery")
        return caught

    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False

# =============================================================================
# SCENARIO 4 — Counter Rollback Attack
# =============================================================================

def scenario_4_counter_rollback():
    separator("SCENARIO 4: COUNTER ROLLBACK ATTACK")
    print("📋 What we're doing:")
    print("   Sending a counter value LOWER than what the server last accepted.")
    print("   A real attacker might try to roll back to gain access with old state.")
    print("   Expected result: 'Counter rollback' → 401 → failure logged.\n")

    private_key = load_device_keys()
    if not private_key:
        return False

    current_counter = load_counter()
    rollback_counter = max(0, current_counter - 3)   # go back 3 steps
    real_hw_hash     = get_real_hw_hash()

    print(f"   Server's last counter : {current_counter}")
    print(f"   Rollback counter sent : {rollback_counter}  ← lower than server expects")

    try:
        challenge = request_contextual_challenge()
        nonce        = challenge["nonce"]
        challenge_id = challenge["challenge_id"]

        _, sig_hex, ts = build_and_sign_payload(
            private_key, nonce, real_hw_hash, rollback_counter
        )

        print(f"\n🌐 POST {ZERO_TRUST_SERVER_URL}/auth/verify-context  (rollback counter={rollback_counter})")
        resp = send_context_proof(challenge_id, nonce, sig_hex,
                                   real_hw_hash, rollback_counter, ts)
        print(f"   HTTP {resp.status_code}")
        data = resp.json()
        print(f"   Message: {data.get('message', '')}")
        vd = data.get("verification_details", {})
        if vd:
            for k, v in vd.items():
                icon = "✅" if v else "❌"
                print(f"   {icon} {k}: {v}")

        caught = resp.status_code == 401 and not vd.get("counter_valid", True)
        result_banner(caught, "Counter Rollback Attack")
        return caught

    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False

# =============================================================================
# MAIN — Run all scenarios
# =============================================================================

def main():
    separator("ZERO TRUST SECURITY FAILURE DEMONSTRATION")
    print("This script intentionally triggers attack scenarios to prove")
    print("the Zero Trust server correctly detects and logs each one.")
    print(f"\n🔐 Device  : {DEVICE_ID}")
    print(f"🌐 Server  : {ZERO_TRUST_SERVER_URL}")
    print(f"💾 Storage : {STORAGE_PATH}")

    # Check server is reachable
    try:
        r = requests.get(f"{ZERO_TRUST_SERVER_URL}/health", timeout=5)
        print(f"\n✅ Zero Trust server reachable (HTTP {r.status_code})\n")
    except Exception:
        print(f"\n❌ Cannot reach Zero Trust server at {ZERO_TRUST_SERVER_URL}")
        print("   Make sure the server is running before running this demo.")
        sys.exit(1)

    results = {}

    # Run each scenario with a short pause between them
    results["HW Fingerprint Tampered"] = scenario_1_hw_fingerprint_tampered()
    time.sleep(1)

    results["Counter Replay Attack"]   = scenario_2_counter_replay()
    time.sleep(1)

    results["Invalid Signature"]       = scenario_3_invalid_signature()
    time.sleep(1)

    results["Counter Rollback Attack"] = scenario_4_counter_rollback()

    # ── Final summary ──────────────────────────────────────────────────────
    separator("DEMONSTRATION SUMMARY")
    print(f"{'Scenario':<35} {'Security Result':<20}")
    print("─" * 55)
    all_passed = True
    for scenario, caught in results.items():
        status = "✅ ATTACK BLOCKED" if caught else "❌ NOT CAUGHT"
        print(f"{scenario:<35} {status}")
        if not caught:
            all_passed = False
    print("─" * 55)

    if all_passed:
        print("\n✅ ALL ATTACKS WERE CORRECTLY DETECTED AND BLOCKED")
        print("   Check the Zero Trust server dashboard at:")
        print(f"   {ZERO_TRUST_SERVER_URL}/view")
        print("   → device_failed_attempt_log  for failed auth attempts")
        print("   → phase5_verification_log    for Phase 5 rejections")
    else:
        print("\n⚠️  Some scenarios were not caught — review server logs.")

    separator()


if __name__ == "__main__":
    main()