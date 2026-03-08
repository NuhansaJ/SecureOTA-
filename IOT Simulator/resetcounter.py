"""
reset_counter.py
────────────────────────────────────────────────────────────────
Run this ONCE from the project root to clear the stuck counter.
After running, execute ota_update_client.py normally.

Usage:
    python reset_counter.py
────────────────────────────────────────────────────────────────
"""

import sqlite3
import json
import os

# ── Adjust these paths if your layout differs ────────────────────
DEVICE_ID    = "iot-device-001"
DB_FILE      = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "Zero Trust Server", "verification_database.db"
)
COUNTER_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "device_storage", f"{DEVICE_ID}_counter.json"
)
# ─────────────────────────────────────────────────────────────────

def reset():
    print("=" * 60)
    print("COUNTER RESET UTILITY")
    print("=" * 60)

    # 1. Clear DB counter rows for this device
    db_path = os.path.abspath(DB_FILE)
    if os.path.exists(db_path):
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM device_monotonic_counters WHERE device_id = ?",
                (DEVICE_ID,)
            )
            deleted = cursor.rowcount
            conn.commit()
            conn.close()
            print(f"✅ DB: Deleted {deleted} counter row(s) for '{DEVICE_ID}'")
            print(f"   DB path: {db_path}")
        except Exception as e:
            print(f"❌ DB reset failed: {e}")
            print(f"   Tried path: {db_path}")
            print(f"   Adjust DB_FILE at the top of this script.")
    else:
        print(f"⚠️  DB not found at: {db_path}")
        print(f"   Adjust DB_FILE at the top of this script.")

    # 2. Reset the counter file to 0
    counter_path = os.path.abspath(COUNTER_FILE)
    if os.path.exists(counter_path):
        try:
            data = {"counter": 0, "device_id": DEVICE_ID,
                    "note": "reset by reset_counter.py"}
            with open(counter_path, "w") as f:
                json.dump(data, f, indent=2)
            print(f"✅ File: Counter reset to 0")
            print(f"   File path: {counter_path}")
        except Exception as e:
            print(f"❌ File reset failed: {e}")
    else:
        # File doesn't exist — that's fine, it will be created at 0 on first load
        print(f"ℹ️  Counter file not found (will be created fresh): {counter_path}")

    print()
    print("=" * 60)
    print("✅ Reset complete.")
    print("   Counter starts fresh from 0.")
    print("   Next Phase 4/5 auth will send counter=1 and DB will accept it.")
    print("=" * 60)


if __name__ == "__main__":
    reset()