from flask import Flask, jsonify, request, render_template_string 
import requests
import jwt
import os
import sqlite3
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import base64
from datetime import datetime, timezone
import secrets
import json


app = Flask(__name__)

JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'your-secure-secret-key-change-in-production')
JWT_ALGORITHM = 'HS256'

# Should match Update Cloud Server's JWT secret in production
UPDATE_CLOUD_URL = "http://localhost:8000"

# Store current JWT token for device communication
CURRENT_JWT_TOKEN = None
CURRENT_DEVICE_FINGERPRINT = None

# Get the directory where this script is located
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Update Cloud Server configuration
UPDATE_CLOUD_URL = "http://localhost:8000"

# Directory to store downloaded firmware (inside Zero Trust Server folder)
DOWNLOAD_DIR = os.path.join(SCRIPT_DIR, "downloaded_firmware")

# SQLite database path (inside Zero Trust Server folder)
DB_FILE = os.path.join(SCRIPT_DIR, "verification_database.db")

# Encryption key storage
KEY_FILE = os.path.join(SCRIPT_DIR, "encryption_key.key")
cipher = None
encryption_key = None


# Initialize SQLite Database
def init_database():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS firmware_verification (
            id INTEGER PRIMARY KEY,
            firmware_name TEXT NOT NULL,
            received_hash TEXT NOT NULL,
            calculated_hash TEXT NOT NULL,
            hash_match BOOLEAN NOT NULL,
            timestamp TEXT NOT NULL,
            status TEXT NOT NULL
        )
    ''')
    # Authentication Actions Log
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS device_auth_log (
            id INTEGER PRIMARY KEY,
            action TEXT NOT NULL,
            token_id TEXT,
            device_id TEXT,
            endpoint TEXT NOT NULL,
            status TEXT NOT NULL,
            error_details TEXT,
            timestamp TEXT NOT NULL
        )
    ''')
    
    # Cached Tokens (for reference and revocation checking)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cached_tokens (
            id INTEGER PRIMARY KEY,
            token_id TEXT UNIQUE NOT NULL,
            token TEXT NOT NULL,
            device_fingerprint TEXT,
            obtained_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            is_valid BOOLEAN DEFAULT 1
        )
    ''')
    
    # Device Certificate Fingerprints
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS device_certificates (
            id INTEGER PRIMARY KEY,
            device_id TEXT UNIQUE NOT NULL,
            certificate_hash TEXT NOT NULL,
            certificate_path TEXT,
            registered_at TEXT NOT NULL,
            is_active BOOLEAN DEFAULT 1
        )
    ''')
        
    # Device action logs
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS device_action_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action_type TEXT NOT NULL,
            device_id TEXT NOT NULL,
            firmware_name TEXT,
            token_id TEXT,
            details TEXT,
            status TEXT NOT NULL,
            ip_address TEXT,
            timestamp TEXT NOT NULL
        )
    ''')
    
    # Verification event logs
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS verification_event_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            firmware_name TEXT NOT NULL,
            device_id TEXT NOT NULL,
            verification_type TEXT NOT NULL,
            expected_value TEXT NOT NULL,
            actual_value TEXT NOT NULL,
            match_result BOOLEAN NOT NULL,
            action_taken TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
    ''')
    
    # Device failed attempt logs
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS device_failed_attempt_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            attempt_type TEXT NOT NULL,
            device_id TEXT NOT NULL,
            target_resource TEXT NOT NULL,
            reason TEXT NOT NULL,
            error_details TEXT,
            timestamp TEXT NOT NULL
        )
    ''')
    
    # System event logs
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS system_event_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            component TEXT NOT NULL,
            description TEXT NOT NULL,
            severity TEXT NOT NULL,
            additional_data TEXT,
            timestamp TEXT NOT NULL
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS device_identity (
            device_id TEXT PRIMARY KEY,
            public_key TEXT NOT NULL,
            public_key_format TEXT DEFAULT 'PEM',
            status TEXT NOT NULL DEFAULT 'active',
            enrollment_timestamp TEXT NOT NULL,
            last_seen TEXT,
            firmware_version TEXT,
            device_type TEXT,
            public_key_fingerprint TEXT UNIQUE NOT NULL,
            enrollment_count INTEGER DEFAULT 1,
            key_algorithm TEXT DEFAULT 'ECC-P256',
            created_at TEXT NOT NULL,
            updated_at TEXT
        )
    ''')
    
    # Device enrollment audit log (Phase 1)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS device_enrollment_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT NOT NULL,
            action TEXT NOT NULL,
            public_key_fingerprint TEXT,
            status TEXT NOT NULL,
            error_details TEXT,
            ip_address TEXT,
            timestamp TEXT NOT NULL
        )
    ''')

    # Hardware fingerprint binding table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS device_hardware_binding (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT NOT NULL,
            hardware_fingerprint TEXT NOT NULL,
            public_key_fingerprint TEXT NOT NULL,
            binding_timestamp TEXT NOT NULL,
            last_verified TEXT,
            verification_count INTEGER DEFAULT 1,
            hardware_info TEXT,
            binding_status TEXT DEFAULT 'active',
            FOREIGN KEY (device_id) REFERENCES device_identity(device_id),
            UNIQUE(device_id, hardware_fingerprint)
        )
    ''')
    
    # NEW: Hardware fingerprint verification log
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS hardware_verification_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT NOT NULL,
            hardware_fingerprint TEXT NOT NULL,
            verification_type TEXT NOT NULL,
            match_result BOOLEAN NOT NULL,
            action_taken TEXT NOT NULL,
            ip_address TEXT,
            timestamp TEXT NOT NULL
        )
    ''')

    # Network fingerprint binding table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS device_network_binding (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT NOT NULL,
            network_fingerprint TEXT NOT NULL,
            public_key_fingerprint TEXT NOT NULL,
            binding_timestamp TEXT NOT NULL,
            last_verified TEXT,
            verification_count INTEGER DEFAULT 1,
            network_info TEXT,
            binding_status TEXT DEFAULT 'active',
            FOREIGN KEY (device_id) REFERENCES device_identity(device_id),
            UNIQUE(device_id, network_fingerprint)
    )
''')
    # Network fingerprint binding table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS device_network_binding (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT NOT NULL,
            network_fingerprint TEXT NOT NULL,
            public_key_fingerprint TEXT NOT NULL,
            binding_timestamp TEXT NOT NULL,
            last_verified TEXT,
            verification_count INTEGER DEFAULT 1,
            network_info TEXT,
            binding_status TEXT DEFAULT 'active',
            FOREIGN KEY (device_id) REFERENCES device_identity(device_id),
            UNIQUE(device_id, network_fingerprint)
        )
    ''')

    # Network fingerprint verification log
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS network_verification_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT NOT NULL,
            network_fingerprint TEXT NOT NULL,
            verification_type TEXT NOT NULL,
            match_result BOOLEAN NOT NULL,
            action_taken TEXT NOT NULL,
            ip_address TEXT,
            timestamp TEXT NOT NULL
    )
''')

    conn.commit()
    conn.close()
    print(f"[Database] Initialized with Device Auth tables: {DB_FILE}")
    print(f"[Database] Phase 1 Device Identity tables initialized")
    print(f"[Database] Phase 2 Hardware Binding tables initialized")

# ============= SECURE LOGGING FUNCTIONS =============

def log_device_action(action_type, device_id, firmware_name, token_id, 
                     details, status, ip_address=None):
    """
    Log all device actions
    
    action_type: FIRMWARE_REQUEST, FIRMWARE_DOWNLOAD, HASH_VERIFICATION, 
                 DECRYPTION, INSTALLATION, ROLLBACK
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT INTO device_action_log
            (action_type, device_id, firmware_name, token_id, details, 
             status, ip_address, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (action_type, device_id, firmware_name, token_id, details, 
              status, ip_address, datetime.now().isoformat()))
        conn.commit()
        print(f"[Device Log] {action_type} - Device: {device_id} - {status}")
    except Exception as e:
        print(f"[Device Log] Error: {e}")
    finally:
        conn.close()

def log_verification_event(firmware_name, device_id, verification_type, 
                          expected_value, actual_value, match_result, 
                          action_taken):
    """
    Log all verification events (hash, signature, attestation)
    
    verification_type: HASH_CHECK, SIGNATURE_VERIFY, ATTESTATION, 
                      CERTIFICATE_VERIFY
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT INTO verification_event_log
            (firmware_name, device_id, verification_type, expected_value, 
             actual_value, match_result, action_taken, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (firmware_name, device_id, verification_type, expected_value, 
              actual_value, match_result, action_taken, datetime.now().isoformat()))
        conn.commit()
        result = "PASSED" if match_result else "FAILED"
        print(f"[Verification Log] {verification_type} - {firmware_name} - {result}")
    except Exception as e:
        print(f"[Verification Log] Error: {e}")
    finally:
        conn.close()

def log_failed_device_attempt(attempt_type, device_id, target_resource, 
                             reason, error_details=None):
    """
    Log all failed device attempts
    
    attempt_type: AUTH_FAILED, PERMISSION_DENIED, DOWNLOAD_FAILED, 
                  HASH_MISMATCH, DECRYPTION_FAILED, TOKEN_EXPIRED
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT INTO device_failed_attempt_log
            (attempt_type, device_id, target_resource, reason, 
             error_details, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (attempt_type, device_id, target_resource, reason, 
              error_details, datetime.now().isoformat()))
        conn.commit()
        print(f"[Device Failed] {attempt_type} - Device: {device_id} - {reason}")
    except Exception as e:
        print(f"[Device Failed Log] Error: {e}")
    finally:
        conn.close()

def log_system_event(event_type, component, description, severity, 
                    additional_data=None):
    """
    Log system-level events
    
    event_type: SERVER_START, SERVER_STOP, CONNECTION_ERROR, 
                ENCRYPTION_KEY_LOADED, DATABASE_ERROR
    severity: INFO, WARNING, ERROR, CRITICAL
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT INTO system_event_log
            (event_type, component, description, severity, additional_data, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (event_type, component, description, severity, 
              additional_data, datetime.now().isoformat()))
        conn.commit()
        print(f"[System Log] {severity} - {event_type} - {component}")
    except Exception as e:
        print(f"[System Log] Error: {e}")
    finally:
        conn.close()


# ============= PHASE 3: CHALLENGE-RESPONSE AUTHENTICATION =============

def generate_challenge_nonce():
    """
    Step 3.1: Generate random 256-bit nonce for challenge-response
    
    Returns:
        tuple: (nonce_hex, nonce_bytes)
    """
    nonce_bytes = secrets.token_bytes(32)  # 256 bits = 32 bytes
    nonce_hex = nonce_bytes.hex()
    
    print(f"[Challenge-Response] Generated nonce: {nonce_hex[:16]}...")
    return nonce_hex, nonce_bytes


def store_challenge_nonce(device_id, nonce_hex, expiry_seconds=300):
    """
    Store challenge nonce with expiry timestamp
    
    Args:
        device_id: Device identifier
        nonce_hex: Nonce in hex format
        expiry_seconds: Challenge validity period (default: 5 minutes)
    
    Returns:
        bool: Success status
    """
    try:
        expiry_time = datetime.now().timestamp() + expiry_seconds
        
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()

        # Compatibility: fix legacy misspelled table name if present
        try:
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='device_monotoniic_counters'")
            if cursor.fetchone():
                # rename legacy table to the correct name
                cursor.execute("ALTER TABLE device_monotoniic_counters RENAME TO device_monotonic_counters")
                print("[DB COMPAT] Renamed legacy table 'device_monotoniic_counters' -> 'device_monotonic_counters'")
        except Exception:
            # non-fatal: continue and ensure correct table exists
            pass

        # Ensure monotonic counter table exists before using it
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS device_monotonic_counters (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT NOT NULL,
                counter_value INTEGER NOT NULL,
                updated_at TEXT NOT NULL,
                verification_context TEXT
            )
        ''')
        
        # Create challenge table if not exists
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS challenge_nonces (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT NOT NULL,
                nonce TEXT NOT NULL,
                issued_at TEXT NOT NULL,
                expires_at REAL NOT NULL,
                is_used BOOLEAN DEFAULT 0,
                verified_at TEXT
            )
        ''')
        
        # Store new challenge
        cursor.execute('''
            INSERT INTO challenge_nonces
            (device_id, nonce, issued_at, expires_at)
            VALUES (?, ?, ?, ?)
        ''', (device_id, nonce_hex, datetime.now().isoformat(), expiry_time))
        
        conn.commit()
        conn.close()
        
        print(f"[Challenge-Response] Challenge stored for device: {device_id}")
        return True
    
    except Exception as e:
        print(f"[Challenge-Response] Error storing challenge: {e}")
        return False


def verify_challenge_response(device_id, nonce_hex, signature_hex):
    """
    Step 3.3: Verify device's signature on challenge nonce
    
    Args:
        device_id: Device identifier
        nonce_hex: Original nonce in hex
        signature_hex: Device's signature in hex
    
    Returns:
        tuple: (is_valid, message)
    """
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    from cryptography.exceptions import InvalidSignature
    
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # Check if challenge exists and is valid
        cursor.execute('''
            SELECT nonce, expires_at, is_used 
            FROM challenge_nonces
            WHERE device_id = ? AND nonce = ?
            ORDER BY issued_at DESC
            LIMIT 1
        ''', (device_id, nonce_hex))
        
        result = cursor.fetchone()
        
        if not result:
            conn.close()
            return False, "Challenge not found"
        
        stored_nonce, expires_at, is_used = result
        
        # Check if already used
        if is_used:
            conn.close()
            return False, "Challenge already used"
        
        # Check if expired
        if datetime.now().timestamp() > expires_at:
            conn.close()
            return False, "Challenge expired"
        
        # Get device's public key
        cursor.execute('''
            SELECT public_key, status
            FROM device_identity
            WHERE device_id = ?
        ''', (device_id,))
        
        device_result = cursor.fetchone()
        
        if not device_result:
            conn.close()
            return False, "Device not enrolled"
        
        public_key_pem, device_status = device_result
        
        if device_status != 'active':
            conn.close()
            return False, f"Device status is {device_status}"
        
        # Load public key
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode(),
            backend=default_backend()
        )
        
        # Convert signature from hex to bytes
        signature_bytes = bytes.fromhex(signature_hex)
        nonce_bytes = bytes.fromhex(nonce_hex)
        
        # Verify signature
        try:
            public_key.verify(
                signature_bytes,
                nonce_bytes,
                ec.ECDSA(hashes.SHA256())
            )
            
            # Mark challenge as used
            cursor.execute('''
                UPDATE challenge_nonces
                SET is_used = 1, verified_at = ?
                WHERE device_id = ? AND nonce = ?
            ''', (datetime.now().isoformat(), device_id, nonce_hex))
            
            conn.commit()
            conn.close()
            
            print(f"[Challenge-Response] ✅ Signature verification PASSED for {device_id}")
            return True, "Signature valid"
        
        except InvalidSignature:
            conn.close()
            print(f"[Challenge-Response] ❌ Invalid signature from {device_id}")
            return False, "Invalid signature"
    
    except Exception as e:
        return False, f"Verification error: {str(e)}"


def log_challenge_response_event(device_id, action, status, nonce=None, 
                                 error_details=None, ip_address=None):
    """
    Log challenge-response authentication events
    
    Args:
        device_id: Device identifier
        action: AUTH_CHALLENGE_ISSUED, AUTH_RESPONSE_VERIFIED, etc.
        status: SUCCESS, FAILED, ERROR
        nonce: Challenge nonce (first 16 chars for logging)
        error_details: Error message if failed
        ip_address: Client IP
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    try:
        # Create log table if not exists
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS challenge_response_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT NOT NULL,
                action TEXT NOT NULL,
                nonce_preview TEXT,
                status TEXT NOT NULL,
                error_details TEXT,
                ip_address TEXT,
                timestamp TEXT NOT NULL
            )
        ''')
        
        nonce_preview = nonce[:16] if nonce else None
        
        cursor.execute('''
            INSERT INTO challenge_response_log
            (device_id, action, nonce_preview, status, error_details, 
             ip_address, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (device_id, action, nonce_preview, status, error_details,
              ip_address, datetime.now().isoformat()))
        
        conn.commit()
        
        print(f"[Challenge-Response Log] {action} - Device: {device_id} - {status}")
    
    except Exception as e:
        print(f"[Challenge-Response Log] Error: {e}")
    
    finally:
        conn.close()


# ============= PHASE 4: CONTEXT-BOUND PROOF (CB-CCR) =============

def generate_contextual_challenge(device_id, required_contexts=None):
    """
    Phase 4 - Step 4.1: Generate contextual challenge requiring device state proof
    
    Args:
        device_id: Device identifier
        required_contexts: List of required context types (e.g., ['hw', 'time', 'counter'])
    
    Returns:
        tuple: (challenge_dict, challenge_id)
    """
    if required_contexts is None:
        required_contexts = ['hw', 'counter']  # Default: require hardware + counter
    
    # Generate cryptographic nonce (256 bits)
    nonce_bytes = secrets.token_bytes(32)
    nonce_hex = nonce_bytes.hex()
    
    # Create challenge ID for tracking
    challenge_id = hashlib.sha256(f"{device_id}{nonce_hex}{datetime.now().isoformat()}".encode()).hexdigest()[:16]
    
    # Build contextual challenge
    challenge = {
        "challenge_id": challenge_id,
        "nonce": nonce_hex,
        "required_contexts": required_contexts,
        "timestamp": datetime.now().isoformat(),
        "expires_in_seconds": 300  # 5 minutes validity
    }
    
    # Add specific requirements based on context types
    context_requirements = {}
    
    if 'hw' in required_contexts:
        context_requirements['hardware_state'] = {
            "description": "Provide SHA-256 hash of current hardware state",
            "required_fields": ["mcu_uid", "flash_size", "bootloader_crc"]
        }
    
    if 'counter' in required_contexts:
        context_requirements['monotonic_counter'] = {
            "description": "Provide current monotonic counter value",
            "note": "Counter must be >= last verified value"
        }
    
    if 'time' in required_contexts:
        context_requirements['timestamp'] = {
            "description": "Provide device timestamp",
            "note": "Clock skew must be within acceptable range"
        }
    
    if 'firmware' in required_contexts:
        context_requirements['firmware_hash'] = {
            "description": "Provide SHA-256 hash of current firmware",
            "note": "Must match last known valid firmware"
        }
    
    challenge['context_requirements'] = context_requirements
    
    print(f"[CB-CCR Challenge] Generated contextual challenge for {device_id}")
    print(f"[CB-CCR Challenge] Challenge ID: {challenge_id}")
    print(f"[CB-CCR Challenge] Required contexts: {', '.join(required_contexts)}")
    
    return challenge, challenge_id


def store_contextual_challenge(device_id, challenge_dict, challenge_id):
    """
    Store contextual challenge with metadata
    
    Args:
        device_id: Device identifier
        challenge_dict: Full challenge dictionary
        challenge_id: Unique challenge identifier
    
    Returns:
        bool: Success status
    """
    try:
        expiry_time = datetime.now().timestamp() + challenge_dict['expires_in_seconds']
        
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # Create contextual challenges table if not exists
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS contextual_challenges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                challenge_id TEXT UNIQUE NOT NULL,
                device_id TEXT NOT NULL,
                nonce TEXT NOT NULL,
                required_contexts TEXT NOT NULL,
                issued_at TEXT NOT NULL,
                expires_at REAL NOT NULL,
                is_used BOOLEAN DEFAULT 0,
                verified_at TEXT,
                context_proof TEXT
            )
        ''')
        
        # Store challenge
        cursor.execute('''
            INSERT INTO contextual_challenges
            (challenge_id, device_id, nonce, required_contexts, issued_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            challenge_id,
            device_id,
            challenge_dict['nonce'],
            json.dumps(challenge_dict['required_contexts']),
            datetime.now().isoformat(),
            expiry_time
        ))
        
        conn.commit()
        conn.close()
        
        print(f"[CB-CCR Challenge] Challenge stored with ID: {challenge_id}")
        return True
    
    except Exception as e:
        print(f"[CB-CCR Challenge] Error storing challenge: {e}")
        return False


def verify_context_bound_proof(device_id, challenge_id, nonce_hex, signature_hex, context_proof):
    """
    Phase 4 - Step 4.4: Verify context-bound proof from device
    ENHANCED WITH PHASE 5: Server verification logic
    
    Args:
        device_id: Device identifier
        challenge_id: Challenge identifier
        nonce_hex: Original nonce
        signature_hex: Device's signature
        context_proof: Dictionary containing contextual proof data
    
    Returns:
        tuple: (is_valid, verification_details, message, phase5_report)
    """
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    from cryptography.exceptions import InvalidSignature
    
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # Retrieve challenge
        cursor.execute('''
            SELECT nonce, required_contexts, expires_at, is_used
            FROM contextual_challenges
            WHERE challenge_id = ? AND device_id = ?
        ''', (challenge_id, device_id))
        
        result = cursor.fetchone()
        
        if not result:
            conn.close()
            return False, {}, "Challenge not found", None
        
        stored_nonce, required_contexts_json, expires_at, is_used = result
        required_contexts = json.loads(required_contexts_json)
        
        # Check if already used
        if is_used:
            conn.close()
            return False, {}, "Challenge already used", None
        
        # Check if expired
        if datetime.now().timestamp() > expires_at:
            conn.close()
            return False, {}, "Challenge expired", None
        
        # Get device's public key and stored state
        cursor.execute('''
            SELECT di.public_key, di.status, di.firmware_version,
                   dhb.hardware_fingerprint
            FROM device_identity di
            LEFT JOIN device_hardware_binding dhb ON di.device_id = dhb.device_id
            WHERE di.device_id = ?
        ''', (device_id,))
        
        device_result = cursor.fetchone()
        
        if not device_result:
            conn.close()
            return False, {}, "Device not enrolled", None
        
        public_key_pem, device_status, last_firmware_version, stored_hw_fp = device_result
        
        if device_status != 'active':
            conn.close()
            return False, {}, f"Device status is {device_status}", None
        
        # Close DB connection before Phase 5 verification
        conn.close()
        
        #PHASE 5: SERVER VERIFICATION LOGIC
    
        
        is_valid, phase5_report, failure_reason = perform_phase5_verification(
            device_id=device_id,
            nonce=nonce_hex,
            signature=signature_hex,
            context_proof=context_proof,
            public_key_pem=public_key_pem,
            stored_hw_fp=stored_hw_fp
        )
        
        # If Phase 5 verification fails, reject immediately
        if not is_valid:
            print(f"\n[Context-Bound Proof] ❌ Phase 5 verification FAILED")
            print(f"[Context-Bound Proof] Reason: {failure_reason}")
            
            # Log Phase 5 failure
            log_phase5_verification(device_id, phase5_report)
            
            verification_details = {
                "signature_valid": phase5_report["step_5_1_cryptography"]["details"].get("signature_valid", False),
                "hardware_state_valid": phase5_report["step_5_2_context_consistency"]["status"] == "PASSED",
                "counter_valid": phase5_report["step_5_3_temporal_continuity"]["details"].get("counter_valid", False),
                "timestamp_valid": phase5_report["step_5_3_temporal_continuity"]["details"].get("timestamp_valid", False),
                "phase5_trust_score": phase5_report["trust_score"],
                "phase5_result": phase5_report["overall_result"]
            }
            
            return False, verification_details, failure_reason, phase5_report
        
    
        # Phase 5 PASSED - Continue with normal Phase 4 processing
        
        print(f"\n[Context-Bound Proof] ✅ Phase 5 verification PASSED")
        print(f"[Context-Bound Proof] Trust Score: {phase5_report['trust_score']}/100")
        
        # Mark challenge as used
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE contextual_challenges
            SET is_used = 1, verified_at = ?, context_proof = ?
            WHERE challenge_id = ?
        ''', (datetime.now().isoformat(), json.dumps(context_proof), challenge_id))
        
        # Update monotonic counter if provided
        if 'counter' in required_contexts and phase5_report["step_5_3_temporal_continuity"]["details"]["counter_valid"]:
            provided_counter = context_proof.get('monotonic_counter')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS device_monotonic_counters (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id TEXT NOT NULL,
                    counter_value INTEGER NOT NULL,
                    updated_at TEXT NOT NULL,
                    verification_context TEXT
                )
            ''')
            
            cursor.execute('''
                INSERT INTO device_monotonic_counters
                (device_id, counter_value, updated_at, verification_context)
                VALUES (?, ?, ?, ?)
            ''', (device_id, provided_counter, datetime.now().isoformat(), challenge_id))
        
        conn.commit()
        conn.close()
        
        # Log successful Phase 5 verification
        log_phase5_verification(device_id, phase5_report)
        
        # Build verification details
        verification_details = {
            "signature_valid": True,
            "hardware_state_valid": phase5_report["step_5_2_context_consistency"]["status"] == "PASSED",
            "counter_valid": phase5_report["step_5_3_temporal_continuity"]["details"]["counter_valid"],
            "timestamp_valid": phase5_report["step_5_3_temporal_continuity"]["details"]["timestamp_valid"],
            "phase5_trust_score": phase5_report["trust_score"],
            "phase5_result": phase5_report["overall_result"]
        }
        
        return True, verification_details, "Context-bound proof verified successfully with Phase 5", phase5_report
    
    except Exception as e:
        return False, {}, f"Verification error: {str(e)}", None


def log_cb_ccr_event(device_id, action, status, challenge_id=None, 
                     verification_details=None, error_details=None, ip_address=None):
    """
    Log CB-CCR authentication events
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cb_ccr_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT NOT NULL,
                action TEXT NOT NULL,
                challenge_id TEXT,
                verification_details TEXT,
                status TEXT NOT NULL,
                error_details TEXT,
                ip_address TEXT,
                timestamp TEXT NOT NULL
            )
        ''')
        
        cursor.execute('''
            INSERT INTO cb_ccr_log
            (device_id, action, challenge_id, verification_details, status,
             error_details, ip_address, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            device_id,
            action,
            challenge_id,
            json.dumps(verification_details) if verification_details else None,
            status,
            error_details,
            ip_address,
            datetime.now().isoformat()
        ))
        
        conn.commit()
        print(f"[CB-CCR Log] {action} - Device: {device_id} - {status}")
    
    except Exception as e:
        print(f"[CB-CCR Log] Error: {e}")
    
    finally:
        conn.close()

def calculate_hardware_drift(stored_hw_fp, provided_hw_state_hash):
    """
    Phase 5 - Step 5.2: Calculate hardware fingerprint drift
    
    Allows small drift due to:
    - Boot time variations
    - Temperature sensor readings
    - Dynamic system values
    
    Args:
        stored_hw_fp (str): Previously stored hardware fingerprint
        provided_hw_state_hash (str): Current hardware state hash from device
    
    Returns:
        tuple: (drift_percentage, is_acceptable)
    """
    if not stored_hw_fp or not provided_hw_state_hash:
        return 100.0, False
    
    # Convert hex strings to binary
    stored_bytes = bytes.fromhex(stored_hw_fp)
    provided_bytes = bytes.fromhex(provided_hw_state_hash)
    
    # Calculate Hamming distance (bit differences)
    xor_result = bytes(a ^ b for a, b in zip(stored_bytes, provided_bytes))
    bit_differences = bin(int.from_bytes(xor_result, 'big')).count('1')
    
    # Total bits in SHA-256 hash
    total_bits = len(stored_bytes) * 8
    
    # Calculate drift percentage
    drift_percentage = (bit_differences / total_bits) * 100
    
    # Acceptable drift threshold: 5%
    # This allows for minor system variations while detecting hardware replacement
    ACCEPTABLE_DRIFT_THRESHOLD = 5.0
    
    is_acceptable = drift_percentage <= ACCEPTABLE_DRIFT_THRESHOLD
    
    print(f"[HW Drift Analysis] Bit differences: {bit_differences}/{total_bits}")
    print(f"[HW Drift Analysis] Drift: {drift_percentage:.2f}%")
    print(f"[HW Drift Analysis] Status: {'ACCEPTABLE ✓' if is_acceptable else 'EXCESSIVE ✗'}")
    
    return drift_percentage, is_acceptable


def verify_temporal_continuity(device_id, provided_counter, provided_timestamp=None):
    """
    Phase 5 - Step 5.3: Verify temporal continuity
    
    Checks:
    1. Counter is strictly increasing (no reuse = no replay)
    2. Timestamp is within acceptable window (if provided)
    
    Args:
        device_id (str): Device identifier
        provided_counter (int): Counter value from device
        provided_timestamp (str): Device timestamp (optional)
    
    Returns:
        dict: Verification results
    """
    verification_result = {
        "counter_valid": False,
        "timestamp_valid": False,
        "counter_check": "PENDING",
        "timestamp_check": "PENDING",
        "errors": []
    }
    
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # === COUNTER VERIFICATION ===
        print(f"\n[Temporal Continuity] Verifying counter for {device_id}...")
        
        # Get last known counter value
        cursor.execute('''
            SELECT counter_value, updated_at
            FROM device_monotonic_counters
            WHERE device_id = ?
            ORDER BY updated_at DESC
            LIMIT 1
        ''', (device_id,))
        
        counter_result = cursor.fetchone()
        
        if counter_result:
            last_counter = counter_result[0]
            last_update = counter_result[1]
            
            print(f"[Temporal Continuity] Last counter: {last_counter}")
            print(f"[Temporal Continuity] Provided counter: {provided_counter}")
            
            # Counter MUST be strictly increasing
            if provided_counter > last_counter:
                verification_result["counter_valid"] = True
                verification_result["counter_check"] = "INCREASING ✓"
                print(f"[Temporal Continuity] ✅ Counter is valid (increasing)")
            elif provided_counter == last_counter:
                verification_result["counter_check"] = "REUSED (REPLAY ATTACK) ✗"
                verification_result["errors"].append(f"Counter reused: {provided_counter}")
                print(f"[Temporal Continuity] ❌ Counter reused - REPLAY ATTACK DETECTED")
            else:
                verification_result["counter_check"] = "ROLLBACK (ATTACK) ✗"
                verification_result["errors"].append(f"Counter rollback: {provided_counter} < {last_counter}")
                print(f"[Temporal Continuity] ❌ Counter rollback - ATTACK DETECTED")
        else:
            # First authentication - accept counter
            verification_result["counter_valid"] = True
            verification_result["counter_check"] = "FIRST AUTH ✓"
            print(f"[Temporal Continuity] ✅ First authentication - counter accepted")
        
        # === TIMESTAMP VERIFICATION ===
        if provided_timestamp:
            print(f"\n[Temporal Continuity] Verifying timestamp...")
            
            try:
                device_time = datetime.fromisoformat(provided_timestamp)
                server_time = datetime.now(timezone.utc)
                
                time_diff = abs((server_time - device_time).total_seconds())
                
                # Acceptable clock skew: 120 seconds (2 minutes)
                ACCEPTABLE_CLOCK_SKEW = 120
                
                print(f"[Temporal Continuity] Device time: {device_time}")
                print(f"[Temporal Continuity] Server time: {server_time}")
                print(f"[Temporal Continuity] Clock skew: {time_diff:.2f}s")
                
                if time_diff <= ACCEPTABLE_CLOCK_SKEW:
                    verification_result["timestamp_valid"] = True
                    verification_result["timestamp_check"] = f"VALID (skew: {time_diff:.1f}s) ✓"
                    print(f"[Temporal Continuity] ✅ Timestamp valid")
                else:
                    verification_result["timestamp_check"] = f"CLOCK SKEW TOO LARGE ({time_diff:.1f}s) ✗"
                    verification_result["errors"].append(f"Clock skew: {time_diff:.1f}s > {ACCEPTABLE_CLOCK_SKEW}s")
                    print(f"[Temporal Continuity] ❌ Clock skew too large")
            
            except ValueError as e:
                verification_result["timestamp_check"] = "INVALID FORMAT ✗"
                verification_result["errors"].append(f"Invalid timestamp format: {str(e)}")
                print(f"[Temporal Continuity] ❌ Invalid timestamp format")
        else:
            verification_result["timestamp_valid"] = True  # Not required
            verification_result["timestamp_check"] = "NOT PROVIDED (OPTIONAL)"
        
        conn.close()
        
        return verification_result
    
    except Exception as e:
        verification_result["errors"].append(f"Temporal verification error: {str(e)}")
        return verification_result


def perform_phase5_verification(device_id, nonce, signature, context_proof, public_key_pem, stored_hw_fp):
    """
    Phase 5: Complete server-side verification logic
    
    Implements adaptive trust through three verification steps:
    1. Cryptographic verification (signature + public key)
    2. Context consistency verification (hardware drift)
    3. Temporal continuity verification (counter + timestamp)
    
    Args:
        device_id (str): Device identifier
        nonce (str): Challenge nonce
        signature (str): Device signature (hex)
        context_proof (dict): Context proof from device
        public_key_pem (str): Device's public key
        stored_hw_fp (str): Stored hardware fingerprint
    
    Returns:
        tuple: (is_valid, verification_report, failure_reason)
    """
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    from cryptography.exceptions import InvalidSignature
    
    print(f"\n{'='*70}")
    print(f"🔍 PHASE 5: SERVER VERIFICATION LOGIC")
    print(f"{'='*70}")
    print(f"Device: {device_id}")
    print(f"{'='*70}\n")
    
    verification_report = {
        "phase": "PHASE 5",
        "device_id": device_id,
        "step_5_1_cryptography": {"status": "PENDING", "details": {}},
        "step_5_2_context_consistency": {"status": "PENDING", "details": {}},
        "step_5_3_temporal_continuity": {"status": "PENDING", "details": {}},
        "overall_result": "PENDING",
        "trust_score": 0,
        "timestamp": datetime.now().isoformat()
    }
    
    # STEP 5.1: CRYPTOGRAPHIC VERIFICATION

    
    print(f"┌{'─'*68}┐")
    print(f"│ STEP 5.1: CRYPTOGRAPHIC VERIFICATION│")
    print(f"└{'─'*68}┘\n")
    
    try:
        # Load public key
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode(),
            backend=default_backend()
        )
        
        verification_report["step_5_1_cryptography"]["details"]["public_key_loaded"] = True
        print(f"✓ Public key loaded successfully")
        
        # Verify it's an ECC key
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            verification_report["step_5_1_cryptography"]["status"] = "FAILED"
            verification_report["step_5_1_cryptography"]["details"]["error"] = "Not an ECC key"
            print(f"✗ Not an ECC public key")
            return False, verification_report, "Invalid key type"
        
        verification_report["step_5_1_cryptography"]["details"]["key_type_valid"] = True
        print(f"✓ Key type verified (ECC)")
        
        # Reconstruct signed payload
        payload_parts = [nonce]
        
        if context_proof.get('hardware_state_hash'):
            payload_parts.append(context_proof['hardware_state_hash'])
        
        if context_proof.get('monotonic_counter') is not None:
            payload_parts.append(str(context_proof['monotonic_counter']))
        
        if context_proof.get('device_timestamp'):
            payload_parts.append(context_proof['device_timestamp'])

        if context_proof.get('firmware_hash'):
            payload_parts.append(context_proof['firmware_hash'])

        payload_string = '||'.join(payload_parts)
        payload_bytes = payload_string.encode('utf-8')
        
        print(f"✓ Payload reconstructed ({len(payload_parts)} components)")
        # Debug: show payload preview for troubleshooting signature mismatches
        print(f"[DEBUG] Payload preview: {payload_string[:200]}")

        # Convert signature from hex
        signature_bytes = bytes.fromhex(signature)
        
        # Verify signature
        try:
            public_key.verify(
                signature_bytes,
                payload_bytes,
                ec.ECDSA(hashes.SHA256())
            )
            
            verification_report["step_5_1_cryptography"]["status"] = "PASSED"
            verification_report["step_5_1_cryptography"]["details"]["signature_valid"] = True
            verification_report["trust_score"] += 40  # Cryptography = 40 points
            
            print(f"\n{'='*70}")
            print(f"✅ STEP 5.1 PASSED - CRYPTOGRAPHIC VERIFICATION SUCCESSFUL")
            print(f"{'='*70}\n")
        
        except InvalidSignature:
            verification_report["step_5_1_cryptography"]["status"] = "FAILED"
            verification_report["step_5_1_cryptography"]["details"]["signature_valid"] = False
            verification_report["step_5_1_cryptography"]["details"]["error"] = "Invalid signature"

            # Additional debug output to help diagnose signature mismatches
            try:
                print(f"[DEBUG] Signature (hex preview): {signature[:128]}")
                print(f"[DEBUG] Signature length (bytes): {len(signature_bytes)}")
                print(f"[DEBUG] Reconstructed payload (first 200 chars): {payload_string[:200]}")
            except Exception:
                pass

            print(f"\n{'='*70}")
            print(f"❌ STEP 5.1 FAILED - INVALID SIGNATURE")
            print(f"{'='*70}\n")

            return False, verification_report, "Invalid signature"
    
    except Exception as e:
        verification_report["step_5_1_cryptography"]["status"] = "ERROR"
        verification_report["step_5_1_cryptography"]["details"]["error"] = str(e)
        
        print(f"\n{'='*70}")
        print(f"❌ STEP 5.1 ERROR - {str(e)}")
        print(f"{'='*70}\n")
        
        return False, verification_report, f"Cryptographic verification error: {str(e)}"
    
    # STEP 5.2: CONTEXT CONSISTENCY VERIFICATION
    
    print(f"┌{'─'*68}┐")
    print(f"│ STEP 5.2: CONTEXT CONSISTENCY VERIFICATION                      │")
    print(f"└{'─'*68}┘\n")
    
    provided_hw_state = context_proof.get('hardware_state_hash')
    
    if provided_hw_state and stored_hw_fp:
        print(f"Stored HW FP:   {stored_hw_fp[:32]}...")
        print(f"Provided HW:    {provided_hw_state[:32]}...")
        
        # Calculate drift
        drift_percentage, is_acceptable = calculate_hardware_drift(stored_hw_fp, provided_hw_state)
        
        verification_report["step_5_2_context_consistency"]["details"]["stored_hw_fp"] = stored_hw_fp[:16] + "..."
        verification_report["step_5_2_context_consistency"]["details"]["provided_hw_state"] = provided_hw_state[:16] + "..."
        verification_report["step_5_2_context_consistency"]["details"]["drift_percentage"] = round(drift_percentage, 2)
        verification_report["step_5_2_context_consistency"]["details"]["drift_acceptable"] = is_acceptable
        
        if is_acceptable:
            verification_report["step_5_2_context_consistency"]["status"] = "PASSED"
            verification_report["trust_score"] += 30  # Context consistency = 30 points
            
            print(f"\n{'='*70}")
            print(f"✅ STEP 5.2 PASSED - CONTEXT CONSISTENCY VERIFIED")
            print(f"{'='*70}\n")
        else:
            verification_report["step_5_2_context_consistency"]["status"] = "FAILED"
            verification_report["step_5_2_context_consistency"]["details"]["error"] = "Hardware drift too large"
            
            print(f"\n{'='*70}")
            print(f"❌ STEP 5.2 FAILED - HARDWARE DRIFT TOO LARGE")
            print(f"⚠️  Possible hardware replacement or tampering detected")
            print(f"{'='*70}\n")
            
            return False, verification_report, f"Hardware drift {drift_percentage:.2f}% exceeds threshold"
    else:
        verification_report["step_5_2_context_consistency"]["status"] = "SKIPPED"
        verification_report["step_5_2_context_consistency"]["details"]["reason"] = "No hardware context provided"
        print(f"⚠️  Hardware context not provided - skipping drift check\n")
    
        # Check network drift (if provided)
    provided_net_state = context_proof.get('network_state_hash')

    if provided_net_state:
        # Get stored network fingerprint
        conn_temp = sqlite3.connect(DB_FILE)
        cursor_temp = conn_temp.cursor()
        cursor_temp.execute('''
            SELECT network_fingerprint FROM device_network_binding
            WHERE device_id = ?
        ''', (device_id,))
        net_result = cursor_temp.fetchone()
        stored_net_fp = net_result[0] if net_result else None
        conn_temp.close()
        
        if stored_net_fp:
            print(f"Stored Network FP: {stored_net_fp[:32]}...")
            print(f"Provided Network:  {provided_net_state[:32]}...")
            
            # Calculate network drift
            net_drift_percentage, net_is_acceptable = calculate_hardware_drift(stored_net_fp, provided_net_state)
            
            verification_report["step_5_2_context_consistency"]["details"]["stored_net_fp"] = stored_net_fp[:16] + "..."
            verification_report["step_5_2_context_consistency"]["details"]["provided_net_state"] = provided_net_state[:16] + "..."
            verification_report["step_5_2_context_consistency"]["details"]["net_drift_percentage"] = round(net_drift_percentage, 2)
            verification_report["step_5_2_context_consistency"]["details"]["net_drift_acceptable"] = net_is_acceptable
            
            if not net_is_acceptable:
                print(f"\n⚠️  NETWORK CHANGE DETECTED - Drift: {net_drift_percentage:.2f}%")
                print(f"⚠️  This may indicate device moved to different network")
                # Note: Network changes are less critical than hardware changes
                # We log but don't reject - could require admin approval in production
    
    # STEP 5.3: TEMPORAL CONTINUITY VERIFICATION
    
    print(f"┌{'─'*68}┐")
    print(f"│ STEP 5.3: TEMPORAL CONTINUITY VERIFICATION                      │")
    print(f"└{'─'*68}┘\n")
    
    provided_counter = context_proof.get('monotonic_counter')
    provided_timestamp = context_proof.get('device_timestamp')
    
    temporal_result = verify_temporal_continuity(device_id, provided_counter, provided_timestamp)
    
    verification_report["step_5_3_temporal_continuity"]["details"] = temporal_result
    
    if temporal_result["counter_valid"] and temporal_result["timestamp_valid"]:
        verification_report["step_5_3_temporal_continuity"]["status"] = "PASSED"
        verification_report["trust_score"] += 30  # Temporal continuity = 30 points
        
        print(f"\n{'='*70}")
        print(f"✅ STEP 5.3 PASSED - TEMPORAL CONTINUITY VERIFIED")
        print(f"{'='*70}\n")
    else:
        verification_report["step_5_3_temporal_continuity"]["status"] = "FAILED"
        
        print(f"\n{'='*70}")
        print(f"❌ STEP 5.3 FAILED - TEMPORAL CONTINUITY VIOLATION")
        print(f"⚠️  Errors: {', '.join(temporal_result['errors'])}")
        print(f"{'='*70}\n")
        
        return False, verification_report, f"Temporal continuity violation: {temporal_result['errors']}"
    
    # =========================================================================
    # FINAL ADAPTIVE TRUST DECISION
    # =========================================================================
    
    print(f"┌{'─'*68}┐")
    print(f"│ ADAPTIVE TRUST EVALUATION                                       │")
    print(f"└{'─'*68}┘\n")
    
    print(f"Trust Score Breakdown:")
    print(f"  • Cryptography (Step 5.1):        {40 if verification_report['step_5_1_cryptography']['status'] == 'PASSED' else 0}/40 points")
    print(f"  • Context Consistency (Step 5.2): {30 if verification_report['step_5_2_context_consistency']['status'] == 'PASSED' else 0}/30 points")
    print(f"  • Temporal Continuity (Step 5.3): {30 if verification_report['step_5_3_temporal_continuity']['status'] == 'PASSED' else 0}/30 points")
    print(f"  • Total Trust Score:              {verification_report['trust_score']}/100 points")
    
    # Trust threshold: 70/100 (must pass at least crypto + one other check)
    TRUST_THRESHOLD = 70
    
    if verification_report["trust_score"] >= TRUST_THRESHOLD:
        verification_report["overall_result"] = "TRUSTED"
        
        print(f"\n{'='*70}")
        print(f"✅ ✅ ✅  PHASE 5 VERIFICATION PASSED  ✅ ✅ ✅")
        print(f"{'='*70}")
        print(f"🎯 Trust Score: {verification_report['trust_score']}/100")
        print(f"✓ Device authenticated with high confidence")
        print(f"✓ All verification checks passed")
        print(f"{'='*70}\n")
        
        return True, verification_report, None
    else:
        verification_report["overall_result"] = "UNTRUSTED"
        
        print(f"\n{'='*70}")
        print(f"❌ ❌ ❌  PHASE 5 VERIFICATION FAILED  ❌ ❌ ❌")
        print(f"{'='*70}")
        print(f"🎯 Trust Score: {verification_report['trust_score']}/100 (threshold: {TRUST_THRESHOLD})")
        print(f"✗ Device cannot be trusted")
        print(f"{'='*70}\n")
        
        return False, verification_report, f"Trust score {verification_report['trust_score']} below threshold {TRUST_THRESHOLD}"


def log_phase5_verification(device_id, verification_report, client_ip=None):
    """
    Log Phase 5 verification results for audit trail
    
    Args:
        device_id (str): Device identifier
        verification_report (dict): Complete verification report
        client_ip (str): Client IP address
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS phase5_verification_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT NOT NULL,
                overall_result TEXT NOT NULL,
                trust_score INTEGER NOT NULL,
                step_5_1_status TEXT NOT NULL,
                step_5_2_status TEXT NOT NULL,
                step_5_3_status TEXT NOT NULL,
                verification_report TEXT NOT NULL,
                ip_address TEXT,
                timestamp TEXT NOT NULL
            )
        ''')
        
        cursor.execute('''
            INSERT INTO phase5_verification_log
            (device_id, overall_result, trust_score, step_5_1_status, 
             step_5_2_status, step_5_3_status, verification_report, 
             ip_address, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            device_id,
            verification_report["overall_result"],
            verification_report["trust_score"],
            verification_report["step_5_1_cryptography"]["status"],
            verification_report["step_5_2_context_consistency"]["status"],
            verification_report["step_5_3_temporal_continuity"]["status"],
            json.dumps(verification_report),
            client_ip,
            datetime.now().isoformat()
        ))
        
        conn.commit()
        
        print(f"[Phase 5 Log] Verification logged for device: {device_id}")
        print(f"[Phase 5 Log] Result: {verification_report['overall_result']}")
        print(f"[Phase 5 Log] Trust Score: {verification_report['trust_score']}/100")
    
    except Exception as e:
        print(f"[Phase 5 Log] Error: {e}")

def register_device_certificate(device_id, certificate_path):
    """
    Register a device's certificate for fingerprint binding
    
    Args:
        device_id: Unique device identifier
        certificate_path: Path to device's certificate file
    
    Returns:
        Certificate hash for fingerprint binding
    """
    try:
        # Calculate hash of certificate
        with open(certificate_path, 'rb') as f:
            cert_data = f.read()
        cert_hash = hashlib.sha256(cert_data).hexdigest()
        
        # Store in database
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO device_certificates
            (device_id, certificate_hash, certificate_path, registered_at, is_active)
            VALUES (?, ?, ?, ?, ?)
        ''', (device_id, cert_hash, certificate_path, datetime.now().isoformat(), 1))
        conn.commit()
        conn.close()
        
        print(f"[Device Auth] Certificate registered for device: {device_id}")
        print(f"[Device Auth] Fingerprint: {cert_hash[:16]}...")
        return cert_hash
    
    except Exception as e:
        print(f"[Device Auth] Error registering certificate: {e}")
        return None

def get_device_certificate_hash(device_id):
    """Retrieve device's certificate hash from database"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute('''
            SELECT certificate_hash FROM device_certificates 
            WHERE device_id = ? AND is_active = 1
        ''', (device_id,))
        result = cursor.fetchone()
        return result[0] if result else None
    finally:
        conn.close()

def log_device_auth_action(action, token_id, device_id, endpoint, status, error_details=None):
    """Log device authentication actions for audit trail"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT INTO device_auth_log
            (action, token_id, device_id, endpoint, status, error_details, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (action, token_id, device_id, endpoint, status, error_details, datetime.now().isoformat()))
        conn.commit()
        print(f"[Device Audit] {action} - Device: {device_id} - Status: {status}")
    except Exception as e:
        print(f"[Device Audit] Error logging action: {e}")
    finally:
        conn.close()

def cache_token(token, token_id, device_fingerprint, expires_at):
    """Cache JWT token locally for reference"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT INTO cached_tokens
            (token_id, token, device_fingerprint, obtained_at, expires_at, is_valid)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (token_id, token, device_fingerprint, datetime.now().isoformat(), expires_at, 1))
        conn.commit()
    except Exception as e:
        print(f"[Token Cache] Error caching token: {e}")
    finally:
        conn.close()

def obtain_jwt_token_from_cloud(device_id, device_certificate_path=None):
    """
    Request JWT token from Update Cloud Server
    This simulates IoT device authentication
    
    Args:
        device_id: Device identifier (e.g., "iot_device_001")
        device_certificate_path: Path to device certificate (for fingerprinting)
    
    Returns:
        Tuple: (token, token_id, device_fingerprint, is_success)
    """
    global CURRENT_JWT_TOKEN, CURRENT_DEVICE_FINGERPRINT
    
    try:
        # Calculate device fingerprint from certificate
        device_fingerprint = ""
        if device_certificate_path and os.path.exists(device_certificate_path):
            device_fingerprint = register_device_certificate(device_id, device_certificate_path)
        else:
            # Generate a fingerprint based on device_id for demonstration
            device_fingerprint = hashlib.sha256(device_id.encode()).hexdigest()
        
        # For IoT device context, we use special credentials
        credentials = {
            "username": f"iot_device_{device_id}",
            "password": f"device_password_{device_id}",
            "device_certificate_hash": device_fingerprint
        }
        
        # Request token from Update Cloud Server
        response = requests.post(
            f"{UPDATE_CLOUD_URL}/auth/login",
            json=credentials,
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            token = data['token']
            token_id = data['token_id']
            
            # Cache token locally
            cache_token(token, token_id, device_fingerprint, data['expires_in_minutes'])
            
            # Store globally for use in requests
            CURRENT_JWT_TOKEN = token
            CURRENT_DEVICE_FINGERPRINT = device_fingerprint
            
            # Log successful authentication
            log_device_auth_action(
                action="DEVICE_AUTH_SUCCESS",
                token_id=token_id,
                device_id=device_id,
                endpoint="/auth/login",
                status="SUCCESS",
                error_details=None
            )
            
            print(f"[Device Auth] JWT obtained successfully for device: {device_id}")
            print(f"[Device Auth] Token expires in: {data['expires_in_minutes']} minutes")
            
            return token, token_id, device_fingerprint, True
        
        else:
            error_msg = response.json().get('error', 'Unknown error')
            log_device_auth_action(
                action="DEVICE_AUTH_FAILED",
                token_id="NONE",
                device_id=device_id,
                endpoint="/auth/login",
                status="FAILED",
                error_details=error_msg
            )
            print(f"[Device Auth] Failed to obtain token: {error_msg}")
            return None, None, None, False
    
    except requests.exceptions.ConnectionError:
        log_device_auth_action(
            action="DEVICE_AUTH_ERROR",
            token_id="NONE",
            device_id=device_id,
            endpoint="/auth/login",
            status="ERROR",
            error_details="Cannot connect to Update Cloud Server"
        )
        print("[Device Auth] Cannot connect to Update Cloud Server")
        return None, None, None, False
    
    except Exception as e:
        log_device_auth_action(
            action="DEVICE_AUTH_ERROR",
            token_id="NONE",
            device_id=device_id,
            endpoint="/auth/login",
            status="ERROR",
            error_details=str(e)
        )
        print(f"[Device Auth] Error obtaining token: {e}")
        return None, None, None, False
      

# Calculate hash of a file
def calculate_file_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

# Store verification result in database
def store_verification_result(firmware_name, received_hash, calculated_hash, hash_match, status):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT INTO firmware_verification
            (firmware_name, received_hash, calculated_hash, hash_match, timestamp, status)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (firmware_name, received_hash, calculated_hash, hash_match, datetime.now().isoformat(), status))
        conn.commit()
        print(f"[Database] Verification result stored for: {firmware_name}")
    except Exception as e:
        print(f"[Database] Error storing verification result: {e}")
    finally:
        conn.close()

def fetch_encryption_key():
    """
    Fetch encryption key from Update Cloud Server
    """
    global cipher
    try:
        response = requests.get(f"{UPDATE_CLOUD_URL}/get-encryption-key")
        if response.status_code == 200:
            key_data = response.json()
            key = base64.b64decode(key_data['encryption_key'])
            
            # Save key locally
            with open(KEY_FILE, 'wb') as f:
                f.write(key)
            
            encryption_key = key
            print("[Encryption] Key fetched and saved successfully")
            return True
        else:
            print("[Encryption] Failed to fetch key")
            return False
    except Exception as e:
        print(f"[Encryption] Error fetching key: {e}")
        return False

def load_encryption_key():
    """
    Load encryption key from file or fetch from server
    """
    global cipher
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, 'rb') as f:
            key = f.read()
            encryption_key = key
        print("[Encryption] Key loaded from local file")
        return True
    else:
        return fetch_encryption_key()

# AES-256-CBC decryption function
def decrypt_data(encrypted_data, key):
    """
    Decrypt AES-256-CBC encrypted data
    
    Args:
        encrypted_data: IV + encrypted data (IV is first 16 bytes)
        key: AES-256 key (32 bytes)
    
    Returns:
        Decrypted data
    """
    # Extract IV (first 16 bytes)
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    
    # Create cipher
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # Decrypt
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove PKCS7 padding
    padding_length = padded_data[-1]
    decrypted_data = padded_data[:-padding_length]
    
    return decrypted_data


# Create download directory if it doesn't exist
if not os.path.exists(DOWNLOAD_DIR):
    os.makedirs(DOWNLOAD_DIR)

# Initialize database and encryption
init_database()
print("[Zero Trust Server] Attempting to load encryption key...")
if not load_encryption_key():
    print("[Warning] Could not load encryption key. Encrypted operations will fail.")

def validate_ecc_public_key(public_key_pem):
    """
    Validate that the public key is in correct PEM format and is an ECC P-256 key
    
    Args:
        public_key_pem (str): Public key in PEM format
    
    Returns:
        tuple: (is_valid, error_message)
    """
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.backends import default_backend
        
        # Try to load the public key
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode() if isinstance(public_key_pem, str) else public_key_pem,
            backend=default_backend()
        )
        
        # Verify it's an ECC key
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            return False, "Key is not an ECC key"
        
        # Verify it's using P-256 curve (SECP256R1)
        if not isinstance(public_key.curve, ec.SECP256R1):
            return False, f"Invalid curve. Expected P-256, got {public_key.curve.name}"
        
        return True, None
    
    except ValueError as e:
        return False, f"Invalid PEM format: {str(e)}"
    except Exception as e:
        return False, f"Key validation error: {str(e)}"


def generate_public_key_fingerprint(public_key_pem):
    """
    Generate SHA-256 fingerprint of public key
    
    Args:
        public_key_pem (str): Public key in PEM format
    
    Returns:
        str: SHA-256 fingerprint (hex)
    """
    if isinstance(public_key_pem, str):
        public_key_pem = public_key_pem.encode()
    
    fingerprint = hashlib.sha256(public_key_pem).hexdigest()
    return fingerprint


def check_device_enrollment_status(device_id):
    """
    Check if device is already enrolled
    
    Args:
        device_id (str): Device identifier
    
    Returns:
        dict: Device enrollment info or None
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            SELECT device_id, status, enrollment_timestamp, public_key_fingerprint, 
                   enrollment_count, firmware_version
            FROM device_identity 
            WHERE device_id = ?
        ''', (device_id,))
        
        result = cursor.fetchone()
        
        if result:
            return {
                "device_id": result[0],
                "status": result[1],
                "enrollment_timestamp": result[2],
                "public_key_fingerprint": result[3],
                "enrollment_count": result[4],
                "firmware_version": result[5]
            }
        return None
    
    finally:
        conn.close()


def store_device_identity(device_id, public_key_pem, device_type, firmware_version):
    """
    Store device cryptographic identity in database
    
    Args:
        device_id (str): Unique device identifier
        public_key_pem (str): Device's ECC public key
        device_type (str): Type of device
        firmware_version (str): Current firmware version
    
    Returns:
        tuple: (success, message, fingerprint)
    """
    try:
        # Generate fingerprint
        pub_key_fingerprint = generate_public_key_fingerprint(public_key_pem)
        timestamp = datetime.now().isoformat()
        
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # Check if device already exists
        existing = check_device_enrollment_status(device_id)
        
        if existing:
            # Re-enrollment: Update existing device
            cursor.execute('''
                UPDATE device_identity 
                SET public_key = ?,
                    public_key_fingerprint = ?,
                    firmware_version = ?,
                    device_type = ?,
                    enrollment_count = enrollment_count + 1,
                    updated_at = ?,
                    last_seen = ?
                WHERE device_id = ?
            ''', (public_key_pem, pub_key_fingerprint, firmware_version, 
                  device_type, timestamp, timestamp, device_id))
            
            action = "RE-ENROLLMENT"
            message = f"Device {device_id} re-enrolled successfully"
        else:
            # New enrollment
            cursor.execute('''
                INSERT INTO device_identity 
                (device_id, public_key, public_key_fingerprint, status, 
                 enrollment_timestamp, last_seen, firmware_version, device_type,
                 key_algorithm, created_at)
                VALUES (?, ?, ?, 'active', ?, ?, ?, ?, 'ECC-P256', ?)
            ''', (device_id, public_key_pem, pub_key_fingerprint, timestamp, 
                  timestamp, firmware_version, device_type, timestamp))
            
            action = "NEW_ENROLLMENT"
            message = f"Device {device_id} enrolled successfully"
        
        conn.commit()
        conn.close()
        
        return True, message, pub_key_fingerprint, action
    
    except sqlite3.IntegrityError as e:
        return False, f"Database integrity error: {str(e)}", None, "ERROR"
    except Exception as e:
        return False, f"Storage error: {str(e)}", None, "ERROR"


def log_device_enrollment(device_id, action, status, public_key_fingerprint=None, 
                         error_details=None, ip_address=None):
    """
    Log device enrollment events for audit trail
    
    Args:
        device_id (str): Device identifier
        action (str): Enrollment action (NEW_ENROLLMENT, RE_ENROLLMENT, etc.)
        status (str): Status (SUCCESS, FAILED, ERROR)
        public_key_fingerprint (str): Public key fingerprint
        error_details (str): Error message if failed
        ip_address (str): Client IP address
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            INSERT INTO device_enrollment_log
            (device_id, action, public_key_fingerprint, status, error_details, 
             ip_address, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (device_id, action, public_key_fingerprint, status, error_details,
              ip_address, datetime.now().isoformat()))
        
        conn.commit()
        
        print(f"[Enrollment Log] {action} - Device: {device_id} - Status: {status}")
    
    except Exception as e:
        print(f"[Enrollment Log] Error: {e}")
    
    finally:
        conn.close()

def store_hardware_binding(device_id, hardware_fingerprint, public_key_fingerprint, hardware_info=None):
    """
    Store hardware fingerprint binding for a device
    
    Args:
        device_id (str): Device identifier
        hardware_fingerprint (str): SHA-256 hash of hardware characteristics
        public_key_fingerprint (str): Public key fingerprint
        hardware_info (dict): Optional hardware details for logging
    
    Returns:
        tuple: (success, message, action)
    """
    try:
        timestamp = datetime.now().isoformat()
        
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # Check if hardware binding already exists
        cursor.execute('''
            SELECT hardware_fingerprint, binding_timestamp, verification_count
            FROM device_hardware_binding
            WHERE device_id = ?
        ''', (device_id,))
        
        existing = cursor.fetchone()
        
        if existing:
            existing_hw_fp = existing[0]
            
            if existing_hw_fp == hardware_fingerprint:
                # Same hardware fingerprint - update verification count
                cursor.execute('''
                    UPDATE device_hardware_binding
                    SET last_verified = ?,
                        verification_count = verification_count + 1
                    WHERE device_id = ?
                ''', (timestamp, device_id))
                
                action = "HW_BINDING_VERIFIED"
                message = f"Hardware fingerprint verified for device {device_id}"
            else:
                # Different hardware fingerprint - potential security issue
                log_hardware_verification(
                    device_id=device_id,
                    hardware_fingerprint=hardware_fingerprint,
                    verification_type="HW_MISMATCH",
                    match_result=False,
                    action_taken="BINDING_REJECTED"
                )
                
                conn.close()
                return False, "Hardware fingerprint mismatch - possible device replacement or tampering", "HW_MISMATCH"
        else:
            # New hardware binding
            hw_info_json = json.dumps(hardware_info) if hardware_info else None
            
            cursor.execute('''
                INSERT INTO device_hardware_binding
                (device_id, hardware_fingerprint, public_key_fingerprint, 
                 binding_timestamp, last_verified, hardware_info, binding_status)
                VALUES (?, ?, ?, ?, ?, ?, 'active')
            ''', (device_id, hardware_fingerprint, public_key_fingerprint, 
                  timestamp, timestamp, hw_info_json))
            
            action = "NEW_HW_BINDING"
            message = f"Hardware binding created for device {device_id}"
        
        conn.commit()
        conn.close()
        
        # Log successful binding
        log_hardware_verification(
            device_id=device_id,
            hardware_fingerprint=hardware_fingerprint,
            verification_type=action,
            match_result=True,
            action_taken="BINDING_ACCEPTED"
        )
        
        return True, message, action
    
    except Exception as e:
        return False, f"Hardware binding error: {str(e)}", "ERROR"

def store_network_binding(device_id, network_fingerprint, public_key_fingerprint, network_info=None):
    """
    Store network fingerprint binding for a device
    
    Args:
        device_id (str): Device identifier
        network_fingerprint (str): SHA-256 hash of network characteristics
        public_key_fingerprint (str): Public key fingerprint
        network_info (dict): Optional network details for logging
    
    Returns:
        tuple: (success, message, action)
    """
    try:
        timestamp = datetime.now().isoformat()
        
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # Check if network binding already exists
        cursor.execute('''
            SELECT network_fingerprint, binding_timestamp, verification_count
            FROM device_network_binding
            WHERE device_id = ?
        ''', (device_id,))
        
        existing = cursor.fetchone()
        
        if existing:
            existing_net_fp = existing[0]
            
            if existing_net_fp == network_fingerprint:
                # Same network fingerprint - update verification count
                cursor.execute('''
                    UPDATE device_network_binding
                    SET last_verified = ?,
                        verification_count = verification_count + 1
                    WHERE device_id = ?
                ''', (timestamp, device_id))
                
                action = "NET_BINDING_VERIFIED"
                message = f"Network fingerprint verified for device {device_id}"
            else:
                # Different network fingerprint - potential network change
                log_network_verification(
                    device_id=device_id,
                    network_fingerprint=network_fingerprint,
                    verification_type="NET_CHANGE_DETECTED",
                    match_result=False,
                    action_taken="BINDING_UPDATED"
                )
                
                # Update to new network fingerprint
                cursor.execute('''
                    UPDATE device_network_binding
                    SET network_fingerprint = ?,
                        last_verified = ?,
                        verification_count = verification_count + 1,
                        network_info = ?
                    WHERE device_id = ?
                ''', (network_fingerprint, timestamp, json.dumps(network_info) if network_info else None, device_id))
                
                action = "NET_CHANGE"
                message = f"Network change detected for device {device_id} - binding updated"
        else:
            # New network binding
            net_info_json = json.dumps(network_info) if network_info else None
            
            cursor.execute('''
                INSERT INTO device_network_binding
                (device_id, network_fingerprint, public_key_fingerprint, 
                 binding_timestamp, last_verified, network_info, binding_status)
                VALUES (?, ?, ?, ?, ?, ?, 'active')
            ''', (device_id, network_fingerprint, public_key_fingerprint, 
                  timestamp, timestamp, net_info_json))
            
            action = "NEW_NET_BINDING"
            message = f"Network binding created for device {device_id}"
        
        conn.commit()
        conn.close()
        
        # Log successful binding
        log_network_verification(
            device_id=device_id,
            network_fingerprint=network_fingerprint,
            verification_type=action,
            match_result=True,
            action_taken="BINDING_ACCEPTED"
        )
        
        return True, message, action
    
    except Exception as e:
        return False, f"Network binding error: {str(e)}", "ERROR"


def log_network_verification(device_id, network_fingerprint, verification_type, 
                             match_result, action_taken, ip_address=None):
    """
    Log network fingerprint verification events
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            INSERT INTO network_verification_log
            (device_id, network_fingerprint, verification_type, match_result,
             action_taken, ip_address, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (device_id, network_fingerprint, verification_type, match_result,
              action_taken, ip_address, datetime.now().isoformat()))
        
        conn.commit()
        
        result_str = "PASSED" if match_result else "FAILED"
        print(f"[Network Verification Log] {verification_type} - Device: {device_id} - {result_str}")
    
    except Exception as e:
        print(f"[Network Verification Log] Error: {e}")
    
    finally:
        conn.close()


def verify_hardware_fingerprint(device_id, provided_hw_fp):
    """
    Verify hardware fingerprint matches stored value
    
    Args:
        device_id (str): Device identifier
        provided_hw_fp (str): Hardware fingerprint provided by device
    
    Returns:
        tuple: (is_valid, stored_hw_fp, message)
    """
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT hardware_fingerprint, binding_status
            FROM device_hardware_binding
            WHERE device_id = ?
        ''', (device_id,))
        
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            return False, None, "No hardware binding found for device"
        
        stored_hw_fp, binding_status = result
        
        if binding_status != 'active':
            return False, stored_hw_fp, f"Hardware binding status is {binding_status}"
        
        if stored_hw_fp == provided_hw_fp:
            return True, stored_hw_fp, "Hardware fingerprint verified"
        else:
            return False, stored_hw_fp, "Hardware fingerprint mismatch"
    
    except Exception as e:
        return False, None, f"Verification error: {str(e)}"


def log_hardware_verification(device_id, hardware_fingerprint, verification_type, 
                              match_result, action_taken, ip_address=None):
    """
    Log hardware fingerprint verification events
    
    Args:
        device_id (str): Device identifier
        hardware_fingerprint (str): Hardware fingerprint
        verification_type (str): Type of verification
        match_result (bool): Whether verification passed
        action_taken (str): Action taken based on result
        ip_address (str): Client IP address
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            INSERT INTO hardware_verification_log
            (device_id, hardware_fingerprint, verification_type, match_result,
             action_taken, ip_address, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (device_id, hardware_fingerprint, verification_type, match_result,
              action_taken, ip_address, datetime.now().isoformat()))
        
        conn.commit()
        
        result_str = "PASSED" if match_result else "FAILED"
        print(f"[HW Verification Log] {verification_type} - Device: {device_id} - {result_str}")
    
    except Exception as e:
        print(f"[HW Verification Log] Error: {e}")
    
    finally:
        conn.close()

@app.route('/device/register', methods=['POST'])
def register_device():
    """
    Register a new IoT device with certificate-based authentication
    
    Expected JSON:
    {
        "device_id": "iot_device_001",
        "certificate_path": "/path/to/device/certificate.pem"
    }
    """
    try:
        data = request.get_json()
        
        if not data or 'device_id' not in data or 'certificate_path' not in data:
            return jsonify({"error": "device_id and certificate_path required"}), 400
        
        device_id = data['device_id']
        cert_path = data['certificate_path']
        
        if not os.path.exists(cert_path):
            return jsonify({"error": "Certificate file not found"}), 404
        
        cert_hash = register_device_certificate(device_id, cert_path)
        
        if not cert_hash:
            return jsonify({"error": "Failed to register device"}), 500
        
        log_device_auth_action(
            action="DEVICE_REGISTERED",
            token_id="NONE",
            device_id=device_id,
            endpoint="/device/register",
            status="SUCCESS",
            error_details=None
        )
        
        return jsonify({
            "status": "success",
            "message": f"Device registered successfully",
            "device_id": device_id,
            "certificate_fingerprint": cert_hash
        }), 200
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/device/auth-logs', methods=['GET'])
def get_device_auth_logs():
    """
    Get device authentication logs (for audit trail)
    """
    try:
        limit = request.args.get('limit', 50, type=int)
        device_id = request.args.get('device_id', None)
        
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        if device_id:
            cursor.execute('''
                SELECT id, action, token_id, device_id, endpoint, status, error_details, timestamp
                FROM device_auth_log
                WHERE device_id = ?
                ORDER BY timestamp DESC LIMIT ?
            ''', (device_id, limit))
        else:
            cursor.execute('''
                SELECT id, action, token_id, device_id, endpoint, status, error_details, timestamp
                FROM device_auth_log
                ORDER BY timestamp DESC LIMIT ?
            ''', (limit,))
        
        results = cursor.fetchall()
        conn.close()
        
        logs = [
            {
                "id": row[0],
                "action": row[1],
                "token_id": row[2],
                "device_id": row[3],
                "endpoint": row[4],
                "status": row[5],
                "error_details": row[6],
                "timestamp": row[7]
            }
            for row in results
        ]
        
        return jsonify({"device_auth_logs": logs}), 200
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "Zero Trust Layer Server is running", "port": 5000}), 200

@app.route('/auth/challenge', methods=['POST'])
def issue_challenge():
    """
    Phase 3 - Step 3.1: Issue authentication challenge to device
    
    Expected JSON:
    {
        "device_id": "iot-device-001"
    }
    
    Returns:
        JSON with challenge nonce
    """
    try:
        data = request.get_json()
        client_ip = request.remote_addr
        
        if not data or 'device_id' not in data:
            return jsonify({
                "success": False,
                "message": "device_id required"
            }), 400
        
        device_id = data['device_id']
        
        # Check if device is enrolled
        device_info = check_device_enrollment_status(device_id)
        
        if not device_info:
            log_challenge_response_event(
                device_id=device_id,
                action="CHALLENGE_REJECTED",
                status="FAILED",
                error_details="Device not enrolled",
                ip_address=client_ip
            )
            return jsonify({
                "success": False,
                "message": "Device not enrolled"
            }), 404
        
        if device_info['status'] != 'active':
            log_challenge_response_event(
                device_id=device_id,
                action="CHALLENGE_REJECTED",
                status="FAILED",
                error_details=f"Device status: {device_info['status']}",
                ip_address=client_ip
            )
            return jsonify({
                "success": False,
                "message": f"Device status is {device_info['status']}"
            }), 403
        
        # Generate challenge nonce
        nonce_hex, nonce_bytes = generate_challenge_nonce()
        
        # Store challenge
        if not store_challenge_nonce(device_id, nonce_hex):
            return jsonify({
                "success": False,
                "message": "Failed to store challenge"
            }), 500
        
        # Log challenge issued
        log_challenge_response_event(
            device_id=device_id,
            action="CHALLENGE_ISSUED",
            status="SUCCESS",
            nonce=nonce_hex,
            ip_address=client_ip
        )
        
        log_system_event(
            event_type="AUTH_CHALLENGE_ISSUED",
            component="CHALLENGE_RESPONSE_AUTH",
            description=f"Challenge issued to device {device_id}",
            severity="INFO",
            additional_data=f"Nonce: {nonce_hex[:16]}..."
        )
        
        print(f"\n[Challenge-Response] {'='*60}")
        print(f"[Challenge-Response] Challenge issued to: {device_id}")
        print(f"[Challenge-Response] Nonce: {nonce_hex[:32]}...")
        print(f"[Challenge-Response] Valid for: 5 minutes")
        print(f"[Challenge-Response] {'='*60}\n")
        
        return jsonify({
            "success": True,
            "device_id": device_id,
            "challenge": nonce_hex,
            "expires_in_seconds": 300,
            "message": "Sign this challenge with your private key"
        }), 200
    
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error issuing challenge: {str(e)}"
        }), 500


@app.route('/auth/verify', methods=['POST'])
def verify_challenge():
    """
    Phase 3 - Step 3.3: Verify device's challenge response
    
    Expected JSON:
    {
        "device_id": "iot-device-001",
        "challenge": "abc123...",
        "signature": "def456..."
    }
    
    Returns:
        JSON with verification result
    """
    try:
        data = request.get_json()
        client_ip = request.remote_addr
        
        if not data or 'device_id' not in data or 'challenge' not in data or 'signature' not in data:
            return jsonify({
                "success": False,
                "message": "device_id, challenge, and signature required"
            }), 400
        
        device_id = data['device_id']
        nonce_hex = data['challenge']
        signature_hex = data['signature']
        
        print(f"\n[Challenge-Response] {'='*60}")
        print(f"[Challenge-Response] Verifying response from: {device_id}")
        print(f"[Challenge-Response] Challenge: {nonce_hex[:32]}...")
        print(f"[Challenge-Response] Signature: {signature_hex[:32]}...")
        
        # Verify signature
        is_valid, message = verify_challenge_response(device_id, nonce_hex, signature_hex)
        
        if is_valid:
            log_challenge_response_event(
                device_id=device_id,
                action="CHALLENGE_VERIFIED",
                status="SUCCESS",
                nonce=nonce_hex,
                ip_address=client_ip
            )
            
            log_verification_event(
                firmware_name="N/A",
                device_id=device_id,
                verification_type="CHALLENGE_RESPONSE",
                expected_value="Valid signature",
                actual_value="Signature verified",
                match_result=True,
                action_taken="DEVICE_AUTHENTICATED"
            )
            
            log_system_event(
                event_type="AUTH_SUCCESS",
                component="CHALLENGE_RESPONSE_AUTH",
                description=f"Device {device_id} authenticated successfully",
                severity="INFO"
            )
            
            print(f"[Challenge-Response] ✅ AUTHENTICATION SUCCESSFUL")
            print(f"[Challenge-Response] {'='*60}\n")
            
            return jsonify({
                "success": True,
                "device_id": device_id,
                "authenticated": True,
                "message": "Device authenticated successfully",
                "timestamp": datetime.now().isoformat()
            }), 200
        
        else:
            log_challenge_response_event(
                device_id=device_id,
                action="CHALLENGE_VERIFICATION_FAILED",
                status="FAILED",
                nonce=nonce_hex,
                error_details=message,
                ip_address=client_ip
            )
            
            log_failed_device_attempt(
                attempt_type="AUTH_FAILED",
                device_id=device_id,
                target_resource="CHALLENGE_RESPONSE_AUTH",
                reason="Signature verification failed",
                error_details=message
            )
            
            print(f"[Challenge-Response] ❌ AUTHENTICATION FAILED: {message}")
            print(f"[Challenge-Response] {'='*60}\n")
            
            return jsonify({
                "success": False,
                "device_id": device_id,
                "authenticated": False,
                "message": message
            }), 401
    
    except Exception as e:
        log_challenge_response_event(
            device_id=data.get('device_id', 'UNKNOWN') if data else 'UNKNOWN',
            action="CHALLENGE_VERIFICATION_ERROR",
            status="ERROR",
            error_details=str(e),
            ip_address=request.remote_addr
        )
        
        return jsonify({
            "success": False,
            "message": f"Verification error: {str(e)}"
        }), 500


@app.route('/challenge-logs', methods=['GET'])
def get_challenge_logs():
    """
    Get challenge-response authentication logs
    
    Query parameters:
        - device_id: Filter by device (optional)
        - limit: Maximum results (default: 50)
    """
    try:
        device_id_filter = request.args.get('device_id', None)
        limit = request.args.get('limit', 50, type=int)
        
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # Ensure table exists
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS challenge_response_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT NOT NULL,
                action TEXT NOT NULL,
                nonce_preview TEXT,
                status TEXT NOT NULL,
                error_details TEXT,
                ip_address TEXT,
                timestamp TEXT NOT NULL
            )
        ''')
        
        if device_id_filter:
            cursor.execute('''
                SELECT id, device_id, action, nonce_preview, status,
                       error_details, ip_address, timestamp
                FROM challenge_response_log
                WHERE device_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (device_id_filter, limit))
        else:
            cursor.execute('''
                SELECT id, device_id, action, nonce_preview, status,
                       error_details, ip_address, timestamp
                FROM challenge_response_log
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (limit,))
        
        results = cursor.fetchall()
        conn.close()
        
        logs = [
            {
                "id": row[0],
                "device_id": row[1],
                "action": row[2],
                "nonce_preview": row[3],
                "status": row[4],
                "error_details": row[5],
                "ip_address": row[6],
                "timestamp": row[7]
            }
            for row in results
        ]
        
        return jsonify({
            "success": True,
            "count": len(logs),
            "challenge_response_logs": logs
        }), 200
    
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error retrieving logs: {str(e)}"
        }), 500

@app.route('/auth/challenge-context', methods=['POST'])
def issue_contextual_challenge():
    """
    Phase 4 - Step 4.1: Issue contextual challenge to device
    
    Expected JSON:
    {
        "device_id": "iot-device-001",
        "required_contexts": ["hw", "counter"]  // Optional
    }
    """
    try:
        data = request.get_json()
        client_ip = request.remote_addr
        
        if not data or 'device_id' not in data:
            return jsonify({
                "success": False,
                "message": "device_id required"
            }), 400
        
        device_id = data['device_id']
        required_contexts = data.get('required_contexts', ['hw', 'counter'])
        
        # Check if device is enrolled
        device_info = check_device_enrollment_status(device_id)
        
        if not device_info:
            log_cb_ccr_event(
                device_id=device_id,
                action="CONTEXTUAL_CHALLENGE_REJECTED",
                status="FAILED",
                error_details="Device not enrolled",
                ip_address=client_ip
            )
            return jsonify({
                "success": False,
                "message": "Device not enrolled"
            }), 404
        
        if device_info['status'] != 'active':
            log_cb_ccr_event(
                device_id=device_id,
                action="CONTEXTUAL_CHALLENGE_REJECTED",
                status="FAILED",
                error_details=f"Device status: {device_info['status']}",
                ip_address=client_ip
            )
            return jsonify({
                "success": False,
                "message": f"Device status is {device_info['status']}"
            }), 403
        
        # Generate contextual challenge
        challenge, challenge_id = generate_contextual_challenge(device_id, required_contexts)
        
        # Store challenge
        if not store_contextual_challenge(device_id, challenge, challenge_id):
            return jsonify({
                "success": False,
                "message": "Failed to store challenge"
            }), 500
        
        # Log challenge issued
        log_cb_ccr_event(
            device_id=device_id,
            action="CONTEXTUAL_CHALLENGE_ISSUED",
            status="SUCCESS",
            challenge_id=challenge_id,
            ip_address=client_ip
        )
        
        log_system_event(
            event_type="CB_CCR_CHALLENGE_ISSUED",
            component="CB_CCR_AUTH",
            description=f"Contextual challenge issued to device {device_id}",
            severity="INFO",
            additional_data=f"Challenge ID: {challenge_id}, Contexts: {required_contexts}"
        )
        
        print(f"\n[CB-CCR] {'='*60}")
        print(f"[CB-CCR] Contextual challenge issued to: {device_id}")
        print(f"[CB-CCR] Challenge ID: {challenge_id}")
        print(f"[CB-CCR] Required contexts: {', '.join(required_contexts)}")
        print(f"[CB-CCR] Valid for: 5 minutes")
        print(f"[CB-CCR] {'='*60}\n")
        
        return jsonify({
            "success": True,
            "challenge": challenge,
            "message": "Sign the complete context-bound payload"
        }), 200
    
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error issuing contextual challenge: {str(e)}"
        }), 500


@app.route('/auth/verify-context', methods=['POST'])
def verify_contextual_proof():
    """
    Phase 4 - Step 4.4: Verify device's context-bound proof
    ENHANCED WITH PHASE 5: Server verification logic
    
    Expected JSON:
    {
        "device_id": "iot-device-001",
        "challenge_id": "abc123...",
        "nonce": "def456...",
        "signature": "789ghi...",
        "context_proof": {
            "hardware_state_hash": "...",
            "monotonic_counter": 5,
            "device_timestamp": "2025-01-...",
            "firmware_hash": "..."
        }
    }
    """
    try:
        data = request.get_json()
        client_ip = request.remote_addr
        
        required_fields = ['device_id', 'challenge_id', 'nonce', 'signature', 'context_proof']
        missing = [f for f in required_fields if f not in data]
        
        if missing:
            return jsonify({
                "success": False,
                "message": f"Missing fields: {', '.join(missing)}"
            }), 400
        
        device_id = data['device_id']
        challenge_id = data['challenge_id']
        nonce = data['nonce']
        signature = data['signature']
        context_proof = data['context_proof']
        
        print(f"\n[CB-CCR] {'='*60}")
        print(f"[CB-CCR] Verifying context-bound proof from: {device_id}")
        print(f"[CB-CCR] Challenge ID: {challenge_id}")
        print(f"[CB-CCR] Context proof keys: {list(context_proof.keys())}")
        
        # Verify context-bound proof WITH PHASE 5
        is_valid, verification_details, message, phase5_report = verify_context_bound_proof(
            device_id, challenge_id, nonce, signature, context_proof
        )
        
        if is_valid:
            log_cb_ccr_event(
                device_id=device_id,
                action="CONTEXT_PROOF_VERIFIED",
                status="SUCCESS",
                challenge_id=challenge_id,
                verification_details=verification_details,
                ip_address=client_ip
            )
            
            log_system_event(
                event_type="CB_CCR_AUTH_SUCCESS",
                component="CB_CCR_AUTH",
                description=f"Device {device_id} authenticated with context proof (Phase 5)",
                severity="INFO",
                additional_data=json.dumps({
                    "trust_score": phase5_report["trust_score"],
                    "verification_steps": {
                        "cryptography": phase5_report["step_5_1_cryptography"]["status"],
                        "context_consistency": phase5_report["step_5_2_context_consistency"]["status"],
                        "temporal_continuity": phase5_report["step_5_3_temporal_continuity"]["status"]
                    }
                })
            )
            
            print(f"[CB-CCR] ✅ CONTEXT-BOUND AUTHENTICATION SUCCESSFUL")
            print(f"[CB-CCR] Verification details: {verification_details}")
            print(f"[CB-CCR] Phase 5 Trust Score: {phase5_report['trust_score']}/100")
            print(f"[CB-CCR] {'='*60}\n")
            
            return jsonify({
                "success": True,
                "device_id": device_id,
                "authenticated": True,
                "message": message,
                "verification_details": verification_details,
                "phase5_report": {
                    "trust_score": phase5_report["trust_score"],
                    "overall_result": phase5_report["overall_result"],
                    "step_5_1_cryptography": phase5_report["step_5_1_cryptography"]["status"],
                    "step_5_2_context_consistency": phase5_report["step_5_2_context_consistency"]["status"],
                    "step_5_3_temporal_continuity": phase5_report["step_5_3_temporal_continuity"]["status"]
                },
                "timestamp": datetime.now().isoformat()
            }), 200
        
        else:
            log_cb_ccr_event(
                device_id=device_id,
                action="CONTEXT_PROOF_FAILED",
                status="FAILED",
                challenge_id=challenge_id,
                verification_details=verification_details,
                error_details=message,
                ip_address=client_ip
            )
            
            # Log specific Phase 5 failure
            if phase5_report:
                log_system_event(
                    event_type="CB_CCR_AUTH_FAILED_PHASE5",
                    component="CB_CCR_AUTH",
                    description=f"Device {device_id} failed Phase 5 verification",
                    severity="WARNING",
                    additional_data=json.dumps({
                        "trust_score": phase5_report["trust_score"],
                        "failure_reason": message,
                        "verification_steps": {
                            "cryptography": phase5_report["step_5_1_cryptography"]["status"],
                            "context_consistency": phase5_report["step_5_2_context_consistency"]["status"],
                            "temporal_continuity": phase5_report["step_5_3_temporal_continuity"]["status"]
                        }
                    })
                )
            
            print(f"[CB-CCR] ❌ VERIFICATION FAILED: {message}")
            print(f"[CB-CCR] Verification details: {verification_details}")
            if phase5_report:
                print(f"[CB-CCR] Phase 5 Trust Score: {phase5_report['trust_score']}/100")
            print(f"[CB-CCR] {'='*60}\n")
            
            response_data = {
                "success": False,
                "device_id": device_id,
                "authenticated": False,
                "message": message,
                "verification_details": verification_details
            }
            
            if phase5_report:
                response_data["phase5_report"] = {
                    "trust_score": phase5_report["trust_score"],
                    "overall_result": phase5_report["overall_result"],
                    "step_5_1_cryptography": phase5_report["step_5_1_cryptography"]["status"],
                    "step_5_2_context_consistency": phase5_report["step_5_2_context_consistency"]["status"],
                    "step_5_3_temporal_continuity": phase5_report["step_5_3_temporal_continuity"]["status"]
                }
            
            return jsonify(response_data), 401
    
    except Exception as e:
        log_cb_ccr_event(
            device_id=data.get('device_id', 'UNKNOWN') if data else 'UNKNOWN',
            action="CONTEXT_VERIFICATION_ERROR",
            status="ERROR",
            error_details=str(e),
            ip_address=request.remote_addr
        )
        
        return jsonify({
            "success": False,
            "message": f"Verification error: {str(e)}"
        }), 500


@app.route('/cb-ccr-logs', methods=['GET'])
def get_cb_ccr_logs():
    """
    Get CB-CCR authentication logs
    """
    try:
        device_id_filter = request.args.get('device_id', None)
        limit = request.args.get('limit', 50, type=int)
        
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cb_ccr_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT NOT NULL,
                action TEXT NOT NULL,
                challenge_id TEXT,
                verification_details TEXT,
                status TEXT NOT NULL,
                error_details TEXT,
                ip_address TEXT,
                timestamp TEXT NOT NULL
            )
        ''')
        
        if device_id_filter:
            cursor.execute('''
                SELECT id, device_id, action, challenge_id, verification_details,
                       status, error_details, ip_address, timestamp
                FROM cb_ccr_log
                WHERE device_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (device_id_filter, limit))
        else:
            cursor.execute('''
                SELECT id, device_id, action, challenge_id, verification_details,
                       status, error_details, ip_address, timestamp
                FROM cb_ccr_log
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (limit,))
        
        results = cursor.fetchall()
        conn.close()
        
        logs = [
            {
                "id": row[0],
                "device_id": row[1],
                "action": row[2],
                "challenge_id": row[3],
                "verification_details": json.loads(row[4]) if row[4] else None,
                "status": row[5],
                "error_details": row[6],
                "ip_address": row[7],
                "timestamp": row[8]
            }
            for row in results
        ]
        
        return jsonify({
            "success": True,
            "count": len(logs),
            "cb_ccr_logs": logs
        }), 200
    
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error retrieving logs: {str(e)}"
        }), 500

@app.route('/request-update', methods=['POST'])
def request_update():
    """
    Endpoint to request firmware update from Update Cloud Server
    NOW INCLUDES: JWT authentication with device fingerprint binding
    
    Expected JSON: {
        "firmware_name": "firmware_v1.0.bin",
        "device_id": "iot_device_001",
        "device_certificate_path": "/path/to/device/cert.pem"  (optional)
    }
    """
    try:
        data = request.get_json()
        
        if not data or 'firmware_name' not in data or 'device_id' not in data:
            return jsonify({"error": "firmware_name and device_id are required"}), 400
        
        firmware_name = data['firmware_name']
        device_id = data['device_id']
        device_cert_path = data.get('device_certificate_path', None)
        
        print(f"[Zero Trust Server] Firmware request for device: {device_id}")
        print(f"[Zero Trust Server] Requesting firmware: {firmware_name}")
        
        # ===== OBTAIN JWT TOKEN FOR DEVICE =====
        print(f"[Zero Trust Server] Obtaining JWT token for device...")
        token, token_id, device_fingerprint, auth_success = obtain_jwt_token_from_cloud(device_id, device_cert_path)
        
        if auth_success:
            log_device_action(
                action_type="FIRMWARE_REQUEST",
                device_id=device_id,
                firmware_name=firmware_name,
                token_id=token_id,
                details=f"Device authenticated successfully. Requesting firmware.",
                status="AUTH_SUCCESS",
                ip_address=request.remote_addr
            )

        if not auth_success:
            log_failed_device_attempt(
                attempt_type="AUTH_FAILED",
                device_id=device_id,
                target_resource="UPDATE_CLOUD_SERVER",
                reason="Could not obtain JWT token from cloud",
                error_details="Authentication service unavailable or credentials invalid"
            )

            return jsonify({
                "status": "error",
                "message": "Device authentication failed - could not obtain JWT token",
                "device_id": device_id
            }), 401
        
        # ===== DOWNLOAD FIRMWARE WITH JWT BEARER TOKEN =====
        headers = {
            'Authorization': f'Bearer {token}',
            'X-Device-Fingerprint': device_fingerprint
        }
        
        print(f"[Zero Trust Server] Downloading firmware with JWT token: {token_id}")
        
        response = requests.get(
            f"{UPDATE_CLOUD_URL}/firmware/download/{firmware_name}",
            headers=headers,
            stream=True,
            timeout=30
        )
        
        if response.status_code == 401:
            log_device_auth_action(
                action="FIRMWARE_DOWNLOAD_AUTH_FAILED",
                token_id=token_id,
                device_id=device_id,
                endpoint=f"/firmware/download/{firmware_name}",
                status="FAILED",
                error_details="JWT authentication failed with cloud server"
            )

            log_failed_device_attempt(
                attempt_type="AUTH_FAILED",
                device_id=device_id,
                target_resource=firmware_name,
                reason="JWT authentication failed with cloud server",
                error_details=response.json().get('error', 'Unknown auth error')
            )

            return jsonify({
                "status": "error",
                "message": "Authentication failed with cloud server",
                "device_id": device_id,
                "error": response.json()
            }), 401
        
        elif response.status_code == 403:
            log_device_auth_action(
                action="FIRMWARE_DOWNLOAD_PERMISSION_DENIED",
                token_id=token_id,
                device_id=device_id,
                endpoint=f"/firmware/download/{firmware_name}",
                status="DENIED",
                error_details="Device lacks permission to download firmware"
            )

            log_failed_device_attempt(
                attempt_type="PERMISSION_DENIED",
                device_id=device_id,
                target_resource=firmware_name,
                reason="Device lacks permission to download firmware",
                error_details=response.json().get('error', 'Unknown permission error')
            )

            return jsonify({
                "status": "error",
                "message": "Permission denied - device cannot download firmware",
                "device_id": device_id,
                "error": response.json()
            }), 403
        
        elif response.status_code != 200:
            error_msg = response.json().get('error', 'Unknown error')
            log_device_auth_action(
                action="FIRMWARE_DOWNLOAD_FAILED",
                token_id=token_id,
                device_id=device_id,
                endpoint=f"/firmware/download/{firmware_name}",
                status="FAILED",
                error_details=error_msg
            )
            return jsonify({
                "status": "error",
                "message": "Failed to download firmware from cloud",
                "device_id": device_id,
                "error": error_msg
            }), response.status_code
        
        # ===== HASH VERIFICATION =====
        received_hash = response.headers.get('X-File-Hash')
        
        if not received_hash:
            log_device_auth_action(
                action="HASH_VERIFICATION_FAILED",
                token_id=token_id,
                device_id=device_id,
                endpoint=f"/firmware/download/{firmware_name}",
                status="FAILED",
                error_details="No hash provided by server"
            )
            return jsonify({
                "status": "error",
                "message": "Server did not provide file hash",
                "device_id": device_id
            }), 400
        
        print(f"[Hashing] Received hash from cloud: {received_hash}")
        
        # Download and decrypt
        encrypted_data = b""
        for chunk in response.iter_content(chunk_size=8192):
            encrypted_data += chunk
        
        log_device_action(
            action_type="FIRMWARE_DOWNLOAD",
            device_id=device_id,
            firmware_name=firmware_name,
            token_id=token_id,
            details=f"Firmware downloaded from cloud. Size: {len(encrypted_data)} bytes",
            status="SUCCESS"
        )
        
        # Decrypt firmware
        encryption_key = None  # Load from your encryption system
        try:
            decrypted_data = decrypt_data(encrypted_data, encryption_key)
            
            file_path = os.path.join(DOWNLOAD_DIR, firmware_name)
            with open(file_path, 'wb') as f:
                f.write(decrypted_data)
            
            print(f"[Zero Trust Server] Firmware decrypted and saved: {firmware_name}")

            log_device_action(
                action_type="DECRYPTION",
                device_id=device_id,
                firmware_name=firmware_name,
                token_id=token_id,
                details=f"Firmware decrypted successfully. Saved to: {file_path}",
                status="SUCCESS"
            )
            
            # Calculate hash
            calculated_hash = calculate_file_hash(file_path)
            print(f"[Hashing] Calculated hash: {calculated_hash}")
            
            # Verify hash
            if received_hash == calculated_hash:
                print("[Verification] ✅ Hash verification PASSED")
                
                log_verification_event(
                    firmware_name=firmware_name,
                    device_id=device_id,
                    verification_type="HASH_CHECK",
                    expected_value=received_hash,
                    actual_value=calculated_hash,
                    match_result=True,
                    action_taken="ACCEPTED"
                )

                log_device_auth_action(
                    action="FIRMWARE_DOWNLOAD_SUCCESS",
                    token_id=token_id,
                    device_id=device_id,
                    endpoint=f"/firmware/download/{firmware_name}",
                    status="SUCCESS",
                    error_details=None
                )
                
                store_verification_result(firmware_name, received_hash, calculated_hash, True, "Hash verification passed")
                
                return jsonify({
                    "status": "success",
                    "message": "Firmware downloaded, verified, and ready for deployment",
                    "firmware_name": firmware_name,
                    "device_id": device_id,
                    "token_id": token_id,
                    "saved_to": file_path,
                    "received_hash": received_hash,
                    "calculated_hash": calculated_hash,
                    "verification": "PASSED ✅"
                }), 200
            
            else:
                print("[Verification] ❌ Hash verification FAILED")
                
                log_verification_event(
                    firmware_name=firmware_name,
                    device_id=device_id,
                    verification_type="HASH_CHECK",
                    expected_value=received_hash,
                    actual_value=calculated_hash,
                    match_result=False,
                    action_taken="REJECTED"
                )

                log_failed_device_attempt(
                    attempt_type="HASH_MISMATCH",
                    device_id=device_id,
                    target_resource=firmware_name,
                    reason="Downloaded firmware hash does not match expected value",
                    error_details=f"Expected: {received_hash}, Got: {calculated_hash}"
                )

                log_device_auth_action(
                    action="HASH_MISMATCH",
                    token_id=token_id,
                    device_id=device_id,
                    endpoint=f"/firmware/download/{firmware_name}",
                    status="FAILED",
                    error_details="Hash mismatch - possible tampering detected"
                )
                
                if os.path.exists(file_path):
                    os.remove(file_path)
                
                store_verification_result(firmware_name, received_hash, calculated_hash, False, "Hash mismatch")
                
                return jsonify({
                    "status": "error",
                    "message": "Hash verification FAILED - firmware may be tampered",
                    "device_id": device_id,
                    "received_hash": received_hash,
                    "calculated_hash": calculated_hash,
                    "verification": "FAILED ❌"
                }), 400
        
        except Exception as decrypt_error:
            log_failed_device_attempt(
                attempt_type="DECRYPTION_FAILED",
                device_id=device_id,
                target_resource=firmware_name,
                reason="Failed to decrypt firmware",
                error_details=str(decrypt_error)
            )

            log_device_auth_action(
                action="DECRYPTION_FAILED",
                token_id=token_id,
                device_id=device_id,
                endpoint=f"/firmware/download/{firmware_name}",
                status="FAILED",
                error_details=str(decrypt_error)
            )
            return jsonify({
                "status": "error",
                "message": "Failed to decrypt firmware",
                "device_id": device_id,
                "error": str(decrypt_error)
            }), 500
    
    except requests.exceptions.ConnectionError:
        return jsonify({
            "error": "Cannot connect to Update Cloud Server. Is it running?"
        }), 503
    except Exception as e:
        log_device_auth_action(
            action="REQUEST_UPDATE_ERROR",
            token_id="UNKNOWN",
            device_id=data.get('device_id', 'UNKNOWN'),
            endpoint="/request-update",
            status="ERROR",
            error_details=str(e)
        )
        return jsonify({"error": str(e)}), 500


@app.route('/list-available-firmware', methods=['GET'])
def list_available_firmware():
    """
    Get list of available firmware
    Optional: Add JWT protection in production
    """
    try:
        # In production, send JWT token with this request too
        headers = {}
        if CURRENT_JWT_TOKEN:
            headers['Authorization'] = f'Bearer {CURRENT_JWT_TOKEN}'
            headers['X-Device-Fingerprint'] = CURRENT_DEVICE_FINGERPRINT
        
        response = requests.get(
            f"{UPDATE_CLOUD_URL}/firmware/list",
            headers=headers,
            timeout=10
        )
        
        if response.status_code == 200:
            return jsonify(response.json()), 200
        else:
            return jsonify({"error": "Failed to fetch firmware list"}), response.status_code
    
    except requests.exceptions.ConnectionError:
        return jsonify({
            "error": "Cannot connect to Update Cloud Server"
        }), 503
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/downloaded-firmware', methods=['GET'])
def list_downloaded():
    """List downloaded firmware files"""
    try:
        files = os.listdir(DOWNLOAD_DIR)
        return jsonify({"downloaded_firmware": files}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/verification-history', methods=['GET'])
def verification_history():
    """Get firmware verification history"""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM firmware_verification ORDER BY timestamp DESC LIMIT 10')
        results = cursor.fetchall()
        conn.close()
        
        history = [
            {
                "id": row[0],
                "firmware_name": row[1],
                "received_hash": row[2],
                "calculated_hash": row[3],
                "hash_match": bool(row[4]),
                "timestamp": row[5],
                "status": row[6]
            }
            for row in results
        ]
        
        return jsonify({"verification_history": history}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
@app.route('/enroll', methods=['POST'])
def enroll_device_phase1():
    """
    Phase 1: Device enrollment endpoint
    Receives device cryptographic identity (ECC public key)
    
    Expected JSON:
    {
        "device_id": "iot-device-001",
        "public_key": "-----BEGIN PUBLIC KEY-----...",
        "device_type": "IoT_Simulator",
        "firmware_version": "1.0.0"
    }
    
    Returns:
        JSON response with enrollment status
    """
    try:
        data = request.get_json()
        client_ip = request.remote_addr
        
        # Validate required fields
        if not data:
            return jsonify({
                "success": False,
                "message": "No data provided"
            }), 400
        
        required_fields = ['device_id', 'public_key']
        missing_fields = [field for field in required_fields if field not in data]
        
        if missing_fields:
            error_msg = f"Missing required fields: {', '.join(missing_fields)}"
            log_device_enrollment(
                device_id=data.get('device_id', 'UNKNOWN'),
                action="ENROLLMENT_VALIDATION_FAILED",
                status="FAILED",
                error_details=error_msg,
                ip_address=client_ip
            )
            return jsonify({
                "success": False,
                "message": error_msg
            }), 400
        
        device_id = data['device_id']
        public_key_pem = data['public_key']
        device_type = data.get('device_type', 'Unknown')
        firmware_version = data.get('firmware_version', '0.0.0')
        
        print(f"\n[Phase 1 Enrollment] ========================================")
        print(f"[Phase 1 Enrollment] Device ID: {device_id}")
        print(f"[Phase 1 Enrollment] Client IP: {client_ip}")
        print(f"[Phase 1 Enrollment] Device Type: {device_type}")
        print(f"[Phase 1 Enrollment] Firmware: {firmware_version}")
        
        # Validate public key
        is_valid, error_msg = validate_ecc_public_key(public_key_pem)
        
        if not is_valid:
            print(f"[Phase 1 Enrollment] ✗ Public key validation FAILED: {error_msg}")
            log_device_enrollment(
                device_id=device_id,
                action="KEY_VALIDATION_FAILED",
                status="FAILED",
                error_details=error_msg,
                ip_address=client_ip
            )
            return jsonify({
                "success": False,
                "message": f"Invalid public key: {error_msg}"
            }), 400
        
        print(f"[Phase 1 Enrollment] ✓ Public key validation PASSED")
        
        # Store device identity
        success, message, fingerprint, action = store_device_identity(
            device_id, public_key_pem, device_type, firmware_version
        )
        
        if success:
            print(f"[Phase 1 Enrollment] ✓ {action} SUCCESSFUL")
            print(f"[Phase 1 Enrollment] Fingerprint: {fingerprint[:16]}...")
            
            # Log successful enrollment
            log_device_enrollment(
                device_id=device_id,
                action=action,
                status="SUCCESS",
                public_key_fingerprint=fingerprint,
                ip_address=client_ip
            )
            
            # Also log to system event log
            log_system_event(
                event_type="DEVICE_ENROLLED",
                component="ENROLLMENT_SERVICE",
                description=f"Device {device_id} enrolled successfully",
                severity="INFO",
                additional_data=f"Fingerprint: {fingerprint[:16]}..."
            )
            
            return jsonify({
                "success": True,
                "message": message,
                "device_id": device_id,
                "status": "active",
                "public_key_fingerprint": fingerprint,
                "timestamp": datetime.now().isoformat(),
                "action": action
            }), 200
        
        else:
            print(f"[Phase 1 Enrollment] ✗ Storage FAILED: {message}")
            log_device_enrollment(
                device_id=device_id,
                action="ENROLLMENT_STORAGE_FAILED",
                status="FAILED",
                error_details=message,
                ip_address=client_ip
            )
            return jsonify({
                "success": False,
                "message": message
            }), 500
    
    except Exception as e:
        error_msg = str(e)
        print(f"[Phase 1 Enrollment] ✗ EXCEPTION: {error_msg}")
        
        log_device_enrollment(
            device_id=data.get('device_id', 'UNKNOWN') if data else 'UNKNOWN',
            action="ENROLLMENT_ERROR",
            status="ERROR",
            error_details=error_msg,
            ip_address=request.remote_addr
        )
        
        return jsonify({
            "success": False,
            "message": f"Enrollment error: {error_msg}"
        }), 500
@app.route('/enroll-phase2', methods=['POST'])
def enroll_device_phase2():
    """
    Phase 2: Enhanced device enrollment endpoint
    Receives device cryptographic identity + hardware fingerprint
    
    Expected JSON:
    {
        "device_id": "iot-device-001",
        "public_key": "-----BEGIN PUBLIC KEY-----...",
        "hardware_fingerprint": "a1b2c3d4...",
        "device_type": "IoT_Simulator",
        "firmware_version": "1.0.0",
        "hardware_info": {...}  // Optional
    }
    
    Returns:
        JSON response with enrollment status and hardware binding confirmation
    """
    try:
        data = request.get_json()
        client_ip = request.remote_addr
        
        # Validate required fields
        if not data:
            return jsonify({
                "success": False,
                "message": "No data provided"
            }), 400
        
        required_fields = ['device_id', 'public_key', 'hardware_fingerprint']
        missing_fields = [field for field in required_fields if field not in data]
        
        if missing_fields:
            error_msg = f"Missing required fields: {', '.join(missing_fields)}"
            log_device_enrollment(
                device_id=data.get('device_id', 'UNKNOWN'),
                action="PHASE2_VALIDATION_FAILED",
                status="FAILED",
                error_details=error_msg,
                ip_address=client_ip
            )
            return jsonify({
                "success": False,
                "message": error_msg
            }), 400
        
        device_id = data['device_id']
        public_key_pem = data['public_key']
        hardware_fingerprint = data['hardware_fingerprint']
        device_type = data.get('device_type', 'Unknown')
        firmware_version = data.get('firmware_version', '0.0.0')
        hardware_info = data.get('hardware_info', None)
        
        print(f"\n[Phase 2 Enrollment] ========================================")
        print(f"[Phase 2 Enrollment] Device ID: {device_id}")
        print(f"[Phase 2 Enrollment] Client IP: {client_ip}")
        print(f"[Phase 2 Enrollment] Device Type: {device_type}")
        print(f"[Phase 2 Enrollment] Firmware: {firmware_version}")
        print(f"[Phase 2 Enrollment] Hardware FP: {hardware_fingerprint[:32]}...")
        
        # Validate public key
        is_valid, error_msg = validate_ecc_public_key(public_key_pem)
        
        if not is_valid:
            print(f"[Phase 2 Enrollment] ✗ Public key validation FAILED: {error_msg}")
            log_device_enrollment(
                device_id=device_id,
                action="PHASE2_KEY_VALIDATION_FAILED",
                status="FAILED",
                error_details=error_msg,
                ip_address=client_ip
            )
            return jsonify({
                "success": False,
                "message": f"Invalid public key: {error_msg}"
            }), 400
        
        print(f"[Phase 2 Enrollment] ✓ Public key validation PASSED")
        
        # Store device identity (same as Phase 1)
        success, message, pub_key_fp, action = store_device_identity(
            device_id, public_key_pem, device_type, firmware_version
        )
        
        if not success:
            print(f"[Phase 2 Enrollment] ✗ Identity storage FAILED: {message}")
            log_device_enrollment(
                device_id=device_id,
                action="PHASE2_IDENTITY_STORAGE_FAILED",
                status="FAILED",
                error_details=message,
                ip_address=client_ip
            )
            return jsonify({
                "success": False,
                "message": message
            }), 500
        
        print(f"[Phase 2 Enrollment] ✓ Identity storage SUCCESSFUL")
        
        # Store hardware binding
        hw_success, hw_message, hw_action = store_hardware_binding(
            device_id, hardware_fingerprint, pub_key_fp, hardware_info
        )
        
        if not hw_success:
            print(f"[Phase 2 Enrollment] ✗ Hardware binding FAILED: {hw_message}")
            log_device_enrollment(
                device_id=device_id,
                action="PHASE2_HW_BINDING_FAILED",
                status="FAILED",
                error_details=hw_message,
                ip_address=client_ip
            )
            
            # Quarantine device if hardware mismatch detected
            if hw_action == "HW_MISMATCH":
                conn = sqlite3.connect(DB_FILE)
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE device_identity
                    SET status = 'quarantine'
                    WHERE device_id = ?
                ''', (device_id,))
                conn.commit()
                conn.close()
            
            return jsonify({
                "success": False,
                "message": hw_message,
                "hardware_binding_status": "FAILED",
                "action": hw_action
            }), 400
        
        # Store network binding
        network_fingerprint = data.get('network_fingerprint')
        network_info = data.get('network_info', None)

        if network_fingerprint:
            net_success, net_message, net_action = store_network_binding(
                device_id, network_fingerprint, pub_key_fp, network_info
            )
            
            if not net_success:
                print(f"[Phase 2 Enrollment] ⚠️ Network binding warning: {net_message}")
                # Continue enrollment even if network binding fails (it's supplementary)
        else:
            print(f"[Phase 2 Enrollment] ⚠️ No network fingerprint provided")
            net_action = "NO_NET_BINDING"


        print(f"[Phase 2 Enrollment] ✓ Hardware binding SUCCESSFUL - {hw_action}")
        
        # Log successful Phase 2 enrollment
        log_device_enrollment(
            device_id=device_id,
            action=f"PHASE2_{action}",
            status="SUCCESS",
            public_key_fingerprint=pub_key_fp,
            ip_address=client_ip
        )
        
        # Log to system event
        log_system_event(
            event_type="PHASE2_DEVICE_ENROLLED",
            component="ENROLLMENT_SERVICE",
            description=f"Device {device_id} enrolled with hardware binding",
            severity="INFO",
            additional_data=f"HW FP: {hardware_fingerprint[:16]}..., PK FP: {pub_key_fp[:16]}..."
        )
        
        print(f"[Phase 2 Enrollment] ========================================\n")
        
        return jsonify({
            "success": True,
            "message": f"Phase 2 enrollment successful: {message}",
            "device_id": device_id,
            "status": "active",
            "public_key_fingerprint": pub_key_fp,
            "hardware_fingerprint": hardware_fingerprint,
            "network_fingerprint": network_fingerprint if network_fingerprint else "Not provided",
            "hardware_binding_status": hw_action,
            "network_binding_status": net_action if network_fingerprint else "SKIPPED",
            "timestamp": datetime.now().isoformat(),
            "action": f"PHASE2_{action}",
            "phase": 2
        }), 200
    
    except Exception as e:
        error_msg = str(e)
        print(f"[Phase 2 Enrollment] ✗ EXCEPTION: {error_msg}")
        
        log_device_enrollment(
            device_id=data.get('device_id', 'UNKNOWN') if data else 'UNKNOWN',
            action="PHASE2_ENROLLMENT_ERROR",
            status="ERROR",
            error_details=error_msg,
            ip_address=request.remote_addr
        )
        
        return jsonify({
            "success": False,
            "message": f"Phase 2 enrollment error: {error_msg}"
        }), 500

@app.route('/device/<device_id>', methods=['GET'])
def get_device_identity(device_id):
    """
    Query device identity and enrollment status
    
    Args:
        device_id: Device identifier (URL parameter)
    
    Returns:
        JSON with device identity information
    """
    try:
        device_info = check_device_enrollment_status(device_id)
        
        if device_info:
            return jsonify({
                "success": True,
                "device": device_info
            }), 200
        else:
            return jsonify({
                "success": False,
                "message": f"Device {device_id} not found or not enrolled"
            }), 404
    
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error retrieving device: {str(e)}"
        }), 500


@app.route('/devices', methods=['GET'])
def list_enrolled_devices():
    """
    List all enrolled devices with their identity information
    
    Query parameters:
        - status: Filter by status (active, quarantine, revoked)
        - limit: Maximum number of results (default: 50)
    
    Returns:
        JSON list of enrolled devices
    """
    try:
        status_filter = request.args.get('status', None)
        limit = request.args.get('limit', 50, type=int)
        
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        if status_filter:
            cursor.execute('''
                SELECT device_id, status, enrollment_timestamp, firmware_version,
                       device_type, public_key_fingerprint, enrollment_count
                FROM device_identity
                WHERE status = ?
                ORDER BY enrollment_timestamp DESC
                LIMIT ?
            ''', (status_filter, limit))
        else:
            cursor.execute('''
                SELECT device_id, status, enrollment_timestamp, firmware_version,
                       device_type, public_key_fingerprint, enrollment_count
                FROM device_identity
                ORDER BY enrollment_timestamp DESC
                LIMIT ?
            ''', (limit,))
        
        results = cursor.fetchall()
        conn.close()
        
        devices = [
            {
                "device_id": row[0],
                "status": row[1],
                "enrollment_timestamp": row[2],
                "firmware_version": row[3],
                "device_type": row[4],
                "public_key_fingerprint": row[5],
                "enrollment_count": row[6]
            }
            for row in results
        ]
        
        return jsonify({
            "success": True,
            "count": len(devices),
            "devices": devices
        }), 200
    
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error listing devices: {str(e)}"
        }), 500


@app.route('/device/<device_id>/status', methods=['PUT'])
def update_device_status(device_id):
    """
    Update device status (active / quarantine / revoked)
    
    Expected JSON:
    {
        "status": "quarantine",
        "reason": "Suspicious activity detected"
    }
    """
    try:
        data = request.get_json()
        
        if not data or 'status' not in data:
            return jsonify({
                "success": False,
                "message": "Status field required"
            }), 400
        
        new_status = data['status']
        reason = data.get('reason', 'Manual status update')
        
        valid_statuses = ['active', 'quarantine', 'revoked']
        if new_status not in valid_statuses:
            return jsonify({
                "success": False,
                "message": f"Invalid status. Must be one of: {', '.join(valid_statuses)}"
            }), 400
        
        # Check if device exists
        device_info = check_device_enrollment_status(device_id)
        if not device_info:
            return jsonify({
                "success": False,
                "message": f"Device {device_id} not found"
            }), 404
        
        # Update status
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE device_identity
            SET status = ?, updated_at = ?
            WHERE device_id = ?
        ''', (new_status, datetime.now().isoformat(), device_id))
        
        conn.commit()
        conn.close()
        
        # Log status change
        log_device_enrollment(
            device_id=device_id,
            action=f"STATUS_CHANGED_TO_{new_status.upper()}",
            status="SUCCESS",
            public_key_fingerprint=device_info['public_key_fingerprint'],
            error_details=reason,
            ip_address=request.remote_addr
        )
        
        print(f"[Device Status] {device_id} status changed to: {new_status}")
        
        return jsonify({
            "success": True,
            "message": f"Device status updated to {new_status}",
            "device_id": device_id,
            "new_status": new_status,
            "reason": reason
        }), 200
    
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error updating status: {str(e)}"
        }), 500


@app.route('/enrollment-logs', methods=['GET'])
def get_enrollment_logs():
    """
    Get device enrollment audit logs
    
    Query parameters:
        - device_id: Filter by device (optional)
        - limit: Maximum results (default: 50)
    
    Returns:
        JSON list of enrollment events
    """
    try:
        device_id_filter = request.args.get('device_id', None)
        limit = request.args.get('limit', 50, type=int)
        
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        if device_id_filter:
            cursor.execute('''
                SELECT id, device_id, action, public_key_fingerprint, status,
                       error_details, ip_address, timestamp
                FROM device_enrollment_log
                WHERE device_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (device_id_filter, limit))
        else:
            cursor.execute('''
                SELECT id, device_id, action, public_key_fingerprint, status,
                       error_details, ip_address, timestamp
                FROM device_enrollment_log
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (limit,))
        
        results = cursor.fetchall()
        conn.close()
        
        logs = [
            {
                "id": row[0],
                "device_id": row[1],
                "action": row[2],
                "public_key_fingerprint": row[3],
                "status": row[4],
                "error_details": row[5],
                "ip_address": row[6],
                "timestamp": row[7]
            }
            for row in results
        ]
        
        return jsonify({
            "success": True,
            "count": len(logs),
            "enrollment_logs": logs
        }), 200
    
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error retrieving logs: {str(e)}"
        }), 500
@app.route('/device/<device_id>/hardware-binding', methods=['GET'])
def get_hardware_binding(device_id):
    """
    Query hardware binding information for a device
    
    Returns:
        JSON with hardware binding details
    """
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT hardware_fingerprint, public_key_fingerprint, 
                   binding_timestamp, last_verified, verification_count,
                   hardware_info, binding_status
            FROM device_hardware_binding
            WHERE device_id = ?
        ''', (device_id,))
        
        result = cursor.fetchone()
        conn.close()
        
        if result:
            return jsonify({
                "success": True,
                "device_id": device_id,
                "hardware_fingerprint": result[0],
                "public_key_fingerprint": result[1],
                "binding_timestamp": result[2],
                "last_verified": result[3],
                "verification_count": result[4],
                "hardware_info": json.loads(result[5]) if result[5] else None,
                "binding_status": result[6]
            }), 200
        else:
            return jsonify({
                "success": False,
                "message": f"No hardware binding found for device {device_id}"
            }), 404
    
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error retrieving hardware binding: {str(e)}"
        }), 500


@app.route('/hardware-verification-logs', methods=['GET'])
def get_hardware_verification_logs():
    """
    Get hardware fingerprint verification audit logs
    
    Query parameters:
        - device_id: Filter by device (optional)
        - limit: Maximum results (default: 50)
    
    Returns:
        JSON list of verification events
    """
    try:
        device_id_filter = request.args.get('device_id', None)
        limit = request.args.get('limit', 50, type=int)
        
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        if device_id_filter:
            cursor.execute('''
                SELECT id, device_id, hardware_fingerprint, verification_type,
                       match_result, action_taken, ip_address, timestamp
                FROM hardware_verification_log
                WHERE device_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (device_id_filter, limit))
        else:
            cursor.execute('''
                SELECT id, device_id, hardware_fingerprint, verification_type,
                       match_result, action_taken, ip_address, timestamp
                FROM hardware_verification_log
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (limit,))
        
        results = cursor.fetchall()
        conn.close()
        
        logs = [
            {
                "id": row[0],
                "device_id": row[1],
                "hardware_fingerprint": row[2],
                "verification_type": row[3],
                "match_result": bool(row[4]),
                "action_taken": row[5],
                "ip_address": row[6],
                "timestamp": row[7]
            }
            for row in results
        ]
        
        return jsonify({
            "success": True,
            "count": len(logs),
            "hardware_verification_logs": logs
        }), 200
    
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error retrieving logs: {str(e)}"
        }), 500

@app.route('/phase5-logs', methods=['GET'])
def get_phase5_verification_logs():
    """
    Get Phase 5 verification logs with trust scores and detailed results
    
    Query parameters:
        - device_id: Filter by device (optional)
        - result: Filter by result (TRUSTED/UNTRUSTED) (optional)
        - min_trust_score: Minimum trust score (optional)
        - limit: Maximum results (default: 50)
    """
    try:
        device_id_filter = request.args.get('device_id', None)
        result_filter = request.args.get('result', None)
        min_trust_score = request.args.get('min_trust_score', type=int)
        limit = request.args.get('limit', 50, type=int)
        
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # Build query dynamically
        query = '''
            SELECT id, device_id, overall_result, trust_score,
                   step_5_1_status, step_5_2_status, step_5_3_status,
                   verification_report, ip_address, timestamp
            FROM phase5_verification_log
            WHERE 1=1
        '''
        params = []
        
        if device_id_filter:
            query += ' AND device_id = ?'
            params.append(device_id_filter)
        
        if result_filter:
            query += ' AND overall_result = ?'
            params.append(result_filter)
        
        if min_trust_score is not None:
            query += ' AND trust_score >= ?'
            params.append(min_trust_score)
        
        query += ' ORDER BY timestamp DESC LIMIT ?'
        params.append(limit)
        
        cursor.execute(query, params)
        results = cursor.fetchall()
        conn.close()
        
        logs = []
        for row in results:
            log_entry = {
                "id": row[0],
                "device_id": row[1],
                "overall_result": row[2],
                "trust_score": row[3],
                "step_5_1_cryptography": row[4],
                "step_5_2_context_consistency": row[5],
                "step_5_3_temporal_continuity": row[6],
                "ip_address": row[8],
                "timestamp": row[9]
            }
            
            # Parse detailed verification report
            try:
                verification_report = json.loads(row[7])
                log_entry["detailed_report"] = verification_report
            except:
                log_entry["detailed_report"] = None
            
            logs.append(log_entry)
        
        # Calculate statistics
        if logs:
            trust_scores = [log["trust_score"] for log in logs]
            stats = {
                "total_verifications": len(logs),
                "trusted": len([log for log in logs if log["overall_result"] == "TRUSTED"]),
                "untrusted": len([log for log in logs if log["overall_result"] == "UNTRUSTED"]),
                "avg_trust_score": round(sum(trust_scores) / len(trust_scores), 2),
                "min_trust_score": min(trust_scores),
                "max_trust_score": max(trust_scores)
            }
        else:
            stats = {
                "total_verifications": 0,
                "trusted": 0,
                "untrusted": 0,
                "avg_trust_score": 0,
                "min_trust_score": 0,
                "max_trust_score": 0
            }
        
        return jsonify({
            "success": True,
            "count": len(logs),
            "statistics": stats,
            "phase5_verification_logs": logs
        }), 200
    
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error retrieving Phase 5 logs: {str(e)}"
        }), 500
from flask import Flask, jsonify, request, render_template_string
import sqlite3
import os

# Add this route to your existing zero_trust_server.py

@app.route('/view', methods=['GET'])
def view_dashboard():
    """
    Main dashboard view for Zero Trust Server
    Shows real-time data - displays zeros when no devices are connected
    """
    html_template = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Zero Trust Server Dashboard</title>
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: #1e1e1e;
                color: #d4d4d4;
                padding: 20px;
            }
            
            .container {
                max-width: 1600px;
                margin: 0 auto;
            }
            
            header {
                background: #252526;
                padding: 20px;
                border-radius: 6px;
                margin-bottom: 20px;
                border-left: 4px solid #007acc;
            }
            
            h1 {
                color: #4ec9b0;
                font-size: 24px;
                margin-bottom: 5px;
            }
            
            .subtitle {
                color: #858585;
                font-size: 14px;
            }
            
            .stats-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
                gap: 15px;
                margin-bottom: 20px;
            }
            
            .stat-card {
                background: #252526;
                padding: 15px;
                border-radius: 6px;
                border-left: 3px solid #4ec9b0;
            }
            
            .stat-card.warning {
                border-left-color: #ce9178;
            }
            
            .stat-card.danger {
                border-left-color: #f48771;
            }
            
            .stat-label {
                color: #858585;
                font-size: 12px;
                text-transform: uppercase;
                margin-bottom: 5px;
            }
            
            .stat-value {
                color: #4ec9b0;
                font-size: 28px;
                font-weight: bold;
            }
            
            .stat-value.zero {
                color: #858585;
            }
            
            .stat-value.warning {
                color: #ce9178;
            }
            
            .stat-value.danger {
                color: #f48771;
            }
            
            .section {
                background: #252526;
                padding: 20px;
                border-radius: 6px;
                margin-bottom: 20px;
            }
            
            .section-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 15px;
                padding-bottom: 10px;
                border-bottom: 1px solid #3e3e42;
            }
            
            h2 {
                color: #dcdcaa;
                font-size: 18px;
            }
            
            .refresh-btn {
                background: #007acc;
                color: white;
                border: none;
                padding: 8px 15px;
                border-radius: 4px;
                cursor: pointer;
                font-size: 12px;
            }
            
            .refresh-btn:hover {
                background: #005a9e;
            }
            
            table {
                width: 100%;
                border-collapse: collapse;
                font-size: 13px;
            }
            
            thead {
                background: #1e1e1e;
            }
            
            th {
                padding: 10px;
                text-align: left;
                color: #4ec9b0;
                font-weight: 600;
                border-bottom: 2px solid #3e3e42;
            }
            
            td {
                padding: 10px;
                border-bottom: 1px solid #3e3e42;
            }
            
            tr:hover {
                background: #2a2d2e;
            }
            
            .status-success {
                color: #4ec9b0;
                font-weight: bold;
            }
            
            .status-failed {
                color: #f48771;
                font-weight: bold;
            }
            
            .status-error {
                color: #ce9178;
                font-weight: bold;
            }
            
            .fingerprint {
                font-family: 'Courier New', monospace;
                color: #9cdcfe;
                font-size: 11px;
            }
            
            .full-fingerprint {
                max-width: 350px;
                word-break: break-all;
            }
            
            .timestamp {
                color: #858585;
                font-size: 12px;
            }
            
            .empty-state {
                text-align: center;
                padding: 40px;
                color: #858585;
            }
            
            .empty-icon {
                font-size: 48px;
                margin-bottom: 10px;
            }
            
            .badge {
                display: inline-block;
                padding: 4px 10px;
                border-radius: 3px;
                font-size: 11px;
                font-weight: bold;
            }
            
            .badge-active {
                background: #4ec9b022;
                color: #4ec9b0;
                border: 1px solid #4ec9b0;
            }
            
            .badge-quarantine {
                background: #ce917822;
                color: #ce9178;
                border: 1px solid #ce9178;
            }
            
            .badge-revoked {
                background: #f4877122;
                color: #f48771;
                border: 1px solid #f48771;
            }
            
            .badge-pending {
                background: #007acc22;
                color: #007acc;
                border: 1px solid #007acc;
            }
            
            .server-status {
                display: flex;
                align-items: center;
                gap: 10px;
                padding: 10px 15px;
                background: #1e1e1e;
                border-radius: 4px;
                margin-bottom: 20px;
            }
            
            .status-indicator {
                width: 12px;
                height: 12px;
                border-radius: 50%;
                animation: pulse 2s infinite;
            }
            
            .status-indicator.online {
                background: #4ec9b0;
                box-shadow: 0 0 8px #4ec9b0;
            }
            
            .status-indicator.idle {
                background: #858585;
            }
            
            @keyframes pulse {
                0%, 100% { opacity: 1; }
                50% { opacity: 0.5; }
            }
        </style>
    </head>
    <body>
        <div class="container">
            <header>
                <h1>🔒 Zero Trust Server Dashboard</h1>
                <p class="subtitle">Real-time monitoring of device authentication and firmware verification</p>
            </header>
            
            <!-- Server Status -->
            <div class="server-status">
                <div class="status-indicator {{ 'online' if stats.total_devices > 0 else 'idle' }}"></div>
                <span>
                    {% if stats.total_devices > 0 %}
                        Server Active - {{ stats.total_devices }} device(s) connected
                    {% else %}
                        Server Running - Waiting for device connections
                    {% endif %}
                </span>
            </div>
            
            <!-- Statistics Cards -->
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-label">Total Devices</div>
                    <div class="stat-value {{ 'zero' if stats.total_devices == 0 else '' }}">
                        {{ stats.total_devices }}
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Active Devices</div>
                    <div class="stat-value {{ 'zero' if stats.active_devices == 0 else '' }}">
                        {{ stats.active_devices }}
                    </div>
                </div>
                <div class="stat-card warning">
                    <div class="stat-label">Quarantined</div>
                    <div class="stat-value {{ 'warning' if stats.quarantined_devices > 0 else 'zero' }}">
                        {{ stats.quarantined_devices }}
                    </div>
                </div>
                <div class="stat-card danger">
                    <div class="stat-label">Revoked</div>
                    <div class="stat-value {{ 'danger' if stats.revoked_devices > 0 else 'zero' }}">
                        {{ stats.revoked_devices }}
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Verifications (24h)</div>
                    <div class="stat-value {{ 'zero' if stats.verifications_24h == 0 else '' }}">
                        {{ stats.verifications_24h }}
                    </div>
                </div>
                <div class="stat-card danger">
                    <div class="stat-label">Failed Attempts (24h)</div>
                    <div class="stat-value {{ 'danger' if stats.failed_attempts > 0 else 'zero' }}">
                        {{ stats.failed_attempts }}
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Hardware Bindings</div>
                    <div class="stat-value {{ 'zero' if stats.hardware_bindings == 0 else '' }}">
                        {{ stats.hardware_bindings }}
                    </div>
                </div>
            </div>
            
            <!-- Device Identity Table -->
            <div class="section">
                <div class="section-header">
                    <h2>📱 Device Identity & Status</h2>
                    <button class="refresh-btn" onclick="location.reload()">Refresh</button>
                </div>
                {% if device_identity %}
                <table>
                    <thead>
                        <tr>
                            <th>Device ID</th>
                            <th>Status</th>
                            <th>Public Key Fingerprint</th>
                            <th>Hardware Fingerprint</th>
                            <th>Firmware</th>
                            <th>Device Type</th>
                            <th>Enrollments</th>
                            <th>Last Seen</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for device in device_identity %}
                        <tr>
                            <td><strong>{{ device.device_id }}</strong></td>
                            <td>
                                <span class="badge badge-{{ device.status }}">{{ device.status|upper }}</span>
                            </td>
                            <td class="fingerprint full-fingerprint" title="{{ device.public_key_fingerprint }}">
                                {{ device.public_key_fingerprint }}
                            </td>
                            <td class="fingerprint full-fingerprint" title="{{ device.hardware_fingerprint }}">
                                {{ device.hardware_fingerprint if device.hardware_fingerprint else 'Not bound' }}
                            </td>
                            <td>{{ device.firmware_version }}</td>
                            <td>{{ device.device_type }}</td>
                            <td>{{ device.enrollment_count }}</td>
                            <td class="timestamp">{{ device.last_seen if device.last_seen else 'Never' }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
                {% else %}
                <div class="empty-state">
                    <div class="empty-icon">📭</div>
                    <p>No devices enrolled yet</p>
                    <small>Devices will appear here once they connect to the server</small>
                </div>
                {% endif %}
            </div>
            
            <!-- Phase 5 Verification Logs -->
            <div class="section">
                <div class="section-header">
                    <h2>🔍 Phase 5 Verification Logs (Recent)</h2>
                </div>
                {% if phase5_logs %}
                <table>
                    <thead>
                        <tr>
                            <th>Device ID</th>
                            <th>Result</th>
                            <th>Trust Score</th>
                            <th>Cryptography</th>
                            <th>Context Consistency</th>
                            <th>Temporal Continuity</th>
                            <th>IP Address</th>
                            <th>Timestamp</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for log in phase5_logs %}
                        <tr>
                            <td>{{ log.device_id }}</td>
                            <td class="status-{{ 'success' if log.overall_result == 'TRUSTED' else 'failed' }}">
                                {{ log.overall_result }}
                            </td>
                            <td>
                                <strong class="status-{{ 'success' if log.trust_score >= 70 else 'failed' }}">
                                    {{ log.trust_score }}/100
                                </strong>
                            </td>
                            <td class="status-{{ 'success' if log.step_5_1_status == 'PASSED' else 'failed' }}">
                                {{ log.step_5_1_status }}
                            </td>
                            <td class="status-{{ 'success' if log.step_5_2_status == 'PASSED' else 'failed' }}">
                                {{ log.step_5_2_status }}
                            </td>
                            <td class="status-{{ 'success' if log.step_5_3_status == 'PASSED' else 'failed' }}">
                                {{ log.step_5_3_status }}
                            </td>
                            <td>{{ log.ip_address if log.ip_address else 'N/A' }}</td>
                            <td class="timestamp">{{ log.timestamp }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
                {% else %}
                <div class="empty-state">
                    <div class="empty-icon">🔍</div>
                    <p>No verification logs yet</p>
                    <small>Phase 5 verification logs will appear here when devices authenticate</small>
                </div>
                {% endif %}
            </div>
            
            <!-- Hardware Binding Information -->
            <div class="section">
                <div class="section-header">
                    <h2>🔧 Hardware Fingerprint Bindings</h2>
                </div>
                {% if hardware_bindings %}
                <table>
                    <thead>
                        <tr>
                            <th>Device ID</th>
                            <th>Hardware Fingerprint</th>
                            <th>Public Key Fingerprint</th>
                            <th>Binding Status</th>
                            <th>Verification Count</th>
                            <th>Last Verified</th>
                            <th>Binding Timestamp</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for binding in hardware_bindings %}
                        <tr>
                            <td><strong>{{ binding.device_id }}</strong></td>
                            <td class="fingerprint full-fingerprint">{{ binding.hardware_fingerprint }}</td>
                            <td class="fingerprint full-fingerprint">{{ binding.public_key_fingerprint }}</td>
                            <td>
                                <span class="badge badge-{{ binding.binding_status }}">
                                    {{ binding.binding_status|upper }}
                                </span>
                            </td>
                            <td>{{ binding.verification_count }}</td>
                            <td class="timestamp">{{ binding.last_verified }}</td>
                            <td class="timestamp">{{ binding.binding_timestamp }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
                {% else %}
                <div class="empty-state">
                    <div class="empty-icon">🔗</div>
                    <p>No hardware bindings yet</p>
                    <small>Hardware fingerprints will be bound when devices enroll</small>
                </div>
                {% endif %}
            </div>
            
            <!-- Device Enrollment Log -->
            <div class="section">
                <div class="section-header">
                    <h2>📝 Recent Enrollment Activity</h2>
                </div>
                {% if enrollment_logs %}
                <table>
                    <thead>
                        <tr>
                            <th>Device ID</th>
                            <th>Action</th>
                            <th>Status</th>
                            <th>Public Key Fingerprint</th>
                            <th>IP Address</th>
                            <th>Error Details</th>
                            <th>Timestamp</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for log in enrollment_logs %}
                        <tr>
                            <td>{{ log.device_id }}</td>
                            <td>{{ log.action }}</td>
                            <td class="status-{{ log.status|lower }}">{{ log.status }}</td>
                            <td class="fingerprint full-fingerprint" title="{{ log.public_key_fingerprint }}">
                                {{ log.public_key_fingerprint if log.public_key_fingerprint else 'N/A' }}
                            </td>
                            <td>{{ log.ip_address }}</td>
                            <td class="status-error">{{ log.error_details if log.error_details else '-' }}</td>
                            <td class="timestamp">{{ log.timestamp }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
                {% else %}
                <div class="empty-state">
                    <div class="empty-icon">📝</div>
                    <p>No enrollment activity yet</p>
                    <small>Enrollment logs will appear when devices register</small>
                </div>
                {% endif %}
            </div>
            
            <!-- Device Failed Attempts -->
            <div class="section">
                <div class="section-header">
                    <h2>⚠️ Failed Authentication Attempts</h2>
                </div>
                {% if failed_attempts %}
                <table>
                    <thead>
                        <tr>
                            <th>Attempt Type</th>
                            <th>Device ID</th>
                            <th>Target Resource</th>
                            <th>Reason</th>
                            <th>Error Details</th>
                            <th>Timestamp</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for attempt in failed_attempts %}
                        <tr>
                            <td class="status-error"><strong>{{ attempt.attempt_type }}</strong></td>
                            <td>{{ attempt.device_id }}</td>
                            <td>{{ attempt.target_resource }}</td>
                            <td class="status-failed">{{ attempt.reason }}</td>
                            <td>{{ attempt.error_details if attempt.error_details else '-' }}</td>
                            <td class="timestamp">{{ attempt.timestamp }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
                {% else %}
                <div class="empty-state">
                    <div class="empty-icon">✅</div>
                    <p>No failed authentication attempts</p>
                    <small>This is good - all authentication attempts have been successful</small>
                </div>
                {% endif %}
            </div>
            
            <!-- Hardware Verification Log -->
            <div class="section">
                <div class="section-header">
                    <h2>🔧 Hardware Verification Activity</h2>
                </div>
                {% if hardware_logs %}
                <table>
                    <thead>
                        <tr>
                            <th>Device ID</th>
                            <th>Hardware Fingerprint</th>
                            <th>Verification Type</th>
                            <th>Match Result</th>
                            <th>Action Taken</th>
                            <th>IP Address</th>
                            <th>Timestamp</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for log in hardware_logs %}
                        <tr>
                            <td>{{ log.device_id }}</td>
                            <td class="fingerprint full-fingerprint">{{ log.hardware_fingerprint }}</td>
                            <td>{{ log.verification_type }}</td>
                            <td class="status-{{ 'success' if log.match_result else 'failed' }}">
                                {{ 'PASSED ✓' if log.match_result else 'FAILED ✗' }}
                            </td>
                            <td>{{ log.action_taken }}</td>
                            <td>{{ log.ip_address if log.ip_address else 'N/A' }}</td>
                            <td class="timestamp">{{ log.timestamp }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
                {% else %}
                <div class="empty-state">
                    <div class="empty-icon">🔧</div>
                    <p>No hardware verification logs yet</p>
                    <small>Hardware verification logs will appear when devices authenticate</small>
                </div>
                {% endif %}
            </div>
        </div>
        
        <script>
            // Auto-refresh every 30 seconds
            setTimeout(() => location.reload(), 30000);
        </script>
    </body>
    </html>
    """
    
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # Get statistics - will return 0 if no data
        cursor.execute('SELECT COUNT(*) FROM device_identity')
        total_devices = cursor.fetchone()[0] or 0
        
        cursor.execute('SELECT COUNT(*) FROM device_identity WHERE status = "active"')
        active_devices = cursor.fetchone()[0] or 0
        
        cursor.execute('SELECT COUNT(*) FROM device_identity WHERE status = "quarantine"')
        quarantined_devices = cursor.fetchone()[0] or 0
        
        cursor.execute('SELECT COUNT(*) FROM device_identity WHERE status = "revoked"')
        revoked_devices = cursor.fetchone()[0] or 0
        
        cursor.execute('''
            SELECT COUNT(*) FROM phase5_verification_log 
            WHERE datetime(timestamp) > datetime('now', '-1 day')
        ''')
        verifications_24h = cursor.fetchone()[0] or 0
        
        cursor.execute('''
            SELECT COUNT(*) FROM device_failed_attempt_log
            WHERE datetime(timestamp) > datetime('now', '-1 day')
        ''')
        failed_attempts = cursor.fetchone()[0] or 0
        
        cursor.execute('SELECT COUNT(*) FROM device_hardware_binding')
        hardware_bindings = cursor.fetchone()[0] or 0
        
        stats = {
            'total_devices': total_devices,
            'active_devices': active_devices,
            'quarantined_devices': quarantined_devices,
            'revoked_devices': revoked_devices,
            'verifications_24h': verifications_24h,
            'failed_attempts': failed_attempts,
            'hardware_bindings': hardware_bindings
        }
        
        # Get device identity data with hardware fingerprint
        cursor.execute('''
            SELECT 
                di.device_id, 
                di.status, 
                di.public_key_fingerprint, 
                di.firmware_version,
                di.device_type, 
                di.enrollment_count, 
                di.last_seen,
                dhb.hardware_fingerprint
            FROM device_identity di
            LEFT JOIN device_hardware_binding dhb ON di.device_id = dhb.device_id
            ORDER BY di.last_seen DESC
            LIMIT 20
        ''')
        device_identity = [
            {
                'device_id': row[0],
                'status': row[1],
                'public_key_fingerprint': row[2],
                'firmware_version': row[3],
                'device_type': row[4],
                'enrollment_count': row[5],
                'last_seen': row[6],
                'hardware_fingerprint': row[7]
            }
            for row in cursor.fetchall()
        ]
        
        # Get Phase 5 verification logs
        cursor.execute('''
            SELECT device_id, overall_result, trust_score, step_5_1_status,
                   step_5_2_status, step_5_3_status, ip_address, timestamp
            FROM phase5_verification_log
            ORDER BY timestamp DESC
            LIMIT 15
        ''')
        phase5_logs = [
            {
                'device_id': row[0],
                'overall_result': row[1],
                'trust_score': row[2],
                'step_5_1_status': row[3],
                'step_5_2_status': row[4],
                'step_5_3_status': row[5],
                'ip_address': row[6],
                'timestamp': row[7]
            }
            for row in cursor.fetchall()
        ]
        
        # Get hardware bindings
        cursor.execute('''
            SELECT device_id, hardware_fingerprint, public_key_fingerprint,
                   binding_status, verification_count, last_verified, binding_timestamp
            FROM device_hardware_binding
            ORDER BY binding_timestamp DESC
            LIMIT 20
        ''')
        hardware_bindings_data = [
            {
                'device_id': row[0],
                'hardware_fingerprint': row[1],
                'public_key_fingerprint': row[2],
                'binding_status': row[3],
                'verification_count': row[4],
                'last_verified': row[5],
                'binding_timestamp': row[6]
            }
            for row in cursor.fetchall()
        ]
        
        # Get enrollment logs
        cursor.execute('''
            SELECT device_id, action, status, public_key_fingerprint,
                   ip_address, error_details, timestamp
            FROM device_enrollment_log
            ORDER BY timestamp DESC
            LIMIT 15
        ''')
        enrollment_logs = [
            {
                'device_id': row[0],
                'action': row[1],
                'status': row[2],
                'public_key_fingerprint': row[3],
                'ip_address': row[4],
                'error_details': row[5],
                'timestamp': row[6]
            }
            for row in cursor.fetchall()
        ]
        
        # Get failed attempts
        cursor.execute('''
            SELECT attempt_type, device_id, target_resource, reason, error_details, timestamp
            FROM device_failed_attempt_log
            ORDER BY timestamp DESC
            LIMIT 15
        ''')
        failed_attempts_data = [
            {
                'attempt_type': row[0],
                'device_id': row[1],
                'target_resource': row[2],
                'reason': row[3],
                'error_details': row[4],
                'timestamp': row[5]
            }
            for row in cursor.fetchall()
        ]
        
        # Get hardware verification logs
        cursor.execute('''
            SELECT device_id, hardware_fingerprint, verification_type, 
                   match_result, action_taken, ip_address, timestamp
            FROM hardware_verification_log
            ORDER BY timestamp DESC
            LIMIT 15
        ''')
        hardware_logs = [
            {
                'device_id': row[0],
                'hardware_fingerprint': row[1],
                'verification_type': row[2],
                'match_result': row[3],
                'action_taken': row[4],
                'ip_address': row[5],
                'timestamp': row[6]
            }
            for row in cursor.fetchall()
        ]
        
        conn.close()
        
        return render_template_string(
            html_template,
            stats=stats,
            device_identity=device_identity,
            phase5_logs=phase5_logs,
            hardware_bindings=hardware_bindings_data,
            enrollment_logs=enrollment_logs,
            failed_attempts=failed_attempts_data,
            hardware_logs=hardware_logs
        )
    
    except Exception as e:
        # If database doesn't exist or has errors, show empty dashboard
        return render_template_string(
            html_template,
            stats={
                'total_devices': 0,
                'active_devices': 0,
                'quarantined_devices': 0,
                'revoked_devices': 0,
                'verifications_24h': 0,
                'failed_attempts': 0,
                'hardware_bindings': 0
            },
            device_identity=[],
            phase5_logs=[],
            hardware_bindings=[],
            enrollment_logs=[],
            failed_attempts=[],
            hardware_logs=[]
        )

# ============= RBAC VERIFY ENDPOINT (Integration with Delta Patch Server) =============
# Add this route to zero_trust_server.py

@app.route('/rbac/verify', methods=['POST'])
def rbac_verify():
    """
    RBAC verification endpoint for inter-service calls.
    Called by the Delta Patch FastAPI server before serving a patch.

    Expected JSON:
    {
        "device_id": "esp32_01",
        "action": "get_patch",
        "trust_score": 85          # optional: score already computed by Phase 5
    }

    Returns:
    {
        "allowed": true,
        "trust_score": 85,
        "device_status": "active",
        "reason": "Device authenticated with sufficient trust score"
    }

    Logic:
      1. Check device exists and is 'active' in device_identity table.
      2. Look up the most recent Phase 5 trust score from phase5_verification_log.
         If trust_score is passed in the request body, that is used instead
         (the patch server forwards it from the auth flow).
      3. Allow if trust_score >= TRUST_THRESHOLD (70) AND device is active.
    """
    try:
        data = request.get_json()
        client_ip = request.remote_addr

        if not data or 'device_id' not in data:
            return jsonify({
                "allowed": False,
                "reason": "device_id required"
            }), 400

        device_id = data['device_id']
        action = data.get('action', 'get_patch')
        provided_score = data.get('trust_score', None)

        TRUST_THRESHOLD = 70

        # 1. Check device identity & status
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()

        cursor.execute('''
            SELECT status FROM device_identity WHERE device_id = ?
        ''', (device_id,))
        device_row = cursor.fetchone()

        if not device_row:
            conn.close()
            log_system_event(
                event_type="RBAC_DENIED",
                component="RBAC_VERIFY",
                description=f"Device {device_id} not enrolled — {action} denied",
                severity="WARNING"
            )
            return jsonify({
                "allowed": False,
                "trust_score": 0,
                "device_status": "unknown",
                "reason": "Device not enrolled"
            }), 403

        device_status = device_row[0]

        if device_status != 'active':
            conn.close()
            log_system_event(
                event_type="RBAC_DENIED",
                component="RBAC_VERIFY",
                description=f"Device {device_id} status={device_status} — {action} denied",
                severity="WARNING"
            )
            return jsonify({
                "allowed": False,
                "trust_score": 0,
                "device_status": device_status,
                "reason": f"Device is {device_status}"
            }), 403

        # 2. Resolve trust score
        if provided_score is not None:
            trust_score = int(provided_score)
            score_source = "caller"
        else:
            # Look up most recent Phase 5 result
            try:
                cursor.execute('''
                    SELECT trust_score FROM phase5_verification_log
                    WHERE device_id = ? AND overall_result = 'TRUSTED'
                    ORDER BY timestamp DESC
                    LIMIT 1
                ''', (device_id,))
                score_row = cursor.fetchone()
                trust_score = score_row[0] if score_row else 0
                score_source = "phase5_log"
            except Exception:
                trust_score = 0
                score_source = "default"

        conn.close()

        # 3. Decision
        allowed = (trust_score >= TRUST_THRESHOLD)
        reason = (
            f"Trust score {trust_score}/100 >= threshold {TRUST_THRESHOLD}"
            if allowed
            else f"Trust score {trust_score}/100 below threshold {TRUST_THRESHOLD}"
        )

        # Log the RBAC decision
        log_system_event(
            event_type="RBAC_DECISION",
            component="RBAC_VERIFY",
            description=f"Device {device_id} action={action} — {'ALLOWED' if allowed else 'DENIED'} (score={trust_score}, source={score_source})",
            severity="INFO" if allowed else "WARNING",
            additional_data=f"client_ip={client_ip}"
        )

        status_code = 200 if allowed else 403
        return jsonify({
            "allowed": allowed,
            "trust_score": trust_score,
            "device_status": device_status,
            "reason": reason
        }), status_code

    except Exception as e:
        return jsonify({
            "allowed": False,
            "trust_score": 0,
            "reason": f"RBAC verification error: {str(e)}"
        }), 500


if __name__ == '__main__':
    print("=" * 50)
    print("Zero Trust Layer Server Starting...")
    print("Port: 5000")
    print("Update Cloud URL:", UPDATE_CLOUD_URL)
    print("Download Directory:", DOWNLOAD_DIR)
    print("Database File:", DB_FILE)
    print("=" * 50)

    log_system_event(
        event_type="SERVER_START",
        component="ZERO_TRUST_SERVER",
        description="Zero Trust Server starting on port 5000",
        severity="INFO",
        additional_data=f"Update Cloud URL: {UPDATE_CLOUD_URL}"
    )
    
    # Log encryption key status
    if load_encryption_key():
        log_system_event(
            event_type="ENCRYPTION_KEY_LOADED",
            component="ENCRYPTION_MODULE",
            description="Encryption key loaded successfully",
            severity="INFO"
        )
    else:
        log_system_event(
            event_type="ENCRYPTION_ERROR",
            component="ENCRYPTION_MODULE",
            description="Failed to load encryption key",
            severity="ERROR"
        )
        
    app.run(host='0.0.0.0', port=5000, debug=True)