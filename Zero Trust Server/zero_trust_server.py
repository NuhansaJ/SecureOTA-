from flask import Flask, jsonify, request
import requests
import jwt
import os
import sqlite3
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import base64
from datetime import datetime
import secrets

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
    # NEW: Authentication Actions Log
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
    
    # NEW: Cached Tokens (for reference and revocation checking)
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
    
    # NEW: Device Certificate Fingerprints
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
    
    # === NEW LOGGING TABLES ===
    
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
    conn.commit()
    conn.close()
    print(f"[Database] Initialized with Device Auth tables: {DB_FILE}")
    print(f"[Database] Phase 1 Device Identity tables initialized")


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

# ============= END LOGGING FUNCTIONS =============


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
        
        # ===== NEW: OBTAIN JWT TOKEN FOR DEVICE =====
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