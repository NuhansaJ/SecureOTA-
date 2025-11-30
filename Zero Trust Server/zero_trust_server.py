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
    
    conn.commit()
    conn.close()
    print(f"[Database] Initialized with Device Auth tables: {DB_FILE}")

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
        
        if not auth_success:
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
        
        # Decrypt firmware
        encryption_key = None  # Load from your encryption system
        try:
            decrypted_data = decrypt_data(encrypted_data, encryption_key)
            
            file_path = os.path.join(DOWNLOAD_DIR, firmware_name)
            with open(file_path, 'wb') as f:
                f.write(decrypted_data)
            
            print(f"[Zero Trust Server] Firmware decrypted and saved: {firmware_name}")
            
            # Calculate hash
            calculated_hash = calculate_file_hash(file_path)
            print(f"[Hashing] Calculated hash: {calculated_hash}")
            
            # Verify hash
            if received_hash == calculated_hash:
                print("[Verification] ✅ Hash verification PASSED")
                
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
    

if __name__ == '__main__':
    print("=" * 50)
    print("Zero Trust Layer Server Starting...")
    print("Port: 5000")
    print("Update Cloud URL:", UPDATE_CLOUD_URL)
    print("Download Directory:", DOWNLOAD_DIR)
    print("Database File:", DB_FILE)
    print("=" * 50)
    app.run(host='0.0.0.0', port=5000, debug=True)