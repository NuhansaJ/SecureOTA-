from flask import Flask, send_file, jsonify, request
from functools import wraps
import jwt
import os
import sqlite3
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import base64
from datetime import datetime, timedelta
import secrets

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)

#new lines - erase this later
#JWT Configuration 
JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'your-secure-secret-key-change-in-production')
JWT_ALGORITHM = 'HS256'
JWT_EXPIRATION_MINUTES = 60

# RSA keypair for JWT signature verification (for device fingerprinting)
def get_or_create_rsa_keys():
    private_key_file = os.path.join(SCRIPT_DIR, "jwt_private_key.pem")
    public_key_file = os.path.join(SCRIPT_DIR, "jwt_public_key.pem")
    
    if os.path.exists(private_key_file) and os.path.exists(public_key_file):
        with open(private_key_file, 'rb') as f:
            private_key = f.read()
        with open(public_key_file, 'rb') as f:
            public_key = f.read()
        return private_key, public_key
    else:
        from cryptography.hazmat.primitives import serialization
        private_key_obj = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        private_key = private_key_obj.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_key = private_key_obj.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        with open(private_key_file, 'wb') as f:
            f.write(private_key)
        with open(public_key_file, 'wb') as f:
            f.write(public_key)
        print(f"[JWT] RSA keypair generated and saved")
        return private_key, public_key

JWT_PRIVATE_KEY, JWT_PUBLIC_KEY = get_or_create_rsa_keys()

# Role definitions (IoT-specific)
ROLE_PERMISSIONS = {
    'admin': ['firmware:upload', 'firmware:delete', 'policy:write', 'audit:read', 'audit:write'],
    'technician': ['firmware:download', 'firmware:verify', 'device:manage'],
    'auditor': ['audit:read', 'firmware:list'],
    'iot_device': ['firmware:download', 'firmware:verify'],
}

#UPTO THIS POINT - NEW LINES ADDED - ERASE LATER


# Get the directory where this script is located
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Directory where firmware update files are stored (inside Cloud server folder)
FIRMWARE_DIR = os.path.join(SCRIPT_DIR, "firmware_files")

# SQLite database path (inside Cloud server folder)
DB_FILE = os.path.join(SCRIPT_DIR, "firmware_database.db")

# Encryption key file path
KEY_FILE = os.path.join(SCRIPT_DIR, "encryption_key.key")

# Generate or load AES-256 encryption key
def get_encryption_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, 'rb') as key_file:
            return key_file.read()
    else:
        # Generate a 256-bit (32 bytes) key for AES-256
        key = secrets.token_bytes(32)
        with open(KEY_FILE, 'wb') as key_file:
            key_file.write(key)
        return key

# AES-256-CBC encryption function
def encrypt_data(data, key):
    iv = secrets.token_bytes(16)  # Generate random IV (16 bytes)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Add PKCS7 padding
    padding_length = 16 - (len(data) % 16)
    padded_data = data + bytes([padding_length] * padding_length)
    
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted_data  # Prepend IV to encrypted data

# Initialize encryption
ENCRYPTION_KEY = get_encryption_key()
print(f"[Encryption] AES-256 Key loaded/generated: {KEY_FILE}")

# Initialize SQLite Database
def init_database():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS firmware_hashes (
            id INTEGER PRIMARY KEY,
            firmware_name TEXT UNIQUE NOT NULL,
            file_hash TEXT NOT NULL,
            file_size INTEGER,
            timestamp TEXT NOT NULL
        )
    ''')
#NEW LINES  
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS auth_audit_log (
            id INTEGER PRIMARY KEY,
            token_id TEXT UNIQUE NOT NULL,
            user_id TEXT NOT NULL,
            role TEXT NOT NULL,
            action TEXT NOT NULL,
            device_fingerprint TEXT,
            endpoint TEXT NOT NULL,
            status TEXT NOT NULL,
            ip_address TEXT,
            timestamp TEXT NOT NULL,
            token_expiry TEXT NOT NULL
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS token_blacklist (
            id INTEGER PRIMARY KEY,
            token_id TEXT UNIQUE NOT NULL,
            revoked_at TEXT NOT NULL,
            revoked_by TEXT NOT NULL
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS admin_users (
            id INTEGER PRIMARY KEY,
            user_id TEXT UNIQUE NOT NULL,
            username TEXT UNIQUE NOT NULL,
            role TEXT NOT NULL,
            device_certificate_hash TEXT,
            created_at TEXT NOT NULL,
            is_active BOOLEAN DEFAULT 1
        )
    ''')

# === NEW LOGGING TABLES ===
    
    # Firmware action logs
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS firmware_action_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action_type TEXT NOT NULL,
            firmware_name TEXT NOT NULL,
            user_id TEXT NOT NULL,
            username TEXT NOT NULL,
            role TEXT NOT NULL,
            details TEXT,
            status TEXT NOT NULL,
            ip_address TEXT,
            token_id TEXT,
            timestamp TEXT NOT NULL
        )
    ''')
    
    # Policy change logs
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS policy_change_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            changed_by TEXT NOT NULL,
            user_id TEXT NOT NULL,
            role TEXT NOT NULL,
            change_type TEXT NOT NULL,
            old_value TEXT,
            new_value TEXT,
            affected_entity TEXT NOT NULL,
            ip_address TEXT,
            token_id TEXT,
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
    
    # Failed attempt logs
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS failed_attempt_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            attempt_type TEXT NOT NULL,
            attempted_by TEXT NOT NULL,
            target_resource TEXT NOT NULL,
            reason TEXT NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            timestamp TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()
    print(f"[Database] Initialized with Auth tables: {DB_FILE}")

# ============= SECURE LOGGING FUNCTIONS =============

def log_firmware_action(action_type, firmware_name, user_id, username, role, 
                       details, status, ip_address, token_id=None):
    """
    Log all firmware-related actions
    
    action_type: UPLOAD, DOWNLOAD, DELETE, LIST, VERIFY, ACCESS_DENIED
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT INTO firmware_action_log
            (action_type, firmware_name, user_id, username, role, details, 
             status, ip_address, token_id, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (action_type, firmware_name, user_id, username, role, details, 
              status, ip_address, token_id, datetime.now().isoformat()))
        conn.commit()
        print(f"[Firmware Log] {action_type} - {firmware_name} - {username} - {status}")
    except Exception as e:
        print(f"[Firmware Log] Error: {e}")
    finally:
        conn.close()

def log_policy_change(changed_by, user_id, role, change_type, old_value, 
                     new_value, affected_entity, ip_address, token_id):
    """
    Log all policy and configuration changes
    
    change_type: ROLE_MODIFIED, PERMISSION_CHANGED, USER_ADDED, USER_REMOVED, 
                 CONFIG_UPDATED, KEY_ROTATED
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT INTO policy_change_log
            (changed_by, user_id, role, change_type, old_value, new_value, 
             affected_entity, ip_address, token_id, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (changed_by, user_id, role, change_type, old_value, new_value, 
              affected_entity, ip_address, token_id, datetime.now().isoformat()))
        conn.commit()
        print(f"[Policy Log] {change_type} - By: {changed_by} - Entity: {affected_entity}")
    except Exception as e:
        print(f"[Policy Log] Error: {e}")
    finally:
        conn.close()

def log_system_event(event_type, component, description, severity, 
                    additional_data=None):
    """
    Log system-level events
    
    event_type: SERVER_START, SERVER_STOP, DATABASE_ERROR, ENCRYPTION_ERROR, 
                CONNECTION_ERROR, THRESHOLD_EXCEEDED
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

def log_failed_attempt(attempt_type, attempted_by, target_resource, 
                      reason, ip_address, user_agent=None):
    """
    Log all failed access/operation attempts
    
    attempt_type: INVALID_TOKEN, EXPIRED_TOKEN, MISSING_PERMISSION, 
                  INVALID_CREDENTIALS, RATE_LIMIT_EXCEEDED, INVALID_HASH
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT INTO failed_attempt_log
            (attempt_type, attempted_by, target_resource, reason, 
             ip_address, user_agent, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (attempt_type, attempted_by, target_resource, reason, 
              ip_address, user_agent, datetime.now().isoformat()))
        conn.commit()
        print(f"[Failed Attempt] {attempt_type} - {attempted_by} - {reason}")
    except Exception as e:
        print(f"[Failed Attempt Log] Error: {e}")
    finally:
        conn.close()

# ============= END LOGGING FUNCTIONS =============

def generate_jwt_token(user_id, username, role, device_fingerprint):
    """
    Generate JWT token with custom claims and device fingerprint
    
    Args:
        user_id: Unique user identifier
        username: Username for audit trail
        role: User role (admin, technician, auditor, iot_device)
        device_fingerprint: Hash of device certificate (prevents token reuse)
    
    Returns:
        Encoded JWT token
    """
    token_id = secrets.token_urlsafe(16)  # Unique token ID for audit trail
    
    payload = {
        'jti': token_id,  # JWT ID (for audit trail correlation)
        'sub': user_id,   # Subject (user ID)
        'usr': username,  # Custom claim: username
        'role': role,     # Custom claim: role
        'perm': ROLE_PERMISSIONS.get(role, []),  # Custom claim: permissions
        'dev_fp': device_fingerprint,  # Custom claim: device fingerprint
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(minutes=JWT_EXPIRATION_MINUTES),
        'aud': 'firmware-update-service'  # Audience
    }
    
    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    print(f"[JWT] Token generated - ID: {token_id}, User: {username}, Role: {role}")
    return token, token_id, payload['exp']

def verify_jwt_token(token, device_fingerprint=None):
    """
    Verify JWT token and check device fingerprint binding
    
    Args:
        token: JWT token to verify
        device_fingerprint: Expected device fingerprint (for binding validation)
    
    Returns:
        Tuple: (is_valid, payload_or_error)
    """
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        
        # Check if token is blacklisted
        if is_token_blacklisted(payload['jti']):
            return False, "Token has been revoked"
        
        # Verify device fingerprint if provided
        if device_fingerprint and payload.get('dev_fp') != device_fingerprint:
            return False, "Device fingerprint mismatch - token invalid for this device"
        
        return True, payload
    
    except jwt.ExpiredSignatureError:
        return False, "Token has expired"
    except jwt.InvalidTokenError as e:
        return False, f"Invalid token: {str(e)}"

def is_token_blacklisted(token_id):
    """Check if token has been revoked"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT id FROM token_blacklist WHERE token_id = ?', (token_id,))
        result = cursor.fetchone()
        return result is not None
    finally:
        conn.close()

def log_auth_action(token_id, user_id, username, role, action, device_fingerprint, endpoint, status, ip_address, token_expiry):
    """Log authentication and authorization actions to audit trail"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT INTO auth_audit_log
            (token_id, user_id, role, action, device_fingerprint, endpoint, status, ip_address, timestamp, token_expiry)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (token_id, user_id, role, action, device_fingerprint, endpoint, status, ip_address, datetime.now().isoformat(), token_expiry))
        conn.commit()
        print(f"[Audit] {action} - {username}@{role} - {status} - ID: {token_id}")
    except Exception as e:
        print(f"[Audit] Error logging action: {e}")
    finally:
        conn.close()

def require_jwt_auth(required_permission=None):
    """
    Middleware decorator to validate JWT and check permissions
    
    Args:
        required_permission: Specific permission required (e.g., 'firmware:upload')
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            token = None
            device_fingerprint = None
            
            # Extract token from Authorization header
            if 'Authorization' in request.headers:
                auth_header = request.headers['Authorization']
                try:
                    token = auth_header.split(" ")[1]  # Bearer <token>
                except IndexError:
                    return jsonify({"error": "Invalid authorization header format"}), 401
            
            # Extract device fingerprint from headers (optional but recommended)
            device_fingerprint = request.headers.get('X-Device-Fingerprint', None)
            
            if not token:
                return jsonify({"error": "Authorization token required"}), 401
            
            # Verify token
            is_valid, payload_or_error = verify_jwt_token(token, device_fingerprint)
            
            if not is_valid:
                # Log failed attempt
                endpoint = f"{request.method} {request.path}"
                log_auth_action(
                    token_id="INVALID_TOKEN",
                    user_id="UNKNOWN",
                    username="UNKNOWN",
                    role="UNKNOWN",
                    action=f"AUTH_FAILED: {endpoint}",
                    device_fingerprint=device_fingerprint,
                    endpoint=endpoint,
                    status=f"FAILED - {payload_or_error}",
                    ip_address=request.remote_addr,
                    token_expiry="N/A"
                )

                log_failed_attempt(
                        attempt_type="MISSING_PERMISSION",
                        attempted_by=payload['usr'],
                        target_resource=f"{request.method} {request.path}",
                        reason=f"Missing permission: {required_permission}",
                        ip_address=request.remote_addr
                    )
                
                return jsonify({"error": payload_or_error}), 401
            
            payload = payload_or_error
            
            # Check permission if required
            if required_permission:
                user_permissions = payload.get('perm', [])
                if required_permission not in user_permissions:
                    # Log unauthorized attempt
                    log_auth_action(
                        token_id=payload['jti'],
                        user_id=payload['sub'],
                        username=payload['usr'],
                        role=payload['role'],
                        action=f"PERMISSION_DENIED: {required_permission}",
                        device_fingerprint=device_fingerprint,
                        endpoint=f"{request.method} {request.path}",
                        status=f"DENIED - Missing permission: {required_permission}",
                        ip_address=request.remote_addr,
                        token_expiry=payload['exp']
                    )
                    return jsonify({"error": f"Permission denied: {required_permission}"}), 403
            
            # Log successful authentication
            log_auth_action(
                token_id=payload['jti'],
                user_id=payload['sub'],
                username=payload['usr'],
                role=payload['role'],
                action=f"AUTH_SUCCESS: {request.method} {request.path}",
                device_fingerprint=device_fingerprint,
                endpoint=f"{request.method} {request.path}",
                status="SUCCESS",
                ip_address=request.remote_addr,
                token_expiry=payload['exp']
            )
            
            # Pass payload to route function
            request.jwt_payload = payload
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator

#UPTO HERE - NEW LINES 

# Calculate hash of a file
def calculate_file_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

# Store hash in database
def store_hash_in_db(firmware_name, file_hash, file_size):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT OR REPLACE INTO firmware_hashes 
            (firmware_name, file_hash, file_size, timestamp) 
            VALUES (?, ?, ?, ?)
        ''', (firmware_name, file_hash, file_size, datetime.now().isoformat()))
        conn.commit()
        print(f"[Database] Hash stored for: {firmware_name}")
    except Exception as e:
        print(f"[Database] Error storing hash: {e}")
    finally:
        conn.close()

# Get hash from database
def get_hash_from_db(firmware_name):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT file_hash FROM firmware_hashes WHERE firmware_name = ?', (firmware_name,))
        result = cursor.fetchone()
        return result[0] if result else None
    except Exception as e:
        print(f"[Database] Error retrieving hash: {e}")
        return None
    finally:
        conn.close()

# Initialize database on startup
init_database()

# Create firmware directory if it doesn't exist
if not os.path.exists(FIRMWARE_DIR):
    os.makedirs(FIRMWARE_DIR)
    # Create a sample firmware file for testing (encrypted)
    sample_data = b"Sample firmware data v1.0"
    encrypted_data = encrypt_data(sample_data, ENCRYPTION_KEY)
    sample_file_path = os.path.join(FIRMWARE_DIR, "firmware_v1.0.bin")
    with open(sample_file_path, "wb") as f:
        f.write(encrypted_data)
    print("[Encryption] Sample firmware created and encrypted with AES-256")

# Scan all firmware files and calculate/store their hashes
print("[Hashing] Scanning firmware directory for files...")
for filename in os.listdir(FIRMWARE_DIR):
    file_path = os.path.join(FIRMWARE_DIR, filename)
    if os.path.isfile(file_path):
        file_hash = calculate_file_hash(file_path)
        file_size = os.path.getsize(file_path)
        store_hash_in_db(filename, file_hash, file_size)
        print(f"[Hashing] Hash calculated and stored for: {filename}")


@app.route('/auth/login', methods=['POST'])
def auth_login():
    """
    Login endpoint to obtain JWT token
    
    Expected JSON:
    {
        "username": "admin_user",
        "password": "secure_password",
        "device_certificate_hash": "sha256_hash_of_cert"
    }
    """
    try:
        data = request.get_json()
        
        if not data or 'username' not in data or 'password' not in data:
            return jsonify({"error": "username and password required"}), 400
        
        username = data.get('username')
        password = data.get('password')
        device_certificate_hash = data.get('device_certificate_hash', '')
        
        # TODO: In production, verify password against hashed password in database
        # For now, hardcoded admin for demonstration
        if username == 'admin' and password == 'secure_admin_password':
            user_id = 'user_admin_001'
            role = 'admin'
        elif username == 'technician' and password == 'secure_tech_password':
            user_id = 'user_tech_001'
            role = 'technician'
        else:
            log_auth_action(
                token_id="LOGIN_FAILED",
                user_id="UNKNOWN",
                username=username,
                role="UNKNOWN",
                action="LOGIN_ATTEMPT",
                device_fingerprint=device_certificate_hash,
                endpoint="/auth/login",
                status="FAILED - Invalid credentials",
                ip_address=request.remote_addr,
                token_expiry="N/A"
            )

            log_failed_attempt(
                attempt_type="INVALID_CREDENTIALS",
                attempted_by=username,
                target_resource="/auth/login",
                reason="Invalid username or password",
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent')
            )
            return jsonify({"error": "Invalid credentials"}), 401
        
        # Generate JWT with device fingerprint binding
        token, token_id, expiry = generate_jwt_token(user_id, username, role, device_certificate_hash)
        
        # Log successful login
        log_auth_action(
            token_id=token_id,
            user_id=user_id,
            username=username,
            role=role,
            action="LOGIN_SUCCESS",
            device_fingerprint=device_certificate_hash,
            endpoint="/auth/login",
            status="SUCCESS",
            ip_address=request.remote_addr,
            token_expiry=expiry
        )
        log_system_event(
            event_type="USER_LOGIN",
            component="AUTH_MODULE",
            description=f"User {username} logged in successfully",
            severity="INFO",
            additional_data=f"Role: {role}, IP: {request.remote_addr}"
        )

        return jsonify({
            "status": "success",
            "token": token,
            "token_id": token_id,
            "user_id": user_id,
            "username": username,
            "role": role,
            "expires_in_minutes": JWT_EXPIRATION_MINUTES
        }), 200
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/auth/verify', methods=['POST'])
def auth_verify():
    """Verify if a token is still valid"""
    try:
        data = request.get_json()
        token = data.get('token')
        device_fingerprint = data.get('device_fingerprint', None)
        
        if not token:
            return jsonify({"error": "token required"}), 400
        
        is_valid, payload_or_error = verify_jwt_token(token, device_fingerprint)
        
        if is_valid:
            payload = payload_or_error
            return jsonify({
                "valid": True,
                "token_id": payload['jti'],
                "user": payload['usr'],
                "role": payload['role'],
                "permissions": payload['perm'],
                "expires_at": payload['exp']
            }), 200
        else:
            return jsonify({
                "valid": False,
                "error": payload_or_error
            }), 401
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/auth/logout', methods=['POST'])
def auth_logout():
    """Revoke/blacklist a token"""
    try:
        data = request.get_json()
        token = data.get('token')
        
        if not token:
            return jsonify({"error": "token required"}), 400
        
        is_valid, payload_or_error = verify_jwt_token(token)
        
        if not is_valid:
            return jsonify({"error": "Invalid token"}), 401
        
        payload = payload_or_error
        token_id = payload['jti']
        
        # Add token to blacklist
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT INTO token_blacklist (token_id, revoked_at, revoked_by)
                VALUES (?, ?, ?)
            ''', (token_id, datetime.now().isoformat(), payload['usr']))
            conn.commit()
            
            log_auth_action(
                token_id=token_id,
                user_id=payload['sub'],
                username=payload['usr'],
                role=payload['role'],
                action="LOGOUT",
                device_fingerprint=payload.get('dev_fp'),
                endpoint="/auth/logout",
                status="SUCCESS",
                ip_address=request.remote_addr,
                token_expiry=payload['exp']
            )
            
            return jsonify({"status": "success", "message": "Token revoked"}), 200
        finally:
            conn.close()
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/audit/logs', methods=['GET'])
@require_jwt_auth(required_permission='audit:read')
def get_audit_logs():
    """Get audit logs (requires 'audit:read' permission)"""
    try:
        limit = request.args.get('limit', 50, type=int)
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, token_id, user_id, username, role, action, status, ip_address, timestamp
            FROM auth_audit_log
            ORDER BY timestamp DESC LIMIT ?
        ''', (limit,))
        results = cursor.fetchall()
        conn.close()
        
        logs = [
            {
                "id": row[0],
                "token_id": row[1],
                "user_id": row[2],
                "username": row[3],
                "role": row[4],
                "action": row[5],
                "status": row[6],
                "ip_address": row[7],
                "timestamp": row[8]
            }
            for row in results
        ]
        
        return jsonify({"audit_logs": logs}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

#NEW LINES END HERE

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "Update Cloud Server is running", "port": 8000}), 200

@app.route('/firmware/download/<filename>', methods=['GET'])
@require_jwt_auth(required_permission='firmware:download')
def download_firmware(filename):
    """
    Endpoint to download firmware files (encrypted)
        NOW REQUIRES: 'firmware:download' permission

    """
    try:
        file_path = os.path.join(FIRMWARE_DIR, filename)
        
        if not os.path.exists(file_path):
            log_failed_attempt(
                attempt_type="INVALID_RESOURCE",
                attempted_by=request.jwt_payload['usr'],
                target_resource=filename,
                reason="Firmware file not found",
                ip_address=request.remote_addr
            )
            return jsonify({"error": "Firmware file not found"}), 404
        
        # Get hash from database
        file_hash = get_hash_from_db(filename)
        
        print(f"[Update Cloud Server] Sending encrypted firmware: {filename}")
        print(f"[Hashing] File hash: {file_hash}")
        
        log_firmware_action(
            action_type="DOWNLOAD",
            firmware_name=filename,
            user_id=request.jwt_payload['sub'],
            username=request.jwt_payload['usr'],
            role=request.jwt_payload['role'],
            details=f"Firmware downloaded successfully. Hash: {file_hash[:16]}...",
            status="SUCCESS",
            ip_address=request.remote_addr,
            token_id=request.jwt_payload['jti']
        )
        # === END LOGGING ===

        # Return file with hash in response headers
        response = send_file(file_path, as_attachment=True, download_name=filename)
        response.headers['X-File-Hash'] = file_hash
        return response
    
    except Exception as e:
        log_system_event(
            event_type="DOWNLOAD_ERROR",
            component="FIRMWARE_DOWNLOAD",
            description=f"Error downloading firmware: {filename}",
            severity="ERROR",
            additional_data=str(e)
        )
        return jsonify({"error": str(e)}), 500

@app.route('/firmware/list', methods=['GET'])
@require_jwt_auth(required_permission='firmware:list')
def list_firmware():
    """
    List available firmware files (requires 'firmware:list' permission)
    """
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('SELECT firmware_name, file_hash, file_size, timestamp FROM firmware_hashes')
        results = cursor.fetchall()
        conn.close()
        
        firmware_list = [
            {
                "firmware_name": row[0],
                "file_hash": row[1],
                "file_size": row[2],
                "timestamp": row[3]
            }
            for row in results
        ]
        log_firmware_action(
            action_type="LIST",
            firmware_name="ALL",
            user_id=request.jwt_payload['sub'],
            username=request.jwt_payload['usr'],
            role=request.jwt_payload['role'],
            details=f"Listed {len(firmware_list)} firmware files",
            status="SUCCESS",
            ip_address=request.remote_addr,
            token_id=request.jwt_payload['jti']
        )
        
        return jsonify({"available_firmware": firmware_list}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/firmware/hash/<filename>', methods=['GET'])
@require_jwt_auth(required_permission='firmware:verify')
def get_firmware_hash(filename):
    """
    Endpoint to get hash of a specific firmware (requires 'firmware:verify' permission)
    """
    try:
        file_hash = get_hash_from_db(filename)
        
        if file_hash is None:
            return jsonify({"error": "Firmware not found in database"}), 404
        
        return jsonify({
            "firmware_name": filename,
            "file_hash": file_hash
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/get-encryption-key', methods=['GET'])
@require_jwt_auth(required_permission='firmware:download')
def get_key():
    """
    Endpoint to share encryption key with Zero Trust Server
    In production, this should use secure key exchange protocols
    """
    try:
        return jsonify({
            "encryption_key": base64.b64encode(ENCRYPTION_KEY).decode('utf-8')
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    print("=" * 50)
    print("Update Cloud Server Starting...")
    print("Port: 8000")
    print("Firmware Directory:", FIRMWARE_DIR)
    print("Database File:", DB_FILE)
    print("=" * 50)

    log_system_event(
        event_type="SERVER_START",
        component="UPDATE_CLOUD_SERVER",
        description="Update Cloud Server starting on port 8000",
        severity="INFO",
        additional_data=f"Firmware Dir: {FIRMWARE_DIR}, DB: {DB_FILE}"
    )
    
    app.run(host='0.0.0.0', port=8000, debug=True)