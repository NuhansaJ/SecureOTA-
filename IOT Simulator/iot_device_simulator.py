import hashlib
import json
import os
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import requests


class IoTDeviceSimulator:
    """
    Simulates an IoT device with cryptographic identity capabilities.
    Phase 1: ECC key generation and enrollment
    """
    
    def __init__(self, device_id, storage_path="device_storage"):
        """
        Initialize IoT device simulator
        
        Args:
            device_id (str): Unique identifier for this device
            storage_path (str): Directory to store device keys (simulates flash storage)
        """
        self.device_id = device_id
        self.storage_path = storage_path
        self.private_key = None
        self.public_key = None
        self.key_file = os.path.join(storage_path, f"{device_id}_private_key.pem")
        self.config_file = os.path.join(storage_path, f"{device_id}_config.json")
        
        # Create storage directory if it doesn't exist
        os.makedirs(storage_path, exist_ok=True)
        
        print(f"[{self.device_id}] IoT Device Simulator initialized")
    
    def generate_ecc_keypair(self):
        """
        Step 1.2: Generate ECC key pair on device
        Uses P-256 curve (SECP256R1) as recommended for IoT devices
        """
        print(f"[{self.device_id}] Generating ECC key pair (P-256 curve)...")
        
        # Generate private key using P-256 (SECP256R1) elliptic curve
        self.private_key = ec.generate_private_key(
            ec.SECP256R1(),
            default_backend()
        )
        
        # Extract public key from private key
        self.public_key = self.private_key.public_key()
        
        print(f"[{self.device_id}] ✓ ECC key pair generated successfully")
        return True
    
    def store_private_key(self):
        """
        Step 1.2: Store private key securely in flash storage (simulated)
        In real devices: encrypted flash, secure element, or TPM
        
        📌 SECURITY NOTE: Private key NEVER leaves the device
        """
        print(f"[{self.device_id}] Storing private key to secure storage...")
        
        # Serialize private key to PEM format with encryption
        # In production: use hardware encryption or secure enclave
        pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(b'device_secure_password')
        )
        
        # Write to file (simulates writing to flash memory)
        with open(self.key_file, 'wb') as f:
            f.write(pem)
        
        print(f"[{self.device_id}] ✓ Private key stored at: {self.key_file}")
        print(f"[{self.device_id}] 📌 Private key will NEVER be transmitted")
        return True
    
    def load_private_key(self):
        """
        Load existing private key from storage
        Used on device reboot/restart
        """
        if not os.path.exists(self.key_file):
            print(f"[{self.device_id}] ⚠ No existing key found. Need to generate new keys.")
            return False
        
        print(f"[{self.device_id}] Loading existing private key from storage...")
        
        with open(self.key_file, 'rb') as f:
            pem_data = f.read()
        
        self.private_key = serialization.load_pem_private_key(
            pem_data,
            password=b'device_secure_password',
            backend=default_backend()
        )
        
        self.public_key = self.private_key.public_key()
        
        print(f"[{self.device_id}] ✓ Private key loaded successfully")
        return True
    
    def extract_public_key_pem(self):
        """
        Step 1.2: Extract public key for transmission to server
        Returns public key in PEM format (safe to transmit)
        """
        if self.public_key is None:
            raise ValueError("Public key not available. Generate keys first.")
        
        # Serialize public key to PEM format
        pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return pem.decode('utf-8')
    
    def enroll_with_server(self, server_url):
        """
        Step 1.3: Send enrollment request to Zero-Trust Server
        Transmits: device_id + public_key (NEVER private key)
        
        Args:
            server_url (str): URL of the Zero-Trust server enrollment endpoint
        """
        print(f"\n[{self.device_id}] ========== ENROLLMENT PROCESS ==========")
        print(f"[{self.device_id}] Preparing enrollment payload...")
        
        # Extract public key in PEM format
        public_key_pem = self.extract_public_key_pem()
        
        # Create enrollment payload
        enrollment_data = {
            "device_id": self.device_id,
            "public_key": public_key_pem,
            "enrollment_timestamp": datetime.utcnow().isoformat(),
            "device_type": "IoT_Simulator",
            "firmware_version": "1.0.0"
        }
        
        print(f"[{self.device_id}] Sending enrollment request to: {server_url}")
        print(f"[{self.device_id}] Device ID: {self.device_id}")
        print(f"[{self.device_id}] Public Key (first 100 chars): {public_key_pem[:100]}...")
        
        try:
            # Send POST request to server
            response = requests.post(
                f"{server_url}/enroll",
                json=enrollment_data,
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                print(f"[{self.device_id}] ✓ ENROLLMENT SUCCESSFUL")
                print(f"[{self.device_id}] Server Response: {result.get('message')}")
                print(f"[{self.device_id}] Device Status: {result.get('status')}")
                
                # Save enrollment status locally
                self._save_enrollment_status(result)
                
                return True
            else:
                print(f"[{self.device_id}] ✗ ENROLLMENT FAILED")
                print(f"[{self.device_id}] Status Code: {response.status_code}")
                print(f"[{self.device_id}] Error: {response.text}")
                return False
                
        except requests.exceptions.RequestException as e:
            print(f"[{self.device_id}] ✗ CONNECTION ERROR: {str(e)}")
            print(f"[{self.device_id}] Make sure Zero-Trust Server is running at: {server_url}")
            return False
    
    def _save_enrollment_status(self, server_response):
        """
        Save enrollment configuration locally
        """
        config = {
            "device_id": self.device_id,
            "enrolled": True,
            "enrollment_timestamp": datetime.utcnow().isoformat(),
            "server_response": server_response,
            "public_key_fingerprint": self._get_public_key_fingerprint()
        }
        
        with open(self.config_file, 'w') as f:
            json.dump(config, f, indent=2)
        
        print(f"[{self.device_id}] Enrollment status saved to: {self.config_file}")
    
    def _get_public_key_fingerprint(self):
        """
        Generate fingerprint of public key for verification
        """
        public_key_pem = self.extract_public_key_pem()
        fingerprint = hashlib.sha256(public_key_pem.encode()).hexdigest()
        return fingerprint
    
    def provision(self, server_url):
        """
        Complete device provisioning workflow
        Step 1: Check for existing keys or generate new ones
        Step 2: Store private key securely
        Step 3: Enroll with server
        
        Args:
            server_url (str): Zero-Trust server base URL
        """
        print(f"\n{'='*60}")
        print(f"PHASE 1: BASELINE CRYPTOGRAPHIC IDENTITY")
        print(f"Device: {self.device_id}")
        print(f"{'='*60}\n")
        
        # Try to load existing key first
        if not self.load_private_key():
            # No existing key, generate new one
            print(f"[{self.device_id}] First boot detected - generating new identity...")
            
            # Step 1.2: Generate ECC key pair
            self.generate_ecc_keypair()
            
            # Step 1.2: Store private key
            self.store_private_key()
        
        # Step 1.3: Enroll with server
        success = self.enroll_with_server(server_url)
        
        if success:
            print(f"\n[{self.device_id}] ✓ PROVISIONING COMPLETE")
            print(f"[{self.device_id}] Device can now cryptographically prove identity")
        else:
            print(f"\n[{self.device_id}] ✗ PROVISIONING FAILED")
        
        return success


def main():
    """
    Main function to demonstrate device provisioning
    """
    # Configuration
    ZERO_TRUST_SERVER_URL = "http://localhost:5000"  # Change to your server URL
    DEVICE_ID = "iot-device-001"  # Unique device identifier
    
    print("="*60)
    print("IoT DEVICE SIMULATOR - PHASE 1")
    print("Baseline Cryptographic Identity Implementation")
    print("="*60)
    
    # Create device instance
    device = IoTDeviceSimulator(device_id=DEVICE_ID)
    
    # Provision device (generate keys + enroll)
    device.provision(ZERO_TRUST_SERVER_URL)
    
    print("\n" + "="*60)
    print("PHASE 1 DEMONSTRATION COMPLETE")
    print("="*60)


if __name__ == "__main__":
    main()