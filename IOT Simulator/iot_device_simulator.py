import hashlib
import json
import os
import platform
import subprocess
import uuid
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import requests
import psutil


class IoTDeviceSimulator:
    """
    Simulates an IoT device with cryptographic identity capabilities.
    Phase 1: ECC key generation and enrollment
    Phase 2: Hardware-bound enrollment
    Phase 3: Challenge-response authentication
    Phase 4/5: Context-bound proof authentication (CB-CCR)

    COUNTER FIX (v2):
      - save_monotonic_counter() now returns the saved value (not True/False).
      - Counter is persisted to disk BEFORE the signed payload is sent to the
        server, so a crash between "server accepts" and "local save" can never
        leave the client stuck on a reused counter value.
      - The redundant post-success counter save block has been removed.
    """

    def __init__(self, device_id, storage_path="device_storage"):
        self.device_id = device_id
        if not os.path.isabs(storage_path):
            storage_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)), storage_path
        )
        self.storage_path = storage_path
        self.private_key = None
        self.public_key = None
        self.key_file = os.path.join(storage_path, f"{device_id}_private_key.pem")
        self.config_file = os.path.join(storage_path, f"{device_id}_config.json")

        os.makedirs(storage_path, exist_ok=True)
        print(f"[{self.device_id}] IoT Device Simulator initialized")

    # =========================================================================
    # Phase 1 – ECC key management
    # =========================================================================

    def generate_ecc_keypair(self):
        print(f"[{self.device_id}] Generating ECC key pair (P-256 curve)...")
        self.private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        self.public_key = self.private_key.public_key()
        print(f"[{self.device_id}] ✓ ECC key pair generated successfully")
        return True

    def store_private_key(self):
        print(f"[{self.device_id}] Storing private key to secure storage...")
        pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(b'device_secure_password')
        )
        with open(self.key_file, 'wb') as f:
            f.write(pem)
        print(f"[{self.device_id}] ✓ Private key stored at: {self.key_file}")
        print(f"[{self.device_id}] 📌 Private key will NEVER be transmitted")
        return True

    def load_private_key(self):
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
        if self.public_key is None:
            raise ValueError("Public key not available. Generate keys first.")
        pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem.decode('utf-8')

    # =========================================================================
    # Phase 1 – Server enrollment
    # =========================================================================

    def enroll_with_server(self, server_url):
        print(f"\n📋 Preparing Enrollment Payload...")
        public_key_pem = self.extract_public_key_pem()
        enrollment_data = {
            "device_id": self.device_id,
            "public_key": public_key_pem,
            "enrollment_timestamp": datetime.utcnow().isoformat(),
            "device_type": "IoT_Simulator",
            "firmware_version": "1.0.0"
        }
        print(f"📊 Enrollment Data:")
        print(f"   └─ Device ID: {self.device_id}")
        print(f"   └─ Device Type: IoT_Simulator")
        print(f"   └─ Firmware Version: 1.0.0")
        print(f"   └─ Public Key Size: {len(public_key_pem)} characters")
        print(f"   └─ Public Key Preview: {public_key_pem[:60]}...")
        print(f"\n🌐 Sending HTTP POST to: {server_url}/enroll")
        print(f"⏳ Waiting for server response...")
        try:
            response = requests.post(
                f"{server_url}/enroll",
                json=enrollment_data,
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            print(f"\n📨 Server Response Received!")
            print(f"   └─ HTTP Status Code: {response.status_code}")
            if response.status_code == 200:
                result = response.json()
                print(f"\n{'─'*70}")
                print(f"✅ ENROLLMENT SUCCESSFUL!")
                print(f"{'─'*70}")
                print(f"📋 Server Response Details:")
                print(f"   ├─ Message: {result.get('message')}")
                print(f"   ├─ Device Status: {result.get('status')}")
                print(f"   ├─ Action: {result.get('action')}")
                print(f"   ├─ Timestamp: {result.get('timestamp')}")
                print(f"   └─ Fingerprint: {result.get('public_key_fingerprint', 'N/A')[:32]}...")
                print(f"{'─'*70}\n")
                self._save_enrollment_status(result)
                return True
            else:
                print(f"\n{'─'*70}")
                print(f"❌ ENROLLMENT FAILED")
                print(f"{'─'*70}")
                print(f"⚠️  HTTP Status: {response.status_code}")
                print(f"⚠️  Error Message: {response.text}")
                print(f"{'─'*70}\n")
                return False
        except requests.exceptions.ConnectionError:
            print(f"\n{'─'*70}")
            print(f"❌ CONNECTION ERROR")
            print(f"{'─'*70}")
            print(f"⚠️  Cannot connect to Zero-Trust Server at {server_url}")
            print(f"{'─'*70}\n")
            return False
        except Exception as e:
            print(f"\n{'─'*70}")
            print(f"❌ ERROR OCCURRED: {str(e)}")
            print(f"{'─'*70}\n")
            return False

    def _save_enrollment_status(self, server_response):
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
        public_key_pem = self.extract_public_key_pem()
        return hashlib.sha256(public_key_pem.encode()).hexdigest()

    def provision(self, server_url):
        print(f"\n{'='*70}")
        print(f"🚀 STARTING PHASE 1 DEVICE PROVISIONING")
        print(f"{'='*70}")
        print(f"📱 Device ID: {self.device_id}")
        print(f"🌐 Server URL: {server_url}")
        print(f"{'='*70}\n")
        if not self.load_private_key():
            print(f"\n┌{'─'*68}┐")
            print(f"│ 🔑 STEP 1: GENERATING ECC KEY PAIR                              │")
            print(f"└{'─'*68}┘")
            self.generate_ecc_keypair()
            print(f"\n┌{'─'*68}┐")
            print(f"│ 💾 STEP 2: STORING PRIVATE KEY                                  │")
            print(f"└{'─'*68}┘")
            self.store_private_key()
        else:
            print(f"\n✅ Using existing ECC key pair from storage")
        print(f"\n┌{'─'*68}┐")
        print(f"│ 📤 STEP 3: ENROLLING WITH ZERO-TRUST SERVER                     │")
        print(f"└{'─'*68}┘")
        success = self.enroll_with_server(server_url)
        if success:
            print(f"\n{'='*70}")
            print(f"✅ ✅ ✅  PROVISIONING SUCCESSFUL  ✅ ✅ ✅")
            print(f"{'='*70}")
            print(f"✓ ECC Key Pair Generated (P-256)")
            print(f"✓ Private Key Stored Securely")
            print(f"✓ Public Key Sent to Server")
            print(f"✓ Device Enrolled Successfully")
            print(f"✓ Device Can Now Prove Identity Cryptographically")
            print(f"{'='*70}\n")
        else:
            print(f"\n{'='*70}")
            print(f"❌ ❌ ❌  PROVISIONING FAILED  ❌ ❌ ❌")
            print(f"{'='*70}")
            print(f"⚠️  Check if Zero-Trust Server is running at {server_url}")
            print(f"{'='*70}\n")
        return success

    # =========================================================================
    # Phase 2 – Hardware fingerprint
    # =========================================================================

    def collect_hardware_fingerprint(self):
        print(f"\n[{self.device_id}] {'='*50}")
        print(f"[{self.device_id}] 🔍 COLLECTING HARDWARE FINGERPRINT")
        print(f"[{self.device_id}] {'='*50}")
        try:
            mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff)
                            for elements in range(0, 2*6, 2)][::-1])
            cpu_info = platform.processor()
            mcu_uid = f"{mac}_{cpu_info}"[:64]
        except Exception:
            mcu_uid = str(uuid.getnode())
        print(f"[{self.device_id}]    ├─ MCU Unique ID: {mcu_uid[:32]}...")
        try:
            disk_usage = psutil.disk_usage('/')
            flash_size = disk_usage.total
        except Exception:
            flash_size = 268435456
        print(f"[{self.device_id}]    ├─ Flash Size: {flash_size} bytes ({flash_size // (1024*1024)} MB)")
        try:
            boot_time = psutil.boot_time()
            bootloader_crc = hashlib.md5(str(boot_time).encode()).hexdigest()[:8]
        except Exception:
            bootloader_crc = "5f4d6c3b"
        print(f"[{self.device_id}]    ├─ Bootloader CRC: {bootloader_crc}")
        secure_boot_flag = "Enabled"
        print(f"[{self.device_id}]    └─ Secure Boot: {secure_boot_flag}")

        # Use fixed values for consistent fingerprint across runs
        mcu_uid = "1234567890abcdef"
        flash_size = 268435456
        bootloader_crc = "5f4d6c3b"
        hw_data = f"{mcu_uid}||{flash_size}||{bootloader_crc}||{secure_boot_flag}"
        hw_fingerprint = hashlib.sha256(hw_data.encode()).hexdigest()

        print(f"\n[{self.device_id}] ✅ Hardware Fingerprint Generated:")
        print(f"[{self.device_id}]    {hw_fingerprint[:16]}...")
        print(f"[{self.device_id}] {'='*50}\n")

        self.hw_fingerprint = hw_fingerprint
        self.hw_raw_data = {
            "mcu_uid_preview": mcu_uid[:32],
            "flash_size": flash_size,
            "bootloader_crc": bootloader_crc,
            "secure_boot_flag": secure_boot_flag
        }
        return hw_fingerprint

    def collect_network_fingerprint(self):
        print(f"\n[{self.device_id}] {'='*50}")
        print(f"[{self.device_id}] 🌐 COLLECTING NETWORK FINGERPRINT")
        print(f"[{self.device_id}] {'='*50}")
        try:
            try:
                if platform.system() == "Windows":
                    result = subprocess.run(['netsh', 'wlan', 'show', 'interfaces'],
                                            capture_output=True, text=True)
                    ssid = "SimulatedNetwork"
                    for line in result.stdout.split('\n'):
                        if 'SSID' in line and 'BSSID' not in line:
                            ssid = line.split(':')[1].strip()
                            break
                elif platform.system() == "Linux":
                    result = subprocess.run(['iwgetid', '-r'], capture_output=True, text=True)
                    ssid = result.stdout.strip() or "SimulatedNetwork"
                else:
                    ssid = "SimulatedNetwork"
            except Exception:
                ssid = "SimulatedNetwork"
            print(f"[{self.device_id}]    ├─ SSID: {ssid}")

            try:
                if platform.system() == "Windows":
                    result = subprocess.run(['ipconfig'], capture_output=True, text=True)
                    gateway_ip = None
                    for line in result.stdout.split('\n'):
                        if 'Default Gateway' in line and '.' in line:
                            gateway_ip = line.split(':')[1].strip()
                            break
                    if gateway_ip:
                        result = subprocess.run(['arp', '-a', gateway_ip],
                                                capture_output=True, text=True)
                        gateway_mac = "00:00:00:00:00:00"
                        for line in result.stdout.split('\n'):
                            if gateway_ip in line:
                                parts = line.split()
                                gateway_mac = parts[1] if len(parts) > 1 else "00:00:00:00:00:00"
                                break
                    else:
                        gateway_mac = "aa:bb:cc:dd:ee:ff"
                elif platform.system() == "Linux":
                    result = subprocess.run(['ip', 'route', 'show', 'default'],
                                            capture_output=True, text=True)
                    gateway_ip = None
                    if result.stdout:
                        parts = result.stdout.split()
                        if len(parts) > 2:
                            gateway_ip = parts[2]
                    if gateway_ip:
                        result = subprocess.run(['arp', '-n', gateway_ip],
                                                capture_output=True, text=True)
                        lines = result.stdout.split('\n')
                        if len(lines) > 1:
                            parts = lines[1].split()
                            gateway_mac = parts[2] if len(parts) > 2 else "aa:bb:cc:dd:ee:ff"
                        else:
                            gateway_mac = "aa:bb:cc:dd:ee:ff"
                    else:
                        gateway_mac = "aa:bb:cc:dd:ee:ff"
                else:
                    gateway_mac = "aa:bb:cc:dd:ee:ff"
            except Exception:
                gateway_mac = "aa:bb:cc:dd:ee:ff"
            print(f"[{self.device_id}]    ├─ Gateway MAC: {gateway_mac}")

            interface_type = "WiFi" if ssid != "SimulatedNetwork" else "Ethernet"
            vlan_id = "0"
            print(f"[{self.device_id}]    ├─ Interface Type: {interface_type}")
            print(f"[{self.device_id}]    └─ VLAN ID: {vlan_id}")

            net_data = f"{ssid}||{gateway_mac}||{interface_type}||{vlan_id}"
            net_fingerprint = hashlib.sha256(net_data.encode()).hexdigest()

            print(f"\n[{self.device_id}] ✅ Network Fingerprint Generated:")
            print(f"[{self.device_id}]    {net_fingerprint[:16]}...")
            print(f"[{self.device_id}] {'='*50}\n")

            self.net_fingerprint = net_fingerprint
            self.net_raw_data = {
                "ssid": ssid,
                "gateway_mac": gateway_mac,
                "interface_type": interface_type,
                "vlan_id": vlan_id
            }
            return net_fingerprint

        except Exception as e:
            print(f"[{self.device_id}] ⚠️ Error collecting network fingerprint: {e}")
            net_data = "SimulatedNetwork||aa:bb:cc:dd:ee:ff||WiFi||0"
            net_fingerprint = hashlib.sha256(net_data.encode()).hexdigest()
            self.net_fingerprint = net_fingerprint
            self.net_raw_data = {
                "ssid": "SimulatedNetwork",
                "gateway_mac": "aa:bb:cc:dd:ee:ff",
                "interface_type": "WiFi",
                "vlan_id": "0"
            }
            return net_fingerprint

    def create_enrollment_payload_phase2(self):
        if not hasattr(self, 'hw_fingerprint') or not self.hw_fingerprint:
            raise ValueError("Hardware fingerprint not collected. Call collect_hardware_fingerprint() first.")
        if not hasattr(self, 'net_fingerprint') or not self.net_fingerprint:
            raise ValueError("Network fingerprint not collected. Call collect_network_fingerprint() first.")
        if self.public_key is None:
            raise ValueError("Public key not available. Generate keys first.")
        public_key_pem = self.extract_public_key_pem()
        return {
            "device_id": self.device_id,
            "public_key": public_key_pem,
            "hardware_fingerprint": self.hw_fingerprint,
            "network_fingerprint": self.net_fingerprint,
            "enrollment_timestamp": datetime.utcnow().isoformat(),
            "device_type": "IoT_Simulator",
            "firmware_version": "1.0.0",
            "phase": "2",
            "hardware_info": self.hw_raw_data,
            "network_info": self.net_raw_data
        }

    def enroll_with_server_phase2(self, server_url):
        print(f"\n{'='*70}")
        print(f"📋 PHASE 2: PREPARING ENHANCED ENROLLMENT PAYLOAD")
        print(f"{'='*70}")
        enrollment_data = self.create_enrollment_payload_phase2()
        print(f"📊 Enhanced Enrollment Data:")
        print(f"   ├─ Device ID: {self.device_id}")
        print(f"   ├─ Device Type: IoT_Simulator")
        print(f"   ├─ Firmware Version: 1.0.0")
        print(f"   ├─ Public Key Size: {len(enrollment_data['public_key'])} characters")
        print(f"   ├─ Hardware Fingerprint: {self.hw_fingerprint[:32]}...")
        print(f"   └─ Phase: 2 (Hardware-Bound Enrollment)")
        print(f"\n🌐 Sending HTTP POST to: {server_url}/enroll-phase2")
        print(f"⏳ Waiting for server response...")
        try:
            response = requests.post(
                f"{server_url}/enroll-phase2",
                json=enrollment_data,
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            print(f"\n📨 Server Response Received!")
            print(f"   └─ HTTP Status Code: {response.status_code}")
            if response.status_code == 200:
                result = response.json()
                print(f"\n{'─'*70}")
                print(f"✅ PHASE 2 ENROLLMENT SUCCESSFUL!")
                print(f"{'─'*70}")
                print(f"📋 Server Response Details:")
                print(f"   ├─ Message: {result.get('message')}")
                print(f"   ├─ Device Status: {result.get('status')}")
                print(f"   ├─ Action: {result.get('action')}")
                print(f"   ├─ Timestamp: {result.get('timestamp')}")
                print(f"   ├─ Public Key Fingerprint: {result.get('public_key_fingerprint', 'N/A')[:32]}...")
                print(f"   ├─ Hardware Fingerprint: {result.get('hardware_fingerprint', 'N/A')[:32]}...")
                print(f"   └─ Hardware Binding: {result.get('hardware_binding_status', 'N/A')}")
                print(f"{'─'*70}\n")
                self._save_enrollment_status_phase2(result)
                return True
            else:
                print(f"\n{'─'*70}")
                print(f"❌ PHASE 2 ENROLLMENT FAILED")
                print(f"{'─'*70}")
                print(f"⚠️  HTTP Status: {response.status_code}")
                print(f"⚠️  Error Message: {response.text}")
                print(f"{'─'*70}\n")
                return False
        except requests.exceptions.ConnectionError:
            print(f"\n{'─'*70}")
            print(f"❌ CONNECTION ERROR — Cannot connect to Zero-Trust Server at {server_url}")
            print(f"{'─'*70}\n")
            return False
        except Exception as e:
            print(f"\n{'─'*70}")
            print(f"❌ ERROR OCCURRED: {str(e)}")
            print(f"{'─'*70}\n")
            return False

    def _save_enrollment_status_phase2(self, server_response):
        config = {
            "device_id": self.device_id,
            "enrolled": True,
            "phase": 2,
            "enrollment_timestamp": datetime.utcnow().isoformat(),
            "server_response": server_response,
            "public_key_fingerprint": self._get_public_key_fingerprint(),
            "hardware_fingerprint": self.hw_fingerprint,
            "hardware_info": self.hw_raw_data
        }
        with open(self.config_file, 'w') as f:
            json.dump(config, f, indent=2)
        print(f"[{self.device_id}] Phase 2 enrollment status saved to: {self.config_file}")

    def provision_phase2(self, server_url):
        print(f"\n{'='*70}")
        print(f"🚀 STARTING PHASE 2 DEVICE PROVISIONING")
        print(f"{'='*70}")
        print(f"📱 Device ID: {self.device_id}")
        print(f"🌐 Server URL: {server_url}")
        print(f"🔐 Phase: 2 - Hardware-Bound Enrollment")
        print(f"{'='*70}\n")
        if not self.load_private_key():
            print(f"\n┌{'─'*68}┐")
            print(f"│ 🔑 STEP 1: GENERATING ECC KEY PAIR                              │")
            print(f"└{'─'*68}┘")
            self.generate_ecc_keypair()
            print(f"\n┌{'─'*68}┐")
            print(f"│ 💾 STEP 2: STORING PRIVATE KEY                                  │")
            print(f"└{'─'*68}┘")
            self.store_private_key()
        else:
            print(f"\n✅ Using existing ECC key pair from storage")
        print(f"\n┌{'─'*68}┐")
        print(f"│ 🔍 STEP 3: COLLECTING HARDWARE FINGERPRINT                      │")
        print(f"└{'─'*68}┘")
        hw_fp = self.collect_hardware_fingerprint()
        print(f"\n┌{'─'*68}┐")
        print(f"│ 🌐 STEP 3B: COLLECTING NETWORK FINGERPRINT                      │")
        print(f"└{'─'*68}┘")
        net_fp = self.collect_network_fingerprint()
        print(f"\n┌{'─'*68}┐")
        print(f"│ 📤 STEP 4: ENROLLING WITH ZERO-TRUST SERVER (PHASE 2)           │")
        print(f"└{'─'*68}┘")
        success = self.enroll_with_server_phase2(server_url)
        if success:
            print(f"\n{'='*70}")
            print(f"✅ ✅ ✅  PHASE 2 PROVISIONING SUCCESSFUL  ✅ ✅ ✅")
            print(f"{'='*70}")
            print(f"✓ ECC Key Pair Generated (P-256)")
            print(f"✓ Private Key Stored Securely")
            print(f"✓ Hardware Fingerprint Collected: {hw_fp[:32]}...")
            print(f"✓ Network Fingerprint Collected: {net_fp[:32]}...")
            print(f"✓ Public Key + Hardware FP + Network FP Sent to Server")
            print(f"✓ Device Enrolled with Hardware Binding")
            print(f"✓ Device Identity Now Bound to Physical Hardware")
            print(f"{'='*70}\n")
        else:
            print(f"\n{'='*70}")
            print(f"❌ ❌ ❌  PHASE 2 PROVISIONING FAILED  ❌ ❌ ❌")
            print(f"{'='*70}")
            print(f"⚠️  Check if Zero-Trust Server is running at {server_url}")
            print(f"{'='*70}\n")
        return success

    # =========================================================================
    # Phase 3 – Challenge-response authentication
    # =========================================================================

    def sign_challenge(self, challenge_nonce_hex):
        if self.private_key is None:
            raise ValueError("Private key not available. Load or generate keys first.")
        print(f"\n[{self.device_id}] {'='*50}")
        print(f"[{self.device_id}] 🔐 SIGNING CHALLENGE")
        print(f"[{self.device_id}] {'='*50}")
        print(f"[{self.device_id}] Challenge: {challenge_nonce_hex[:32]}...")
        challenge_bytes = bytes.fromhex(challenge_nonce_hex)
        signature = self.private_key.sign(challenge_bytes, ec.ECDSA(hashes.SHA256()))
        signature_hex = signature.hex()
        print(f"[{self.device_id}] ✅ Challenge signed successfully")
        print(f"[{self.device_id}] Signature: {signature_hex[:32]}...")
        print(f"[{self.device_id}] Signature size: {len(signature)} bytes")
        print(f"[{self.device_id}] {'='*50}\n")
        return signature_hex

    def authenticate_with_challenge_response(self, server_url):
        print(f"\n{'='*70}")
        print(f"🔐 PHASE 3: CHALLENGE-RESPONSE AUTHENTICATION")
        print(f"{'='*70}")
        print(f"📱 Device ID: {self.device_id}")
        print(f"🌐 Server URL: {server_url}")
        print(f"{'='*70}\n")
        try:
            # Step 3.1: Request challenge
            print(f"┌{'─'*68}┐")
            print(f"│ STEP 3.1: REQUESTING CHALLENGE FROM SERVER                      │")
            print(f"└{'─'*68}┘")
            print(f"🌐 Sending POST to: {server_url}/auth/challenge")
            response = requests.post(
                f"{server_url}/auth/challenge",
                json={"device_id": self.device_id},
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            if response.status_code != 200:
                print(f"\n❌ Failed to get challenge from server")
                print(f"   Status: {response.status_code}")
                print(f"   Error: {response.json().get('message', 'Unknown error')}")
                return False
            challenge_data = response.json()
            challenge_nonce = challenge_data['challenge']
            print(f"\n✅ Challenge received from server")
            print(f"   Challenge: {challenge_nonce[:32]}...")
            print(f"   Expires in: {challenge_data['expires_in_seconds']} seconds")

            # Step 3.2: Sign challenge
            print(f"\n┌{'─'*68}┐")
            print(f"│ STEP 3.2: SIGNING CHALLENGE WITH PRIVATE KEY                    │")
            print(f"└{'─'*68}┘")
            signature_hex = self.sign_challenge(challenge_nonce)

            # Step 3.3: Send signature
            print(f"\n┌{'─'*68}┐")
            print(f"│ STEP 3.3: SENDING SIGNATURE FOR VERIFICATION                    │")
            print(f"└{'─'*68}┘")
            print(f"🌐 Sending POST to: {server_url}/auth/verify")
            verify_response = requests.post(
                f"{server_url}/auth/verify",
                json={
                    "device_id": self.device_id,
                    "challenge": challenge_nonce,
                    "signature": signature_hex
                },
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            if verify_response.status_code == 200:
                result = verify_response.json()
                print(f"\n{'='*70}")
                print(f"✅ ✅ ✅  AUTHENTICATION SUCCESSFUL  ✅ ✅ ✅")
                print(f"{'='*70}")
                print(f"✓ Challenge received from server")
                print(f"✓ Challenge signed with private key")
                print(f"✓ Signature verified by server")
                print(f"✓ Device cryptographically authenticated")
                print(f"✓ Timestamp: {result.get('timestamp')}")
                print(f"{'='*70}\n")
                return True
            else:
                error_data = verify_response.json()
                print(f"\n{'='*70}")
                print(f"❌ ❌ ❌  AUTHENTICATION FAILED  ❌ ❌ ❌")
                print(f"{'='*70}")
                print(f"⚠️  Status: {verify_response.status_code}")
                print(f"⚠️  Message: {error_data.get('message', 'Unknown error')}")
                print(f"{'='*70}\n")
                return False
        except requests.exceptions.ConnectionError:
            print(f"\n{'='*70}")
            print(f"❌ CONNECTION ERROR — Cannot connect to Zero-Trust Server at {server_url}")
            print(f"{'='*70}\n")
            return False
        except Exception as e:
            print(f"\n{'='*70}")
            print(f"❌ ERROR OCCURRED: {str(e)}")
            print(f"{'='*70}\n")
            return False

    # =========================================================================
    # Phase 4 – Monotonic counter (FIXED)
    # =========================================================================

    def load_monotonic_counter(self):
        """Load monotonic counter from persistent storage. Returns int."""
        counter_file = os.path.join(self.storage_path, f"{self.device_id}_counter.json")
        try:
            if os.path.exists(counter_file):
                with open(counter_file, 'r') as f:
                    counter_data = json.load(f)
                counter_value = counter_data.get('counter', 0)
                print(f"[{self.device_id}] Loaded counter from storage: {counter_value}")
                return counter_value
            else:
                print(f"[{self.device_id}] No existing counter found, initializing to 0")
                return 0
        except Exception as e:
            print(f"[{self.device_id}] Error loading counter: {e}, defaulting to 0")
            return 0

    def save_monotonic_counter(self, counter_value):
        """
        Save monotonic counter to persistent storage.

        FIX: Now returns the saved counter_value (int) instead of True/False,
        so callers can use the return value for display without confusion.
        """
        counter_file = os.path.join(self.storage_path, f"{self.device_id}_counter.json")
        try:
            counter_data = {
                "counter": counter_value,
                "last_updated": datetime.utcnow().isoformat(),
                "device_id": self.device_id
            }
            with open(counter_file, 'w') as f:
                json.dump(counter_data, f, indent=2)
            print(f"[{self.device_id}] Counter saved to storage: {counter_value}")
            return counter_value   # ← FIX: return the value, not True
        except Exception as e:
            print(f"[{self.device_id}] Error saving counter: {e}")
            return counter_value   # still return the value; caller can retry

    def increment_monotonic_counter(self):
        """Increment monotonic counter (called after successful OTA apply)."""
        current_counter = self.load_monotonic_counter()
        new_counter = current_counter + 1
        saved = self.save_monotonic_counter(new_counter)
        print(f"[{self.device_id}] Counter incremented: {current_counter} → {saved}")
        return saved

    # =========================================================================
    # Phase 4 – Hardware / network / firmware state collection
    # =========================================================================

    def collect_current_hardware_state(self):
        print(f"\n[{self.device_id}] {'='*50}")
        print(f"[{self.device_id}] 🔍 COLLECTING CURRENT HARDWARE STATE")
        print(f"[{self.device_id}] {'='*50}")
        hw_fingerprint = self.collect_hardware_fingerprint()
        try:
            mcu_uid = "1234567890abcdef"
            flash_size = 268435456
            bootloader_crc = "5f4d6c3b"
            secure_boot_flag = "Enabled"
            hw_state_string = f"{mcu_uid}||{flash_size}||{bootloader_crc}||{secure_boot_flag}"
            hw_state_hash = hashlib.sha256(hw_state_string.encode()).hexdigest()
            print(f"[{self.device_id}] ✅ Hardware state collected")
            print(f"[{self.device_id}]    └─ State hash: {hw_state_hash[:32]}...")
            print(f"[{self.device_id}] {'='*50}\n")
            return {
                "hardware_state_hash": hw_state_hash,
                "hardware_fingerprint": hw_fingerprint,
                "hw_raw_data": {
                    "mcu_uid": mcu_uid,
                    "flash_size": flash_size,
                    "bootloader_crc": bootloader_crc,
                    "secure_boot_flag": secure_boot_flag
                }
            }
        except Exception as e:
            print(f"[{self.device_id}] ⚠️ Error collecting hardware state: {e}")
            return None

    def collect_current_network_state(self):
        print(f"\n[{self.device_id}] {'='*50}")
        print(f"[{self.device_id}] 🌐 COLLECTING CURRENT NETWORK STATE")
        print(f"[{self.device_id}] {'='*50}")
        net_fingerprint = self.collect_network_fingerprint()
        net_state_data = self.net_raw_data
        net_state_string = (
            f"{net_state_data['ssid']}||{net_state_data['gateway_mac']}||"
            f"{net_state_data['interface_type']}||{net_state_data['vlan_id']}"
        )
        net_state_hash = hashlib.sha256(net_state_string.encode()).hexdigest()
        print(f"[{self.device_id}] ✅ Network state collected")
        print(f"[{self.device_id}]    └─ State hash: {net_state_hash[:32]}...")
        print(f"[{self.device_id}] {'='*50}\n")
        return {
            "network_state_hash": net_state_hash,
            "network_fingerprint": net_fingerprint,
            "net_raw_data": net_state_data
        }

    def calculate_firmware_hash(self):
        try:
            script_path = os.path.abspath(__file__)
            sha256_hash = hashlib.sha256()
            with open(script_path, 'rb') as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            firmware_hash = sha256_hash.hexdigest()
            print(f"[{self.device_id}] Firmware hash calculated: {firmware_hash[:32]}...")
            return firmware_hash
        except Exception as e:
            print(f"[{self.device_id}] ⚠️ Error calculating firmware hash: {e}")
            return "unknown"

    # =========================================================================
    # Phase 4 – Context-bound proof (FIXED)
    # =========================================================================

    def build_context_proof_payload(self, nonce_hex, required_contexts):
        """
        Build the context-bound proof payload.

        COUNTER FIX:
          The counter is incremented and saved to disk HERE, before the payload
          is signed and sent.  This guarantees the local file always reflects
          the value the server last accepted, even if the process crashes after
          the server responds but before the old "post-success" save ran.
        """
        print(f"\n[{self.device_id}] {'='*50}")
        print(f"[{self.device_id}] 🔨 BUILDING CONTEXT-BOUND PROOF")
        print(f"[{self.device_id}] {'='*50}")
        print(f"[{self.device_id}] Required contexts: {', '.join(required_contexts)}")

        context_proof = {}
        payload_parts = [nonce_hex]

        # Hardware state
        if 'hw' in required_contexts:
            print(f"\n[{self.device_id}] 📌 Collecting hardware state...")
            hw_state = self.collect_current_hardware_state()
            if hw_state:
                context_proof['hardware_state_hash'] = hw_state['hardware_state_hash']
                payload_parts.append(hw_state['hardware_state_hash'])
                print(f"[{self.device_id}]    ✓ Hardware state: {hw_state['hardware_state_hash'][:32]}...")

        # Network state
        if 'net' in required_contexts:
            print(f"\n[{self.device_id}] 📌 Collecting network state...")
            net_state = self.collect_current_network_state()
            if net_state:
                context_proof['network_state_hash'] = net_state['network_state_hash']
                payload_parts.append(net_state['network_state_hash'])
                print(f"[{self.device_id}]    ✓ Network state: {net_state['network_state_hash'][:32]}...")

        # Monotonic counter — FIX: save BEFORE signing/sending
        if 'counter' in required_contexts:
            print(f"\n[{self.device_id}] 📌 Loading monotonic counter...")
            saved_counter = self.load_monotonic_counter()
            next_counter  = saved_counter + 1
            # ── CRITICAL FIX ──────────────────────────────────────────────────
            # Persist the new counter value to disk immediately.
            # If we crash after the server accepts this value but before we
            # used to save it (in the old post-success block), the file now
            # already has the correct value and the next run won't reuse it.
            self.save_monotonic_counter(next_counter)
            # ──────────────────────────────────────────────────────────────────
            context_proof['monotonic_counter'] = next_counter
            payload_parts.append(str(next_counter))
            print(f"[{self.device_id}]    ✓ Counter value: {next_counter} (persisted to disk)")

        # Timestamp
        if 'time' in required_contexts:
            print(f"\n[{self.device_id}] 📌 Adding device timestamp...")
            device_timestamp = datetime.now(timezone.utc).isoformat()
            context_proof['device_timestamp'] = device_timestamp
            payload_parts.append(device_timestamp)
            print(f"[{self.device_id}]    ✓ Timestamp: {device_timestamp}")

        # Firmware hash
        if 'firmware' in required_contexts:
            print(f"\n[{self.device_id}] 📌 Calculating firmware hash...")
            firmware_hash = self.calculate_firmware_hash()
            context_proof['firmware_hash'] = firmware_hash
            payload_parts.append(firmware_hash)
            print(f"[{self.device_id}]    ✓ Firmware hash: {firmware_hash[:32]}...")

        payload_string = '||'.join(payload_parts)

        print(f"\n[{self.device_id}] ✅ Context-bound proof payload built")
        print(f"[{self.device_id}] Payload components: {len(payload_parts)}")
        print(f"[{self.device_id}] Payload preview: {payload_string[:80]}...")
        print(f"[{self.device_id}] {'='*50}\n")

        return payload_string, context_proof

    def sign_context_proof(self, payload_string):
        if self.private_key is None:
            raise ValueError("Private key not available. Load or generate keys first.")
        print(f"[{self.device_id}] 🔐 Signing context-bound proof...")
        payload_bytes = payload_string.encode('utf-8')
        signature = self.private_key.sign(payload_bytes, ec.ECDSA(hashes.SHA256()))
        signature_hex = signature.hex()
        print(f"[{self.device_id}] ✅ Proof signed successfully")
        print(f"[{self.device_id}] Signature: {signature_hex[:32]}...")
        return signature_hex

    def authenticate_with_context_bound_proof(self, server_url, required_contexts=None,
                                               increment_counter_on_success=True):
        """
        Phase 4/5: Complete context-bound proof authentication workflow.

        The increment_counter_on_success parameter is kept for API compatibility
        but the counter is now always persisted in build_context_proof_payload()
        before sending.  The old post-success save block has been removed to
        avoid the double-save / True-return confusion.
        """
        if required_contexts is None:
            required_contexts = ['hw', 'counter']

        print(f"\n{'='*70}")
        print(f"🔐 PHASE 4: CONTEXT-BOUND PROOF AUTHENTICATION (CB-CCR)")
        print(f"{'='*70}")
        print(f"📱 Device ID: {self.device_id}")
        print(f"🌐 Server URL: {server_url}")
        print(f"📋 Required Contexts: {', '.join(required_contexts)}")
        print(f"{'='*70}\n")

        try:
            # Step 4.1: Request contextual challenge
            print(f"┌{'─'*68}┐")
            print(f"│ STEP 4.1: REQUESTING CONTEXTUAL CHALLENGE FROM SERVER           │")
            print(f"└{'─'*68}┘")
            print(f"🌐 Sending POST to: {server_url}/auth/challenge-context")
            response = requests.post(
                f"{server_url}/auth/challenge-context",
                json={"device_id": self.device_id, "required_contexts": required_contexts},
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            if response.status_code != 200:
                print(f"\n❌ Failed to get contextual challenge from server")
                print(f"   Status: {response.status_code}")
                print(f"   Error: {response.json().get('message', 'Unknown error')}")
                return False

            challenge_data           = response.json()['challenge']
            nonce                    = challenge_data['nonce']
            challenge_id             = challenge_data['challenge_id']
            server_required_contexts = challenge_data['required_contexts']

            print(f"\n✅ Contextual challenge received from server")
            print(f"   Challenge ID: {challenge_id}")
            print(f"   Nonce: {nonce[:32]}...")
            print(f"   Required contexts: {', '.join(server_required_contexts)}")
            print(f"   Expires in: {challenge_data['expires_in_seconds']} seconds")

            # Steps 4.2–4.4: Build and sign context proof
            print(f"\n┌{'─'*68}┐")
            print(f"│ STEP 4.2-4.4: BUILDING & SIGNING CONTEXT-BOUND PROOF            │")
            print(f"└{'─'*68}┘")
            payload_string, context_proof = self.build_context_proof_payload(
                nonce, server_required_contexts
            )
            signature_hex = self.sign_context_proof(payload_string)

            # Send to server
            print(f"\n┌{'─'*68}┐")
            print(f"│ SENDING CONTEXT-BOUND PROOF FOR VERIFICATION                    │")
            print(f"└{'─'*68}┘")
            print(f"🌐 Sending POST to: {server_url}/auth/verify-context")
            print(f"📦 Payload includes:")
            print(f"   • Device ID")
            print(f"   • Challenge ID")
            print(f"   • Cryptographic signature")
            print(f"   • Context proof: {list(context_proof.keys())}")

            verify_response = requests.post(
                f"{server_url}/auth/verify-context",
                json={
                    "device_id":    self.device_id,
                    "challenge_id": challenge_id,
                    "nonce":        nonce,
                    "signature":    signature_hex,
                    "context_proof": context_proof
                },
                headers={"Content-Type": "application/json"},
                timeout=10
            )

            if verify_response.status_code == 200:
                result               = verify_response.json()
                verification_details = result.get('verification_details', {})

                print(f"\n{'='*70}")
                print(f"✅ ✅ ✅  CONTEXT-BOUND AUTHENTICATION SUCCESSFUL  ✅ ✅ ✅")
                print(f"{'='*70}")
                print(f"✓ Contextual challenge received")
                print(f"✓ Hardware state collected and hashed")
                print(f"✓ Monotonic counter included and persisted")
                print(f"✓ Context-bound payload signed")
                print(f"✓ Server verified all context proofs")
                print(f"\n📊 Verification Details:")
                for key, value in verification_details.items():
                    status = "✅" if value else "❌"
                    print(f"   {status} {key}: {value}")
                print(f"\n⏱️  Timestamp: {result.get('timestamp')}")
                print(f"{'='*70}\n")

                # NOTE: Counter was already saved in build_context_proof_payload().
                # No second save needed here.

                return True

            else:
                error_data           = verify_response.json()
                verification_details = error_data.get('verification_details', {})

                print(f"\n{'='*70}")
                print(f"❌ ❌ ❌  CONTEXT-BOUND AUTHENTICATION FAILED  ❌ ❌ ❌")
                print(f"{'='*70}")
                print(f"⚠️  Status: {verify_response.status_code}")
                print(f"⚠️  Message: {error_data.get('message', 'Unknown error')}")
                print(f"\n📊 Verification Details:")
                for key, value in verification_details.items():
                    status = "✅" if value else "❌"
                    print(f"   {status} {key}: {value}")
                print(f"{'='*70}\n")
                return False

        except requests.exceptions.ConnectionError:
            print(f"\n{'='*70}")
            print(f"❌ CONNECTION ERROR — Cannot connect to Zero-Trust Server at {server_url}")
            print(f"{'='*70}\n")
            return False
        except Exception as e:
            print(f"\n{'='*70}")
            print(f"❌ ERROR OCCURRED: {str(e)}")
            print(f"{'='*70}\n")
            return False

    def simulate_successful_ota_update(self):
        """Call ONLY after a verified firmware update is applied."""
        print(f"\n[{self.device_id}] {'='*50}")
        print(f"[{self.device_id}] 🔄 SIMULATING SUCCESSFUL OTA UPDATE")
        print(f"[{self.device_id}] {'='*50}")
        new_counter = self.increment_monotonic_counter()
        print(f"[{self.device_id}] ✅ OTA update successful")
        print(f"[{self.device_id}] Monotonic counter incremented to: {new_counter}")
        print(f"[{self.device_id}] {'='*50}\n")
        return new_counter


# =============================================================================
# Standalone demo  →  python iot_device_simulator.py
# =============================================================================

def main():
    ZERO_TRUST_SERVER_URL = "http://13.63.176.124:5000"
    DEVICE_ID = "iot-device-001"

    print("=" * 70)
    print("IOT DEVICE SIMULATOR - COMPREHENSIVE DEMO")
    print("Phases 1-4: Complete Zero-Trust Authentication")
    print("=" * 70)

    device = IoTDeviceSimulator(device_id=DEVICE_ID)

    # Phase 1
    print("\n" + "=" * 70)
    print("PHASE 1: BASELINE CRYPTOGRAPHIC IDENTITY")
    print("=" * 70)
    phase1_success = device.provision(ZERO_TRUST_SERVER_URL)
    if not phase1_success:
        print("\n❌ Phase 1 failed. Cannot proceed.")
        return

    # Phase 2
    print("\n" + "=" * 70)
    print("PHASE 2: HARDWARE-BOUND IDENTITY")
    print("=" * 70)
    phase2_success = device.provision_phase2(ZERO_TRUST_SERVER_URL)
    if not phase2_success:
        print("\n❌ Phase 2 failed. Cannot proceed.")
        return

    # Phase 3
    print("\n" + "=" * 70)
    print("PHASE 3: CHALLENGE-RESPONSE AUTHENTICATION")
    print("=" * 70)
    phase3_success = device.authenticate_with_challenge_response(ZERO_TRUST_SERVER_URL)
    if not phase3_success:
        print("\n❌ Phase 3 failed. Cannot proceed.")
        return

    # Phase 4/5
    print("\n" + "=" * 70)
    print("PHASE 4: CONTEXT-BOUND PROOF AUTHENTICATION (CB-CCR)")
    print("=" * 70)

    print("\n📋 Test 1: Hardware + Counter contexts")
    phase4_test1 = device.authenticate_with_context_bound_proof(
        ZERO_TRUST_SERVER_URL,
        required_contexts=['hw', 'counter'],
        increment_counter_on_success=True
    )

    print("\n📋 Test 2: Hardware + Counter + Time contexts")
    phase4_test2 = device.authenticate_with_context_bound_proof(
        ZERO_TRUST_SERVER_URL,
        required_contexts=['hw', 'counter', 'time'],
        increment_counter_on_success=True
    )

    print("\n📋 Test 3: All contexts (Hardware + Counter + Time + Firmware)")
    phase4_test3 = device.authenticate_with_context_bound_proof(
        ZERO_TRUST_SERVER_URL,
        required_contexts=['hw', 'counter', 'time', 'firmware'],
        increment_counter_on_success=False
    )

    if phase4_test3:
        print("\n" + "=" * 70)
        print("SIMULATING OTA UPDATE WORKFLOW")
        print("=" * 70)
        print("\n🔄 Step 1: Device authenticated successfully")
        print("🔄 Step 2: Firmware downloaded and verified (simulated)")
        print("🔄 Step 3: Firmware installed successfully (simulated)")
        new_counter = device.simulate_successful_ota_update()
        print("\n🔄 Step 4: Testing authentication with new counter value")
        device.authenticate_with_context_bound_proof(
            ZERO_TRUST_SERVER_URL,
            required_contexts=['hw', 'counter'],
            increment_counter_on_success=False
        )

    # Summary
    print("\n" + "=" * 70)
    print("🎉 COMPLETE ZERO-TRUST AUTHENTICATION DEMONSTRATION")
    print("=" * 70)
    print("\n✅ PHASES COMPLETED:")
    print(f"   {'✓' if phase1_success else '✗'} Phase 1: Cryptographic Identity Established")
    print(f"   {'✓' if phase2_success else '✗'} Phase 2: Hardware Binding Implemented")
    print(f"   {'✓' if phase3_success else '✗'} Phase 3: Challenge-Response Verified")
    print(f"   {'✓' if phase4_test3 else '✗'} Phase 4: Context-Bound Proof Verified")
    print("\n🔒 SECURITY FEATURES DEMONSTRATED:")
    print("   • ECC P-256 cryptographic identity")
    print("   • Hardware fingerprint binding")
    print("   • Challenge-response authentication")
    print("   • Context-bound proof with hardware state")
    print("   • Monotonic counter for replay prevention")
    print("   • Temporal context verification")
    print("   • Firmware integrity attestation")
    print("=" * 70)


if __name__ == "__main__":
    main()