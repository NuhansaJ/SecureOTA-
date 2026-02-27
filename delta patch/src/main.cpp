#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <WiFiClient.h>
#include <LittleFS.h>
#include <Update.h>
#include <Arduino.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <Wire.h>
#include "mbedtls/aes.h"
#include "mbedtls/ccm.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/pk.h"
#include "mbedtls/sha256.h"
#include <bspatch_stub.h>

const char* WIFI_SSID = "YourWiFiNetwork";
const char* WIFI_PASS = "YourWiFiPassword";

const char* SERVER_HOST = "10.185.33.245";
const uint16_t SERVER_PORT = 8000;
const char* DEVICE_ID = "esp32_01";
const bool USE_HTTPS = false;

const uint8_t DEVICE_AES_KEY[32] = {
  0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,
  0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF
};

const char* CURRENT_VERSION = "1.0.0";

Adafruit_SSD1306 display1(128, 64, &Wire, -1);
Adafruit_SSD1306 display2(128, 64, &Wire, -1);
static bool display1_ready = false;
static bool display2_ready = false;

bool download_to_file(WiFiClient& client, const char* url, const char* filepath, bool show_progress = false) {
    if (!client.connect(SERVER_HOST, SERVER_PORT)) {
        return false;
    }
    
    client.print(String("GET ") + url + " HTTP/1.1\r\n" +
                 "Host: " + SERVER_HOST + "\r\n" +
                 "Connection: close\r\n\r\n");
    
    int content_length = 0;
    while (client.connected() || client.available()) {
        String line = client.readStringUntil('\n');
        if (line.startsWith("Content-Length: ")) {
            content_length = line.substring(16).toInt();
        }
        if (line == "\r") {
            break;
        }
    }
    
    File file = LittleFS.open(filepath, "w");
    if (!file) {
        client.stop();
        return false;
    }
    
    int bytes_received = 0;
    while (client.available()) {
        uint8_t byte = client.read();
        file.write(byte);
        bytes_received++;
        
        if (show_progress && content_length > 0 && bytes_received % 100 == 0) {
            int percent = (bytes_received * 100) / content_length;
            display1.clearDisplay();
            display1.setTextSize(1);
            display1.setTextColor(SSD1306_WHITE);
            display1.setCursor(0, 0);
            display1.println("Downloading...");
            display1.setCursor(0, 12);
            display1.print("Bytes: ");
            display1.print(bytes_received);
            display1.print("/");
            display1.println(content_length);
            display1.setCursor(0, 24);
            display1.print("Progress: ");
            display1.print(percent);
            display1.println("%");
            int barWidth = (percent * 120) / 100;
            display1.drawRect(0, 35, 128, 8, SSD1306_WHITE);
            display1.fillRect(2, 37, barWidth, 4, SSD1306_WHITE);
            display1.display();
            
            display2.clearDisplay();
            display2.setTextSize(1);
            display2.setTextColor(SSD1306_WHITE);
            display2.setCursor(0, 0);
            display2.println("Download Status");
            display2.drawLine(0, 10, 128, 10, SSD1306_WHITE);
            display2.setCursor(0, 15);
            display2.print(percent);
            display2.println("% Complete");
            display2.setCursor(0, 28);
            display2.print("Received: ");
            display2.print(bytes_received);
            display2.println(" bytes");
            display2.setCursor(0, 40);
            display2.print("Total: ");
            display2.print(content_length);
            display2.println(" bytes");
            display2.drawRect(0, 52, 128, 8, SSD1306_WHITE);
            display2.fillRect(2, 54, barWidth, 4, SSD1306_WHITE);
            display2.display();
        }
    }
    
    file.close();
    client.stop();
    return true;
}

bool aes_ccm_decrypt_file(const char* encrypted_file, const char* output_file) {
    File enc_file = LittleFS.open(encrypted_file, "r");
    if (!enc_file) {
        return false;
    }
    
    uint8_t nonce[13];
    uint8_t tag[16];
    
    if (enc_file.read(nonce, 13) != 13) {
        enc_file.close();
        return false;
    }
    
    if (enc_file.read(tag, 16) != 16) {
        enc_file.close();
        return false;
    }
    
    size_t ciphertext_len = enc_file.size() - 13 - 16;
    uint8_t* ciphertext = (uint8_t*)malloc(ciphertext_len);
    if (!ciphertext) {
        enc_file.close();
        return false;
    }
    
    if (enc_file.read(ciphertext, ciphertext_len) != ciphertext_len) {
        free(ciphertext);
        enc_file.close();
        return false;
    }
    enc_file.close();
    
    mbedtls_ccm_context ccm;
    mbedtls_ccm_init(&ccm);
    
    int ret = mbedtls_ccm_setkey(&ccm, MBEDTLS_CIPHER_ID_AES, DEVICE_AES_KEY, 256);
    if (ret != 0) {
        mbedtls_ccm_free(&ccm);
        free(ciphertext);
        return false;
    }
    
    uint8_t* plaintext = (uint8_t*)malloc(ciphertext_len);
    if (!plaintext) {
        mbedtls_ccm_free(&ccm);
        free(ciphertext);
        return false;
    }
    
    ret = mbedtls_ccm_auth_decrypt(&ccm, ciphertext_len, nonce, 13, NULL, 0,
                                    ciphertext, plaintext, tag, 16);
    
    mbedtls_ccm_free(&ccm);
    free(ciphertext);
    
    if (ret != 0) {
        free(plaintext);
        return false;
    }
    
    File out_file = LittleFS.open(output_file, "w");
    if (!out_file) {
        free(plaintext);
        return false;
    }
    
    out_file.write(plaintext, ciphertext_len);
    out_file.close();
    free(plaintext);
    
    return true;
}

bool verify_signature_file(const char* patch_file, const char* signature_file) {
    File patch = LittleFS.open(patch_file, "r");
    if (!patch) {
        return false;
    }
    
    size_t patch_size = patch.size();
    uint8_t* patch_data = (uint8_t*)malloc(patch_size);
    if (!patch_data) {
        patch.close();
        return false;
    }
    
    patch.read(patch_data, patch_size);
    patch.close();
    
    mbedtls_sha256_context sha256;
    mbedtls_sha256_init(&sha256);
    uint8_t hash[32];
    mbedtls_sha256_starts(&sha256, 0);
    mbedtls_sha256_update(&sha256, patch_data, patch_size);
    mbedtls_sha256_finish(&sha256, hash);
    free(patch_data);
    
    File sig_file = LittleFS.open(signature_file, "r");
    if (!sig_file) {
        return false;
    }
    
    size_t sig_size = sig_file.size();
    uint8_t* sig_data = (uint8_t*)malloc(sig_size);
    if (!sig_data) {
        sig_file.close();
        return false;
    }
    
    sig_file.read(sig_data, sig_size);
    sig_file.close();
    
    File pubkey_file = LittleFS.open("/server_pub.pem", "r");
    if (!pubkey_file) {
        free(sig_data);
        return false;
    }
    
    String pubkey_str = pubkey_file.readString();
    pubkey_file.close();
    
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    
    int ret = mbedtls_pk_parse_public_key(&pk, (const unsigned char*)pubkey_str.c_str(), pubkey_str.length() + 1);
    if (ret != 0) {
        mbedtls_pk_free(&pk);
        free(sig_data);
        return false;
    }
    
    ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, hash, 32, sig_data, sig_size);
    
    mbedtls_pk_free(&pk);
    free(sig_data);
    
    return (ret == 0);
}

bool apply_patch_and_write_ota(const char* patch_file) {
    return apply_patch_to_ota(patch_file);
}

void update_display(const char* line1, const char* line2 = "", const char* line3 = "") {
    if (display1_ready) {
        display1.clearDisplay();
        display1.setTextSize(1);
        display1.setTextColor(SSD1306_WHITE);
        display1.setCursor(0, 0);
        display1.println(line1);
        if (strlen(line2) > 0) display1.println(line2);
        if (strlen(line3) > 0) display1.println(line3);
        display1.display();
    }
    if (display2_ready) {
        display2.clearDisplay();
        display2.setTextSize(1);
        display2.setTextColor(SSD1306_WHITE);
        display2.setCursor(0, 0);
        display2.println(line1);
        if (strlen(line2) > 0) display2.println(line2);
        if (strlen(line3) > 0) display2.println(line3);
        display2.display();
    }
}

void update_display_split(const char* status, const char* detail, int progress = -1) {
    if (display1_ready) {
        display1.clearDisplay();
        display1.setTextSize(1);
        display1.setTextColor(SSD1306_WHITE);
        display1.setCursor(0, 0);
        display1.println("ESP32 OTA Update");
        display1.drawLine(0, 10, 128, 10, SSD1306_WHITE);
        display1.setCursor(0, 12);
        display1.setTextSize(1);
        display1.println(status);
        if (strlen(detail) > 0) {
            display1.setCursor(0, 22);
            display1.setTextSize(1);
            display1.println(detail);
        }
        if (progress >= 0 && progress <= 100) {
            display1.setCursor(0, 50);
            display1.setTextSize(1);
            display1.print("Progress: ");
            display1.print(progress);
            display1.println("%");
            int barWidth = (progress * 120) / 100;
            display1.drawRect(0, 58, 128, 6, SSD1306_WHITE);
            display1.fillRect(2, 60, barWidth, 2, SSD1306_WHITE);
        }
        display1.display();
    }
    
    if (display2_ready) {
        display2.clearDisplay();
        display2.setTextSize(1);
        display2.setTextColor(SSD1306_WHITE);
        display2.setCursor(0, 0);
        display2.println("Device Info");
        display2.drawLine(0, 10, 128, 10, SSD1306_WHITE);
        display2.setCursor(0, 12);
        display2.print("ID: ");
        display2.println(DEVICE_ID);
        display2.setCursor(0, 22);
        display2.print("Ver: ");
        display2.println(CURRENT_VERSION);
        display2.setCursor(0, 32);
        display2.println("Status:");
        display2.setCursor(0, 42);
        display2.setTextSize(1);
        display2.println(status);
        if (strlen(detail) > 0) {
            display2.setCursor(0, 52);
            display2.setTextSize(1);
            String detailStr2 = String(detail);
            if (detailStr2.length() > 21) {
                detailStr2 = detailStr2.substring(0, 18) + "...";
            }
            display2.println(detailStr2.c_str());
        }
        display2.display();
    }
}

void run_update_flow() {
    WiFiClient client;
    String check_url = String("/check_update/?device_id=") + DEVICE_ID + "&version=" + CURRENT_VERSION;
    
    update_display_split("Checking", "Server...", 0);
    
    Serial.print("Attempting to connect to: ");
    Serial.print(SERVER_HOST);
    Serial.print(":");
    Serial.println(SERVER_PORT);
    
    if (!client.connect(SERVER_HOST, SERVER_PORT)) {
        Serial.println("Connection failed!");
        Serial.print("Failed to connect to: ");
        Serial.print(SERVER_HOST);
        Serial.print(":");
        Serial.println(SERVER_PORT);
        Serial.println("Check:");
        Serial.println("1. Server is running (uvicorn server:app --host 0.0.0.0 --port 8000)");
        Serial.println("2. ESP32 and server are on same WiFi network");
        Serial.println("3. Firewall allows port 8000");
        Serial.print("4. ESP32 IP: ");
        Serial.println(WiFi.localIP());
        update_display_split("Connection", "FAILED", 0);
        delay(3000);
        return;
    }
    
    Serial.println("Connected to server!");
    
    client.print(String("GET ") + check_url + " HTTP/1.1\r\n" +
                 "Host: " + SERVER_HOST + "\r\n" +
                 "Connection: close\r\n\r\n");
    
    String response = "";
    while (client.connected() || client.available()) {
        String line = client.readStringUntil('\n');
        response += line;
        if (line == "\r") {
            break;
        }
    }
    
    String body = "";
    while (client.available()) {
        body += (char)client.read();
    }
    client.stop();
    
    update_display_split("Checking", "for updates...", 10);
    
    if (body.indexOf("\"update_available\":true") < 0) {
        Serial.println("No update available");
        update_display_split("No Update", "Available", 0);
        delay(2000);
        return;
    }
    
    int old_start = body.indexOf("\"old_version\":\"") + 15;
    int old_end = body.indexOf("\"", old_start);
    String old_version = body.substring(old_start, old_end);
    
    int new_start = body.indexOf("\"new_version\":\"") + 15;
    int new_end = body.indexOf("\"", new_start);
    String new_version = body.substring(new_start, new_end);
    
    Serial.println("Update available: " + old_version + " -> " + new_version);
    update_display_split("Update Found!", (old_version + " -> " + new_version).c_str(), 20);
    delay(2000);
    
    String patch_url = String("/get_patch/") + old_version + "/" + new_version + "/" + DEVICE_ID;
    String sig_url = String("/get_signature/") + old_version + "/" + new_version;
    
    Serial.println("Downloading patch...");
    update_display_split("Downloading", "Patch file...", 30);
    
    WiFiClient client2;
    if (!download_to_file(client2, patch_url.c_str(), "/patch.enc", true)) {
        Serial.println("Patch download failed");
        update_display_split("Download", "FAILED!", 0);
        delay(3000);
        return;
    }
    
    update_display_split("Downloading", "Signature...", 60);
    
    Serial.println("Downloading signature...");
    WiFiClient client3;
    if (!download_to_file(client3, sig_url.c_str(), "/patch.sig", false)) {
        Serial.println("Signature download failed");
        update_display_split("Sig Download", "FAILED!", 0);
        delay(3000);
        return;
    }
    
    Serial.println("Decrypting patch...");
    update_display_split("Decrypting", "Patch file...", 70);
    delay(500);
    
    if (!aes_ccm_decrypt_file("/patch.enc", "/patch.bsdiff")) {
        Serial.println("Decryption failed");
        update_display_split("Decryption", "FAILED!", 0);
        delay(3000);
        return;
    }
    
    Serial.println("Verifying signature...");
    update_display_split("Verifying", "Signature...", 80);
    delay(500);
    
    if (!verify_signature_file("/patch.bsdiff", "/patch.sig")) {
        Serial.println("Verification failed");
        update_display_split("Verification", "FAILED!", 0);
        delay(3000);
        return;
    }
    
    Serial.println("Applying patch...");
    update_display_split("Applying", "Patch to OTA...", 90);
    delay(500);
    
    if (!apply_patch_and_write_ota("/patch.bsdiff")) {
        Serial.println("Patch application failed");
        update_display_split("Apply Failed", "Check Serial", 0);
        delay(3000);
        return;
    }
    
    Serial.println("Update complete! Rebooting...");
    update_display_split("SUCCESS!", "Rebooting...", 100);
    delay(3000);
    
    ESP.restart();
}

void setup() {
    Serial.begin(115200);
    delay(1000);
    
    if (!LittleFS.begin(true)) {
        Serial.println("LittleFS mount failed");
        return;
    }
    
    Wire.begin();
    
    display1_ready = display1.begin(SSD1306_SWITCHCAPVCC, 0x3C);
    display2_ready = display2.begin(SSD1306_SWITCHCAPVCC, 0x3D);

    if (!display1_ready) {
        Serial.println("Display 1 (0x3C) initialization failed!");
    } else {
        Serial.println("Display 1 (0x3C) initialized successfully");
        display1.display();
    }
    if (!display2_ready) {
        Serial.println("Display 2 (0x3D) initialization failed!");
    } else {
        Serial.println("Display 2 (0x3D) initialized successfully");
        display2.display();
    }
    
    update_display_split("Initializing", "WiFi...", 5);
    Serial.println("Connecting to WiFi...");
    
    WiFi.mode(WIFI_STA);
    WiFi.begin(WIFI_SSID, WIFI_PASS);
    
    int attempts = 0;
    while (WiFi.status() != WL_CONNECTED && attempts < 20) {
        delay(500);
        Serial.print(".");
        int progress = 5 + (attempts * 30 / 20);
        update_display_split("Connecting", "WiFi...", progress);
        attempts++;
    }
    
    if (WiFi.status() != WL_CONNECTED) {
        Serial.println("WiFi connection failed");
        update_display_split("WiFi", "FAILED!", 0);
        delay(3000);
        return;
    }
    
    Serial.println("WiFi connected");
    Serial.println("IP address: " + WiFi.localIP().toString());
    update_display_split("WiFi Connected", WiFi.localIP().toString().c_str(), 40);
    delay(2000);
    
    update_display_split("Checking", "PUBKEY...", 50);
    File pubkey = LittleFS.open("/server_pub.pem", "r");
    if (!pubkey) {
        Serial.println("PUBKEY not found!");
        update_display_split("PUBKEY", "NOT FOUND!", 0);
        delay(3000);
        return;
    }
    pubkey.close();
    Serial.println("PUBKEY found");
    update_display_split("PUBKEY", "Found OK", 60);
    delay(1000);
    
    update_display_split("Ready", "Waiting...", 100);
    delay(2000);
    
    Serial.println("Starting update flow demo...");
    run_update_flow();
}

void loop() {
    delay(60000);
    run_update_flow();
}

