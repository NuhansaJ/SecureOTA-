#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <WiFiClient.h>
#include <LittleFS.h>
#include <Update.h>
#include <Arduino.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <Wire.h>
#include <esp_partition.h>
#include <esp_ota_ops.h>
#include <string.h>
#include "mbedtls/aes.h"
#include "mbedtls/ccm.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/pk.h"
#include "mbedtls/sha256.h"
#include "mbedtls/md.h"
#include "mbedtls/error.h"

static const char REM_MAGIC[4] = {'R','E','M','1'};
static const char REM_SALT[16] = "REM1-OTA-PATCH";
static const char REM_CTX[4] = {'R','E','M','1'};
#define REM_TAG_SIZE 32
#define REM_NONCE_SIZE 16
#define REM_HEADER_SIZE (4 + REM_NONCE_SIZE)

static void rem_derive_keys(uint8_t* aes_key_out, uint8_t* hmac_key_out) {
    const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    uint8_t prk[32];
    mbedtls_md_hmac(md, (const unsigned char*)REM_SALT, 16, DEVICE_AES_KEY, 32, prk);
    uint8_t block1[37];
    memcpy(block1, REM_CTX, 4);
    block1[4] = 0x01;
    mbedtls_md_hmac(md, prk, 32, block1, 5, aes_key_out);
    uint8_t block2[37];
    memcpy(block2, aes_key_out, 32);
    memcpy(block2 + 32, REM_CTX, 4);
    block2[36] = 0x02;
    mbedtls_md_hmac(md, prk, 32, block2, 37, hmac_key_out);
}

const char* WIFI_SSID = "Dialog 4G 325";
const char* WIFI_PASS = "A75Cb8D3";

const char* SERVER_HOST = "192.168.8.136";
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

static int64_t read_bsdiff_int64_le(const uint8_t* buf) {
    int64_t y = buf[7] & 0x7F;
    for (int i = 6; i >= 0; i--) {
        y = y * 256 + buf[i];
    }
    if (buf[7] & 0x80) {
        y = -y;
    }
    return y;
}

static bool file_read_exact(File& f, uint8_t* out, size_t n) {
    size_t got = 0;
    while (got < n) {
        size_t r = f.read(out + got, n - got);
        if (r == 0) {
            return false;
        }
        got += r;
    }
    return true;
}

bool apply_patch_to_ota(const char* patch_file_path) {
    File patch_file = LittleFS.open(patch_file_path, "r");
    if (!patch_file) {
        Serial.println("APPLY_FAIL:OPEN_PATCH");
        return false;
    }
    
    size_t patch_file_size = patch_file.size();
    if (patch_file_size < 40) {
        Serial.println("APPLY_FAIL:PATCH_TOO_SMALL");
        patch_file.close();
        return false;
    }
    
    const esp_partition_t* running = esp_ota_get_running_partition();
    if (!running) {
        Serial.println("APPLY_FAIL:GET_RUNNING_PART");
        patch_file.close();
        return false;
    }
    
    uint8_t header[40];
    if (!file_read_exact(patch_file, header, sizeof(header))) {
        Serial.println("APPLY_FAIL:READ_HEADER");
        patch_file.close();
        return false;
    }
    
    if (memcmp(header, "BSDIFRAW", 8) != 0) {
        Serial.println("APPLY_FAIL:BAD_MAGIC");
        patch_file.close();
        return false;
    }
    
    int64_t ctrl_len = read_bsdiff_int64_le(header + 8);
    int64_t diff_len = read_bsdiff_int64_le(header + 16);
    int64_t new_size = read_bsdiff_int64_le(header + 24);
    int64_t old_size = read_bsdiff_int64_le(header + 32);
    
    if (ctrl_len < 0 || diff_len < 0 || new_size < 0 || old_size < 0) {
        Serial.println("APPLY_FAIL:BAD_HEADER");
        patch_file.close();
        return false;
    }
    if ((ctrl_len % 24) != 0) {
        Serial.println("APPLY_FAIL:CTRL_LEN_NOT_MULTIPLE_24");
        patch_file.close();
        return false;
    }
    
    if (ctrl_len == 0 && diff_len == 0 && new_size == 0) {
        Serial.println("APPLY_FAIL:EMPTY_PATCH");
        patch_file.close();
        return false;
    }
    
    size_t expected_patch_size = 40 + (size_t)ctrl_len + (size_t)diff_len;
    if (expected_patch_size > patch_file_size) {
        Serial.println("APPLY_FAIL:PATCH_INCOMPLETE");
        patch_file.close();
        return false;
    }
    
    if (!Update.begin(new_size)) {
        Serial.println("APPLY_FAIL:UPDATE_BEGIN");
        patch_file.close();
        return false;
    }
    int64_t oldpos = 0;
    int64_t newpos = 0;
    int64_t ctrlpos = 0;
    int64_t diffpos = 0;
    int64_t extrapos = 0;

    const int64_t ctrl_start = 40;
    const int64_t diff_start = ctrl_start + ctrl_len;
    const int64_t extra_start = diff_start + diff_len;
    const int64_t extra_len = (int64_t)patch_file_size - extra_start;

    const size_t chunk = 1024;
    uint8_t* diff_buf = (uint8_t*)malloc(chunk);
    uint8_t* old_buf = (uint8_t*)malloc(chunk);
    uint8_t* out_buf = (uint8_t*)malloc(chunk);
    if (!diff_buf || !old_buf || !out_buf) {
        free(diff_buf);
        free(old_buf);
        free(out_buf);
        Serial.println("APPLY_FAIL:OOM_BUFS");
        Update.abort();
        patch_file.close();
        return false;
    }

    while (newpos < new_size) {
        if (ctrlpos + 24 > ctrl_len) {
            Serial.println("APPLY_FAIL:CTRL_UNDERFLOW");
            free(diff_buf);
            free(old_buf);
            free(out_buf);
            Update.abort();
            patch_file.close();
            return false;
        }

        uint8_t ctrl_triplet[24];
        if (!patch_file.seek(ctrl_start + ctrlpos)) {
            Serial.println("APPLY_FAIL:SEEK_CTRL");
            free(diff_buf);
            free(old_buf);
            free(out_buf);
            Update.abort();
            patch_file.close();
            return false;
        }
        if (!file_read_exact(patch_file, ctrl_triplet, sizeof(ctrl_triplet))) {
            Serial.println("APPLY_FAIL:READ_CTRL");
            free(diff_buf);
            free(old_buf);
            free(out_buf);
            Update.abort();
            patch_file.close();
            return false;
        }
        ctrlpos += 24;

        int64_t x = read_bsdiff_int64_le(ctrl_triplet + 0);
        int64_t y = read_bsdiff_int64_le(ctrl_triplet + 8);
        int64_t z = read_bsdiff_int64_le(ctrl_triplet + 16);

        if (x < 0 || y < 0) {
            Serial.println("APPLY_FAIL:NEG_XY");
            free(diff_buf);
            free(old_buf);
            free(out_buf);
            Update.abort();
            patch_file.close();
            return false;
        }
        if (newpos + x > new_size) {
            Serial.println("APPLY_FAIL:NEW_OVERFLOW");
            free(diff_buf);
            free(old_buf);
            free(out_buf);
            Update.abort();
            patch_file.close();
            return false;
        }
        if (diffpos + x > diff_len) {
            Serial.println("APPLY_FAIL:DIFF_UNDERFLOW");
            free(diff_buf);
            free(old_buf);
            free(out_buf);
            Update.abort();
            patch_file.close();
            return false;
        }

        int64_t remaining = x;
        while (remaining > 0) {
            size_t n = (size_t)((remaining > (int64_t)chunk) ? chunk : remaining);
            if (!patch_file.seek(diff_start + diffpos)) {
                Serial.println("APPLY_FAIL:SEEK_DIFF");
                free(diff_buf);
                free(old_buf);
                free(out_buf);
                Update.abort();
                patch_file.close();
                return false;
            }
            if (!file_read_exact(patch_file, diff_buf, n)) {
                Serial.println("APPLY_FAIL:READ_DIFF");
                free(diff_buf);
                free(old_buf);
                free(out_buf);
                Update.abort();
                patch_file.close();
                return false;
            }
            diffpos += (int64_t)n;

            if (oldpos < old_size) {
                int64_t n_old64 = (oldpos + (int64_t)n > old_size) ? (old_size - oldpos) : (int64_t)n;
                size_t n_old = (size_t)n_old64;
                if (n_old > 0) {
                    esp_err_t err = esp_partition_read(running, (size_t)oldpos, old_buf, n_old);
                    if (err != ESP_OK) {
                        Serial.print("APPLY_FAIL:READ_OLD_PART err=");
                        Serial.println((int)err);
                        free(diff_buf);
                        free(old_buf);
                        free(out_buf);
                        Update.abort();
                        patch_file.close();
                        return false;
                    }
                    for (size_t i = 0; i < n_old; i++) {
                        out_buf[i] = (uint8_t)(old_buf[i] + diff_buf[i]);
                    }
                }
                for (size_t i = n_old; i < n; i++) {
                    out_buf[i] = diff_buf[i];
                }
            } else {
                memcpy(out_buf, diff_buf, n);
            }

            size_t written = Update.write(out_buf, n);
            if (written != n) {
                Serial.println("APPLY_FAIL:WRITE_DIFF");
                free(diff_buf);
                free(old_buf);
                free(out_buf);
                Update.abort();
                patch_file.close();
                return false;
            }

            oldpos += (int64_t)n;
            newpos += (int64_t)n;
            remaining -= (int64_t)n;
        }

        if (newpos + y > new_size) {
            Serial.println("APPLY_FAIL:EXTRA_NEW_OVERFLOW");
            free(diff_buf);
            free(old_buf);
            free(out_buf);
            Update.abort();
            patch_file.close();
            return false;
        }
        if (extrapos + y > extra_len) {
            Serial.println("APPLY_FAIL:EXTRA_UNDERFLOW");
            free(diff_buf);
            free(old_buf);
            free(out_buf);
            Update.abort();
            patch_file.close();
            return false;
        }

        remaining = y;
        while (remaining > 0) {
            size_t n = (size_t)((remaining > (int64_t)chunk) ? chunk : remaining);
            if (!patch_file.seek(extra_start + extrapos)) {
                Serial.println("APPLY_FAIL:SEEK_EXTRA");
                free(diff_buf);
                free(old_buf);
                free(out_buf);
                Update.abort();
                patch_file.close();
                return false;
            }
            if (!file_read_exact(patch_file, out_buf, n)) {
                Serial.println("APPLY_FAIL:READ_EXTRA");
                free(diff_buf);
                free(old_buf);
                free(out_buf);
                Update.abort();
                patch_file.close();
                return false;
            }
            extrapos += (int64_t)n;

            size_t written = Update.write(out_buf, n);
            if (written != n) {
                Serial.println("APPLY_FAIL:WRITE_EXTRA");
                free(diff_buf);
                free(old_buf);
                free(out_buf);
                Update.abort();
                patch_file.close();
                return false;
            }

            newpos += (int64_t)n;
            remaining -= (int64_t)n;
        }

        oldpos += z;
        if (oldpos < 0) {
            Serial.println("APPLY_FAIL:OLDPOS_NEG");
            free(diff_buf);
            free(old_buf);
            free(out_buf);
            Update.abort();
            patch_file.close();
            return false;
        }
    }

    free(diff_buf);
    free(old_buf);
    free(out_buf);
    patch_file.close();

    if (!Update.end()) {
        Serial.println("APPLY_FAIL:UPDATE_END");
        return false;
    }
    return true;
}

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
    unsigned long download_start = millis();
    while (client.connected() || client.available()) {
        if (client.available()) {
            uint8_t byte = client.read();
            file.write(byte);
            bytes_received++;
        } else {
            delay(10);
        }
        
        if (show_progress && content_length > 0 && bytes_received % 100 == 0) {
            int percent = (bytes_received * 100) / content_length;
            int barWidth = (percent * 120) / 100;
            
            if (display1_ready) {
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
                display1.setCursor(0, 25);
                display1.setTextSize(1);
                display1.print(percent);
                display1.println("%");
                display1.drawRect(0, 55, 128, 8, SSD1306_WHITE);
                display1.fillRect(2, 57, barWidth, 4, SSD1306_WHITE);
                display1.display();
            }
            
            if (display2_ready) {
                display2.clearDisplay();
                display2.setTextSize(1);
                display2.setTextColor(SSD1306_WHITE);
                display2.setCursor(0, 0);
                display2.println("Download Status");
                display2.drawLine(0, 10, 128, 10, SSD1306_WHITE);
                display2.setCursor(0, 15);
                display2.setTextSize(1);
                display2.print(percent);
                display2.println("%");
                display2.setTextSize(1);
                display2.setCursor(0, 35);
                display2.print("Rx: ");
                display2.print(bytes_received);
                display2.println("B");
                display2.setCursor(0, 45);
                display2.print("Total: ");
                display2.print(content_length);
                display2.println("B");
                display2.drawRect(0, 55, 128, 6, SSD1306_WHITE);
                display2.fillRect(2, 57, barWidth, 2, SSD1306_WHITE);
                display2.display();
            }
        }
    }
    
    file.close();
    client.stop();
    
    if (content_length > 0 && bytes_received != content_length) {
        Serial.println("DOWNLOAD_FAIL:INCOMPLETE");
        return false;
    }
    return true;
}

bool rem_decrypt_file(const char* encrypted_file, const char* output_file) {
    File enc_file = LittleFS.open(encrypted_file, "r");
    if (!enc_file) {
        Serial.println("DECRYPT_FAIL:FILE_OPEN");
        return false;
    }
    size_t file_size = enc_file.size();
    if (file_size < REM_HEADER_SIZE + REM_TAG_SIZE + 1) {
        Serial.println("DECRYPT_FAIL:FILE_TOO_SMALL");
        enc_file.close();
        return false;
    }
    uint8_t magic[4];
    if (enc_file.read(magic, 4) != 4 || memcmp(magic, REM_MAGIC, 4) != 0) {
        Serial.println("DECRYPT_FAIL:BAD_MAGIC");
        enc_file.close();
        return false;
    }
    uint8_t nonce[REM_NONCE_SIZE];
    if (enc_file.read(nonce, REM_NONCE_SIZE) != REM_NONCE_SIZE) {
        Serial.println("DECRYPT_FAIL:READ_NONCE");
        enc_file.close();
        return false;
    }
    size_t ciphertext_len = file_size - 4 - REM_NONCE_SIZE - REM_TAG_SIZE;
    if (ciphertext_len == 0) {
        Serial.println("DECRYPT_FAIL:NO_DATA");
        enc_file.close();
        return false;
    }
    LittleFS.remove("/patch.bsdiff");
    LittleFS.remove("/patch.sig");
    File out_file = LittleFS.open(output_file, "w");
    if (!out_file) {
        Serial.println("DECRYPT_FAIL:OUTPUT_CREATE");
        enc_file.close();
        return false;
    }
    uint8_t aes_key[32], hmac_key[32];
    rem_derive_keys(aes_key, hmac_key);
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    int ret = mbedtls_aes_setkey_enc(&aes, aes_key, 256);
    if (ret != 0) {
        Serial.println("DECRYPT_FAIL:KEY_SETUP");
        mbedtls_aes_free(&aes);
        out_file.close();
        enc_file.close();
        return false;
    }
    mbedtls_md_context_t md_ctx;
    mbedtls_md_init(&md_ctx);
    const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md || mbedtls_md_setup(&md_ctx, md, 1) != 0 || mbedtls_md_hmac_starts(&md_ctx, hmac_key, 32) != 0) {
        Serial.println("DECRYPT_FAIL:HMAC_INIT");
        mbedtls_md_free(&md_ctx);
        mbedtls_aes_free(&aes);
        out_file.close();
        enc_file.close();
        return false;
    }
    mbedtls_md_hmac_update(&md_ctx, nonce, REM_NONCE_SIZE);
    size_t iv_off = 0;
    const size_t chunk = 1024;
    uint8_t* in_buf = (uint8_t*)malloc(chunk);
    uint8_t* out_buf = (uint8_t*)malloc(chunk);
    if (!in_buf || !out_buf) {
        Serial.println("DECRYPT_FAIL:OOM_BUFS");
        mbedtls_md_free(&md_ctx);
        mbedtls_aes_free(&aes);
        out_file.close();
        enc_file.close();
        return false;
    }
    size_t remaining = ciphertext_len;
    while (remaining > 0) {
        size_t n = remaining > chunk ? chunk : remaining;
        size_t r = enc_file.read(in_buf, n);
        if (r == 0) {
            Serial.println("DECRYPT_FAIL:READ_EOF");
            free(in_buf);
            free(out_buf);
            mbedtls_md_free(&md_ctx);
            mbedtls_aes_free(&aes);
            out_file.close();
            enc_file.close();
            return false;
        }
        mbedtls_md_hmac_update(&md_ctx, in_buf, r);
        ret = mbedtls_aes_crypt_cfb128(&aes, MBEDTLS_AES_DECRYPT, r, &iv_off, nonce, in_buf, out_buf);
        if (ret != 0) {
            Serial.print("DECRYPT_FAIL:MBEDTLS_CODE=");
            Serial.println(ret);
            free(in_buf);
            free(out_buf);
            mbedtls_md_free(&md_ctx);
            mbedtls_aes_free(&aes);
            out_file.close();
            enc_file.close();
            return false;
        }
        if (out_file.write(out_buf, r) != r) {
            Serial.println("DECRYPT_FAIL:WRITE_INCOMPLETE");
            free(in_buf);
            free(out_buf);
            mbedtls_md_free(&md_ctx);
            mbedtls_aes_free(&aes);
            out_file.close();
            enc_file.close();
            return false;
        }
        remaining -= r;
    }
    uint8_t tag_computed[REM_TAG_SIZE];
    mbedtls_md_hmac_finish(&md_ctx, tag_computed);
    mbedtls_md_free(&md_ctx);
    uint8_t tag_file[REM_TAG_SIZE];
    if (enc_file.read(tag_file, REM_TAG_SIZE) != REM_TAG_SIZE) {
        Serial.println("DECRYPT_FAIL:READ_TAG");
        free(in_buf);
        free(out_buf);
        mbedtls_aes_free(&aes);
        out_file.close();
        enc_file.close();
        return false;
    }
    if (memcmp(tag_computed, tag_file, REM_TAG_SIZE) != 0) {
        Serial.println("DECRYPT_FAIL:TAG_MISMATCH");
        free(in_buf);
        free(out_buf);
        mbedtls_aes_free(&aes);
        out_file.close();
        enc_file.close();
        return false;
    }
    free(in_buf);
    free(out_buf);
    mbedtls_aes_free(&aes);
    enc_file.close();
    out_file.close();
    LittleFS.remove(encrypted_file);
    return true;
}

static bool verify_signature_encrypted(const char* encrypted_patch_file, const char* signature_file) {
    File enc = LittleFS.open(encrypted_patch_file, "r");
    if (!enc) {
        Serial.println("ERROR: Cannot open encrypted patch file");
        return false;
    }
    size_t file_size = enc.size();
    if (file_size < REM_HEADER_SIZE + REM_TAG_SIZE + 1) {
        enc.close();
        return false;
    }
    uint8_t magic[4];
    if (enc.read(magic, 4) != 4 || memcmp(magic, REM_MAGIC, 4) != 0) {
        enc.close();
        return false;
    }
    uint8_t nonce[REM_NONCE_SIZE];
    if (enc.read(nonce, REM_NONCE_SIZE) != REM_NONCE_SIZE) {
        enc.close();
        return false;
    }
    size_t ciphertext_len = file_size - 4 - REM_NONCE_SIZE - REM_TAG_SIZE;
    uint8_t aes_key[32], hmac_key[32];
    rem_derive_keys(aes_key, hmac_key);
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    int ret = mbedtls_aes_setkey_enc(&aes, aes_key, 256);
    if (ret != 0) {
        mbedtls_aes_free(&aes);
        enc.close();
        return false;
    }
    mbedtls_md_context_t md_ctx;
    mbedtls_md_init(&md_ctx);
    const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md || mbedtls_md_setup(&md_ctx, md, 1) != 0 || mbedtls_md_hmac_starts(&md_ctx, hmac_key, 32) != 0) {
        mbedtls_md_free(&md_ctx);
        mbedtls_aes_free(&aes);
        enc.close();
        return false;
    }
    mbedtls_md_hmac_update(&md_ctx, nonce, REM_NONCE_SIZE);
    size_t iv_off = 0;
    const size_t chunk = 1024;
    uint8_t* in_buf = (uint8_t*)malloc(chunk);
    uint8_t* out_buf = (uint8_t*)malloc(chunk);
    if (!in_buf || !out_buf) {
        free(in_buf);
        free(out_buf);
        mbedtls_md_free(&md_ctx);
        mbedtls_aes_free(&aes);
        enc.close();
        return false;
    }
    mbedtls_sha256_context sha256;
    mbedtls_sha256_init(&sha256);
    uint8_t hash[32];
    mbedtls_sha256_starts(&sha256, 0);
    size_t remaining = ciphertext_len;
    while (remaining > 0) {
        size_t n = remaining > chunk ? chunk : remaining;
        size_t r = enc.read(in_buf, n);
        if (r == 0) {
            free(in_buf);
            free(out_buf);
            mbedtls_md_free(&md_ctx);
            mbedtls_aes_free(&aes);
            enc.close();
            return false;
        }
        mbedtls_md_hmac_update(&md_ctx, in_buf, r);
        ret = mbedtls_aes_crypt_cfb128(&aes, MBEDTLS_AES_DECRYPT, r, &iv_off, nonce, in_buf, out_buf);
        if (ret != 0) {
            free(in_buf);
            free(out_buf);
            mbedtls_md_free(&md_ctx);
            mbedtls_aes_free(&aes);
            enc.close();
            return false;
        }
        mbedtls_sha256_update(&sha256, out_buf, r);
        remaining -= r;
    }
    mbedtls_sha256_finish(&sha256, hash);
    uint8_t tag_computed[REM_TAG_SIZE];
    mbedtls_md_hmac_finish(&md_ctx, tag_computed);
    mbedtls_md_free(&md_ctx);
    uint8_t tag_file[REM_TAG_SIZE];
    if (enc.read(tag_file, REM_TAG_SIZE) != REM_TAG_SIZE || memcmp(tag_computed, tag_file, REM_TAG_SIZE) != 0) {
        free(in_buf);
        free(out_buf);
        mbedtls_aes_free(&aes);
        enc.close();
        return false;
    }
    free(in_buf);
    free(out_buf);
    mbedtls_aes_free(&aes);
    enc.close();
    
    File sig_file = LittleFS.open(signature_file, "r");
    if (!sig_file) {
        Serial.println("ERROR: Failed to open signature file");
        return false;
    }
    
    size_t sig_size = sig_file.size();
    if (sig_size == 0) {
        Serial.println("VERIFY_FAIL:EMPTY_SIG");
        sig_file.close();
        return false;
    }
    
    uint8_t* sig_data = (uint8_t*)malloc(sig_size);
    if (!sig_data) {
        Serial.println("VERIFY_FAIL:OOM");
        sig_file.close();
        return false;
    }
    
    size_t bytes_read = sig_file.read(sig_data, sig_size);
    sig_file.close();
    
    if (bytes_read != sig_size) {
        Serial.println("VERIFY_FAIL:READ_INCOMPLETE");
        free(sig_data);
        return false;
    }
    
    File pubkey_file = LittleFS.open("/server_pub.pem", "r");
    if (!pubkey_file) {
        Serial.println("VERIFY_FAIL:NO_PUBKEY");
        free(sig_data);
        return false;
    }
    
    String pubkey_str = pubkey_file.readString();
    pubkey_file.close();
    
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    
    ret = mbedtls_pk_parse_public_key(&pk, (const unsigned char*)pubkey_str.c_str(), pubkey_str.length() + 1);
    if (ret != 0) {
        Serial.println("VERIFY_FAIL:PARSE_PUBKEY");
        mbedtls_pk_free(&pk);
        free(sig_data);
        return false;
    }
    
    ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, hash, 32, sig_data, sig_size);
    
    if (ret != 0 && ret == -19968) {
        if (mbedtls_pk_get_type(&pk) == MBEDTLS_PK_ECKEY && sig_size >= 70 && sig_data[0] == 0x30) {
            mbedtls_ecp_keypair* ecp = mbedtls_pk_ec(pk);
            if (ecp) {
                uint8_t r_bytes[32] = {0};
                uint8_t s_bytes[32] = {0};
                bool r_ok = false, s_ok = false;
                
                size_t pos = 2;
                if (sig_data[pos] == 0x02) {
                    pos++;
                    uint8_t r_len = sig_data[pos++];
                    if (r_len == 0x20) {
                        memcpy(r_bytes, sig_data + pos, 32);
                        pos += 32;
                        r_ok = true;
                    } else if (r_len == 0x21 && sig_data[pos] == 0x00) {
                        memcpy(r_bytes, sig_data + pos + 1, 32);
                        pos += 33;
                        r_ok = true;
                    }
                }
                
                if (pos < sig_size && sig_data[pos] == 0x02) {
                    pos++;
                    uint8_t s_len = sig_data[pos++];
                    if (s_len == 0x20) {
                        memcpy(s_bytes, sig_data + pos, 32);
                        s_ok = true;
                    } else if (s_len == 0x21 && sig_data[pos] == 0x00) {
                        memcpy(s_bytes, sig_data + pos + 1, 32);
                        s_ok = true;
                    }
                }
                
                if (r_ok && s_ok) {
                    mbedtls_mpi r, s;
                    mbedtls_mpi_init(&r);
                    mbedtls_mpi_init(&s);
                    
                    if (mbedtls_mpi_read_binary(&r, r_bytes, 32) == 0 &&
                        mbedtls_mpi_read_binary(&s, s_bytes, 32) == 0) {
                        mbedtls_ecdsa_context ecdsa;
                        mbedtls_ecdsa_init(&ecdsa);
                        mbedtls_ecp_group_copy(&ecdsa.grp, &ecp->grp);
                        mbedtls_ecp_copy(&ecdsa.Q, &ecp->Q);
                        
                        int ecdsa_ret = mbedtls_ecdsa_read_signature(&ecdsa, hash, 32, sig_data, sig_size);
                        if (ecdsa_ret == 0) {
                            ret = 0;
                        } else {
                            mbedtls_pk_context pk_ecdsa;
                            mbedtls_pk_init(&pk_ecdsa);
                            if (mbedtls_pk_setup(&pk_ecdsa, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)) == 0) {
                                mbedtls_ecp_keypair* ecp_new = mbedtls_pk_ec(pk_ecdsa);
                                if (ecp_new) {
                                    mbedtls_ecp_group_copy(&ecp_new->grp, &ecp->grp);
                                    mbedtls_ecp_copy(&ecp_new->Q, &ecp->Q);
                                    ecdsa_ret = mbedtls_pk_verify(&pk_ecdsa, MBEDTLS_MD_SHA256, hash, 32, sig_data, sig_size);
                                    if (ecdsa_ret == 0) ret = 0;
                                }
                            }
                            mbedtls_pk_free(&pk_ecdsa);
                        }
                        mbedtls_ecdsa_free(&ecdsa);
                    }
                    mbedtls_mpi_free(&r);
                    mbedtls_mpi_free(&s);
                }
            }
        }
    }
    
    mbedtls_pk_free(&pk);
    free(sig_data);
    
    if (ret != 0) {
        Serial.println("VERIFY_FAIL");
        return false;
    }
    return true;
}

static bool apply_stream_patch_from_encrypted(const char* encrypted_patch_file) {
    File enc = LittleFS.open(encrypted_patch_file, "r");
    if (!enc) {
        Serial.println("APPLY_FAIL:OPEN_ENC");
        return false;
    }
    size_t file_size = enc.size();
    if (file_size < REM_HEADER_SIZE + REM_TAG_SIZE + 1) {
        enc.close();
        Serial.println("APPLY_FAIL:ENC_TOO_SMALL");
        return false;
    }
    uint8_t magic[4];
    if (enc.read(magic, 4) != 4 || memcmp(magic, REM_MAGIC, 4) != 0) {
        enc.close();
        Serial.println("APPLY_FAIL:BAD_MAGIC");
        return false;
    }
    uint8_t nonce[REM_NONCE_SIZE];
    if (enc.read(nonce, REM_NONCE_SIZE) != REM_NONCE_SIZE) {
        enc.close();
        Serial.println("APPLY_FAIL:READ_NONCE");
        return false;
    }
    size_t ciphertext_len = file_size - 4 - REM_NONCE_SIZE - REM_TAG_SIZE;
    uint8_t aes_key[32], hmac_key[32];
    rem_derive_keys(aes_key, hmac_key);
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    int ret = mbedtls_aes_setkey_enc(&aes, aes_key, 256);
    if (ret != 0) {
        mbedtls_aes_free(&aes);
        enc.close();
        Serial.println("APPLY_FAIL:AES_KEY");
        return false;
    }
    mbedtls_md_context_t md_ctx;
    mbedtls_md_init(&md_ctx);
    const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md || mbedtls_md_setup(&md_ctx, md, 1) != 0 || mbedtls_md_hmac_starts(&md_ctx, hmac_key, 32) != 0) {
        mbedtls_md_free(&md_ctx);
        mbedtls_aes_free(&aes);
        enc.close();
        Serial.println("APPLY_FAIL:HMAC_INIT");
        return false;
    }
    mbedtls_md_hmac_update(&md_ctx, nonce, REM_NONCE_SIZE);
    size_t iv_off = 0;
    const size_t chunk = 1024;
    uint8_t* in_buf = (uint8_t*)malloc(chunk);
    uint8_t* out_buf = (uint8_t*)malloc(chunk);
    if (!in_buf || !out_buf) {
        free(in_buf);
        free(out_buf);
        mbedtls_md_free(&md_ctx);
        mbedtls_aes_free(&aes);
        enc.close();
        Serial.println("APPLY_FAIL:OOM_BUFS");
        return false;
    }
    uint8_t plain_buf[2048];
    size_t plain_len = 0;
    size_t plain_pos = 0;

    auto fill_plain = [&]() -> bool {
        plain_len = 0;
        plain_pos = 0;
        if (ciphertext_len == 0) return false;
        size_t n = ciphertext_len > chunk ? chunk : ciphertext_len;
        size_t r = enc.read(in_buf, n);
        if (r == 0) return false;
        mbedtls_md_hmac_update(&md_ctx, in_buf, r);
        ret = mbedtls_aes_crypt_cfb128(&aes, MBEDTLS_AES_DECRYPT, r, &iv_off, nonce, in_buf, out_buf);
        if (ret != 0) return false;
        memcpy(plain_buf, out_buf, r);
        plain_len = r;
        ciphertext_len -= r;
        return true;
    };

    auto read_plain = [&](uint8_t* dst, size_t n) -> bool {
        size_t got = 0;
        while (got < n) {
            if (plain_pos >= plain_len) {
                if (!fill_plain()) return false;
            }
            size_t avail = plain_len - plain_pos;
            size_t take = (n - got) < avail ? (n - got) : avail;
            memcpy(dst + got, plain_buf + plain_pos, take);
            plain_pos += take;
            got += take;
        }
        return true;
    };

    uint8_t header[32];
    if (!read_plain(header, sizeof(header))) {
        free(in_buf);
        free(out_buf);
        mbedtls_aes_free(&aes);
        enc.close();
        Serial.println("APPLY_FAIL:READ_HEADER");
        return false;
    }
    if (memcmp(header, "BSDIFST1", 8) != 0) {
        free(in_buf);
        free(out_buf);
        mbedtls_aes_free(&aes);
        enc.close();
        Serial.println("APPLY_FAIL:BAD_MAGIC");
        return false;
    }
    int64_t new_size = read_bsdiff_int64_le(header + 8);
    int64_t old_size = read_bsdiff_int64_le(header + 16);
    if (new_size <= 0 || old_size <= 0) {
        free(in_buf);
        free(out_buf);
        mbedtls_aes_free(&aes);
        enc.close();
        Serial.println("APPLY_FAIL:BAD_SIZES");
        return false;
    }

    if (!Update.begin((size_t)new_size)) {
        free(in_buf);
        free(out_buf);
        mbedtls_aes_free(&aes);
        enc.close();
        Serial.print("APPLY_FAIL:UPDATE_BEGIN ");
        Serial.println(Update.errorString());
        return false;
    }

    const esp_partition_t* running = esp_ota_get_running_partition();
    if (!running) {
        free(in_buf);
        free(out_buf);
        mbedtls_aes_free(&aes);
        enc.close();
        Update.abort();
        Serial.println("APPLY_FAIL:RUNNING_PART");
        return false;
    }

    uint8_t* diff_buf = (uint8_t*)malloc(chunk);
    uint8_t* old_buf = (uint8_t*)malloc(chunk);
    uint8_t* write_buf = (uint8_t*)malloc(chunk);
    if (!diff_buf || !old_buf || !write_buf) {
        free(diff_buf);
        free(old_buf);
        free(write_buf);
        free(in_buf);
        free(out_buf);
        mbedtls_aes_free(&aes);
        enc.close();
        Update.abort();
        Serial.println("APPLY_FAIL:OOM_WORK");
        return false;
    }

    int64_t oldpos = 0;
    int64_t newpos = 0;
    while (newpos < new_size) {
        uint8_t ctrl_triplet[24];
        if (!read_plain(ctrl_triplet, sizeof(ctrl_triplet))) {
            free(diff_buf);
            free(old_buf);
            free(write_buf);
            free(in_buf);
            free(out_buf);
            mbedtls_aes_free(&aes);
            enc.close();
            Update.abort();
            Serial.println("APPLY_FAIL:READ_CTRL");
            return false;
        }
        int64_t x = read_bsdiff_int64_le(ctrl_triplet + 0);
        int64_t y = read_bsdiff_int64_le(ctrl_triplet + 8);
        int64_t z = read_bsdiff_int64_le(ctrl_triplet + 16);
        if (x < 0 || y < 0) {
            free(diff_buf);
            free(old_buf);
            free(write_buf);
            free(in_buf);
            free(out_buf);
            mbedtls_aes_free(&aes);
            enc.close();
            Update.abort();
            Serial.println("APPLY_FAIL:NEG_XY");
            return false;
        }
        if (newpos + x + y > new_size) {
            free(diff_buf);
            free(old_buf);
            free(write_buf);
            free(in_buf);
            free(out_buf);
            mbedtls_aes_free(&aes);
            enc.close();
            Update.abort();
            Serial.println("APPLY_FAIL:NEW_OVERFLOW");
            return false;
        }

        int64_t remaining = x;
        while (remaining > 0) {
            size_t n = (size_t)((remaining > (int64_t)chunk) ? chunk : remaining);
            if (!read_plain(diff_buf, n)) {
                free(diff_buf);
                free(old_buf);
                free(write_buf);
                free(in_buf);
                free(out_buf);
                mbedtls_aes_free(&aes);
                enc.close();
                Update.abort();
                Serial.println("APPLY_FAIL:READ_DIFF");
                return false;
            }
            if (oldpos < old_size) {
                int64_t n_old64 = (oldpos + (int64_t)n > old_size) ? (old_size - oldpos) : (int64_t)n;
                size_t n_old = (size_t)n_old64;
                if (n_old > 0) {
                    esp_err_t err = esp_partition_read(running, (size_t)oldpos, old_buf, n_old);
                    if (err != ESP_OK) {
                        free(diff_buf);
                        free(old_buf);
                        free(write_buf);
                        free(in_buf);
                        free(out_buf);
                        mbedtls_aes_free(&aes);
                        enc.close();
                        Update.abort();
                        Serial.println("APPLY_FAIL:READ_OLD");
                        return false;
                    }
                    for (size_t i = 0; i < n_old; i++) write_buf[i] = (uint8_t)(old_buf[i] + diff_buf[i]);
                    for (size_t i = n_old; i < n; i++) write_buf[i] = diff_buf[i];
                } else {
                    memcpy(write_buf, diff_buf, n);
                }
            } else {
                memcpy(write_buf, diff_buf, n);
            }
            size_t written = Update.write(write_buf, n);
            if (written != n) {
                free(diff_buf);
                free(old_buf);
                free(write_buf);
                free(in_buf);
                free(out_buf);
                mbedtls_aes_free(&aes);
                enc.close();
                Update.abort();
                Serial.print("APPLY_FAIL:WRITE_X ");
                Serial.println(Update.errorString());
                return false;
            }
            oldpos += (int64_t)n;
            newpos += (int64_t)n;
            remaining -= (int64_t)n;
        }

        remaining = y;
        while (remaining > 0) {
            size_t n = (size_t)((remaining > (int64_t)chunk) ? chunk : remaining);
            if (!read_plain(write_buf, n)) {
                free(diff_buf);
                free(old_buf);
                free(write_buf);
                free(in_buf);
                free(out_buf);
                mbedtls_aes_free(&aes);
                enc.close();
                Update.abort();
                Serial.println("APPLY_FAIL:READ_EXTRA");
                return false;
            }
            size_t written = Update.write(write_buf, n);
            if (written != n) {
                free(diff_buf);
                free(old_buf);
                free(write_buf);
                free(in_buf);
                free(out_buf);
                mbedtls_aes_free(&aes);
                enc.close();
                Update.abort();
                Serial.print("APPLY_FAIL:WRITE_Y ");
                Serial.println(Update.errorString());
                return false;
            }
            newpos += (int64_t)n;
            remaining -= (int64_t)n;
        }

        oldpos += x + z;
        if (oldpos < 0) {
            free(diff_buf);
            free(old_buf);
            free(write_buf);
            free(in_buf);
            free(out_buf);
            mbedtls_aes_free(&aes);
            enc.close();
            Update.abort();
            Serial.println("APPLY_FAIL:OLDPOS_NEG");
            return false;
        }
    }

    uint8_t tag_computed[REM_TAG_SIZE];
    mbedtls_md_hmac_finish(&md_ctx, tag_computed);
    mbedtls_md_free(&md_ctx);
    uint8_t tag_file[REM_TAG_SIZE];
    if (enc.read(tag_file, REM_TAG_SIZE) != REM_TAG_SIZE || memcmp(tag_computed, tag_file, REM_TAG_SIZE) != 0) {
        free(diff_buf);
        free(old_buf);
        free(write_buf);
        free(in_buf);
        free(out_buf);
        mbedtls_aes_free(&aes);
        enc.close();
        Serial.println("APPLY_FAIL:TAG_MISMATCH");
        return false;
    }
    free(diff_buf);
    free(old_buf);
    free(write_buf);
    free(in_buf);
    free(out_buf);
    mbedtls_aes_free(&aes);
    enc.close();

    if (!Update.end()) {
        Serial.print("APPLY_FAIL:UPDATE_END ");
        Serial.println(Update.errorString());
        return false;
    }

    LittleFS.remove("/patch.enc");
    return true;
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
        display1.setTextSize(1);
        display1.println(status);
        if (strlen(detail) > 0) {
            display1.setCursor(0, 20);
            display1.println(detail);
        }
        if (progress >= 0 && progress <= 100) {
            display1.setCursor(0, 35);
            display1.setTextSize(1);
            display1.print(progress);
            display1.println("%");
            int barWidth = (progress * 120) / 100;
            display1.drawRect(0, 55, 128, 8, SSD1306_WHITE);
            display1.fillRect(2, 57, barWidth, 4, SSD1306_WHITE);
        }
        display1.display();
    }

    if (display2_ready) {
        display2.clearDisplay();
        display2.setTextSize(1);
        display2.setTextColor(SSD1306_WHITE);
        display2.setCursor(0, 0);
        display2.print("ID: ");
        display2.println(DEVICE_ID);
        display2.setCursor(0, 12);
        display2.print("Ver: ");
        display2.println(CURRENT_VERSION);
        display2.setCursor(0, 24);
        display2.print("Status: ");
        display2.println(status);
        if (strlen(detail) > 0) {
            display2.setCursor(0, 36);
            display2.println(detail);
        }
        display2.display();
    }
}


void run_update_flow() {
    WiFiClient client;
    String check_url = String("/check_update/?device_id=") + DEVICE_ID + "&version=" + CURRENT_VERSION;
    
    update_display_split("Checking", "Server...", 0);
    
    if (!client.connect(SERVER_HOST, SERVER_PORT)) {
        Serial.println("CONN_FAIL");
        update_display_split("Connection", "FAILED", 0);
        delay(3000);
        return;
    }
    
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
    
    update_display_split("Update Found!", (old_version + " -> " + new_version).c_str(), 20);
    delay(2000);
    
    String patch_url = String("/get_patch/") + old_version + "/" + new_version + "/" + DEVICE_ID;
    String sig_url = String("/get_signature/") + old_version + "/" + new_version;
    
    update_display_split("Downloading", "Patch file...", 30);
    
    WiFiClient client2;
    if (!download_to_file(client2, patch_url.c_str(), "/patch.enc", true)) {
        Serial.println("DOWNLOAD_FAIL:PATCH");
        update_display_split("Download", "FAILED!", 0);
        delay(3000);
        return;
    }
    
    update_display_split("Downloading", "Signature...", 60);
    
    WiFiClient client3;
    if (!download_to_file(client3, sig_url.c_str(), "/patch.sig", false)) {
        Serial.println("DOWNLOAD_FAIL:SIG");
        update_display_split("Sig Download", "FAILED!", 0);
        delay(3000);
        return;
    }
    
    update_display_split("Verifying", "Signature...", 80);
    delay(500);
    
    if (!verify_signature_encrypted("/patch.enc", "/patch.sig")) {
        Serial.println("VERIFY_FAIL");
        update_display_split("Verification", "FAILED!", 0);
        delay(3000);
        return;
    }
    
    update_display_split("Applying", "Patch to OTA...", 90);
    delay(500);

    if (!apply_stream_patch_from_encrypted("/patch.enc")) {
        Serial.println("APPLY_FAIL");
        update_display_split("Apply Failed", "Check Serial", 0);
        delay(5000);
        return;
    }
    
    update_display_split("SUCCESS!", "Rebooting...", 100);
    delay(3000);
    
    ESP.restart();
}

void setup() {
    Serial.begin(115200);
    delay(1000);
    
    if (!LittleFS.begin(true)) {
        Serial.println("LITTLEFS_FAIL:MOUNT");
        return;
    }
    
    LittleFS.remove("/patch.enc");
    LittleFS.remove("/patch.bsdiff");
    LittleFS.remove("/patch.sig");
    
    Wire.begin();
    display1_ready = display1.begin(SSD1306_SWITCHCAPVCC, 0x3C);
    display2_ready = display2.begin(SSD1306_SWITCHCAPVCC, 0x3D);
    
    if (display1_ready) {
        display1.clearDisplay();
        display1.setTextSize(1);
        display1.setTextColor(SSD1306_WHITE);
        display1.setCursor(5, 10);
        display1.println("OLED 0x3C");
        display1.setCursor(5, 30);
        display1.setTextSize(1);
        display1.println("READY");
        display1.display();
        delay(100);
    }
    
    if (display2_ready) {
        display2.clearDisplay();
        display2.setTextSize(1);
        display2.setTextColor(SSD1306_WHITE);
        display2.setCursor(5, 10);
        display2.println("OLED 0x3D");
        display2.setCursor(5, 30);
        display2.setTextSize(1);
        display2.println("READY");
        display2.display();
        delay(100);
    }
    
    delay(3000);
    
    update_display_split("Initializing", "WiFi...", 5);
    
    WiFi.mode(WIFI_STA);
    WiFi.setSleep(false);
    WiFi.setAutoReconnect(true);
    WiFi.disconnect();
    delay(500);
    
    update_display_split("Scanning", "Networks...", 10);
    WiFi.scanNetworks();
    
    update_display_split("Connecting", "WiFi...", 20);
    WiFi.begin(WIFI_SSID, WIFI_PASS);
    
    int attempts = 0;
    int max_attempts = 80;
    while (WiFi.status() != WL_CONNECTED && attempts < max_attempts) {
        delay(500);
        int progress = 20 + (attempts * 75 / max_attempts);
        if (progress > 95) progress = 95;
        update_display_split("Connecting", "WiFi...", progress);
        attempts++;
    }
    
    if (WiFi.status() != WL_CONNECTED) {
        Serial.println("WIFI_FAIL");
        update_display_split("WiFi", "FAILED!", 0);
        delay(5000);
        return;
    }
    
    update_display_split("WiFi Connected", WiFi.localIP().toString().c_str(), 40);
    delay(2000);
    
    update_display_split("Checking", "PUBKEY...", 50);
    
    File pubkey = LittleFS.open("/server_pub.pem", "r");
    if (!pubkey) {
        File pubkey2 = LittleFS.open("server_pub.pem", "r");
        if (!pubkey2) {
            Serial.println("PUBKEY_NOT_FOUND");
            update_display_split("PUBKEY", "NOT FOUND!", 0);
            delay(10000);
            return;
        }
        pubkey2.close();
    } else {
        pubkey.close();
    }
    
    update_display_split("PUBKEY", "Found OK", 60);
    delay(1000);
    
    update_display_split("Ready", "Waiting...", 100);
    delay(2000);
    
    run_update_flow();
}

void loop() {
    delay(60000);
    run_update_flow();
}


