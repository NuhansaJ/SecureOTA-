#include "bspatch_stub.h"
#include <LittleFS.h>
#include <Update.h>
#include <Arduino.h>
#include <esp_partition.h>
#include <esp_ota_ops.h>
#include <string.h>

static int64_t read_int64_from_buffer(const uint8_t* buf, size_t& pos) {
    if (pos + 8 > 0xFFFFFFFF) {
        return -1;
    }
    
    int64_t result = 0;
    for (int i = 0; i < 8; i++) {
        result |= ((int64_t)buf[pos + i] & 0xFF) << (8 * (7 - i));
    }
    pos += 8;
    
    int64_t sign = result & 0x8000000000000000LL;
    if (sign != 0) {
        result = -((~result) + 1);
    }
    
    return result;
}

bool apply_patch_to_ota(const char* patch_file_path) {
    File patch_file = LittleFS.open(patch_file_path, "r");
    if (!patch_file) {
        Serial.println("Failed to open patch file");
        return false;
    }
    
    const esp_partition_t* running = esp_ota_get_running_partition();
    if (!running) {
        Serial.println("Failed to get running partition");
        patch_file.close();
        return false;
    }
    
    const esp_partition_t* update_partition = esp_ota_get_next_update_partition(NULL);
    if (!update_partition) {
        Serial.println("No OTA partition available");
        patch_file.close();
        return false;
    }
    
    uint8_t header[32];
    if (patch_file.read(header, 32) != 32) {
        Serial.println("Failed to read patch header");
        patch_file.close();
        return false;
    }
    
    size_t pos = 0;
    int64_t header_magic = read_int64_from_buffer(header, pos);
    if (header_magic != 0x3034464649445342LL) {
        Serial.println("Invalid patch file format");
        patch_file.close();
        return false;
    }
    
    int64_t ctrl_len = read_int64_from_buffer(header, pos);
    int64_t diff_len = read_int64_from_buffer(header, pos);
    int64_t new_size = read_int64_from_buffer(header, pos);
    
    if (ctrl_len < 0 || diff_len < 0 || new_size < 0) {
        Serial.println("Invalid patch file header");
        patch_file.close();
        return false;
    }
    
    Serial.printf("Patch: ctrl=%lld, diff=%lld, new_size=%lld\n", ctrl_len, diff_len, new_size);
    
    if (!Update.begin(new_size)) {
        Serial.printf("Update.begin failed: %s\n", Update.errorString());
        patch_file.close();
        return false;
    }
    
    size_t old_size = running->size;
    uint8_t* old_data = (uint8_t*)malloc(old_size);
    if (!old_data) {
        Serial.println("Failed to allocate memory for old firmware");
        Update.abort();
        patch_file.close();
        return false;
    }
    
    esp_err_t err = esp_partition_read(running, 0, old_data, old_size);
    if (err != ESP_OK) {
        Serial.printf("Failed to read current firmware: %s\n", esp_err_to_name(err));
        free(old_data);
        Update.abort();
        patch_file.close();
        return false;
    }
    
    uint8_t* new_data = (uint8_t*)malloc(new_size);
    if (!new_data) {
        Serial.println("Failed to allocate memory for new firmware");
        free(old_data);
        Update.abort();
        patch_file.close();
        return false;
    }
    
    uint8_t* ctrl = (uint8_t*)malloc(ctrl_len);
    uint8_t* diff = (uint8_t*)malloc(diff_len);
    uint8_t* extra = (uint8_t*)malloc(new_size);
    
    if (!ctrl || !diff || !extra) {
        Serial.println("Failed to allocate memory for patch data");
        free(old_data);
        free(new_data);
        free(ctrl);
        free(diff);
        free(extra);
        Update.abort();
        patch_file.close();
        return false;
    }
    
    if (patch_file.read(ctrl, ctrl_len) != ctrl_len) {
        Serial.println("Failed to read control block");
        free(old_data);
        free(new_data);
        free(ctrl);
        free(diff);
        free(extra);
        Update.abort();
        patch_file.close();
        return false;
    }
    
    if (patch_file.read(diff, diff_len) != diff_len) {
        Serial.println("Failed to read diff block");
        free(old_data);
        free(new_data);
        free(ctrl);
        free(diff);
        free(extra);
        Update.abort();
        patch_file.close();
        return false;
    }
    
    size_t extra_len = patch_file.size() - patch_file.position();
    if (patch_file.read(extra, extra_len) != extra_len) {
        Serial.println("Failed to read extra block");
        free(old_data);
        free(new_data);
        free(ctrl);
        free(diff);
        free(extra);
        Update.abort();
        patch_file.close();
        return false;
    }
    patch_file.close();
    
    int64_t oldpos = 0;
    int64_t newpos = 0;
    int64_t ctrlpos = 0;
    int64_t diffpos = 0;
    int64_t extrapos = 0;
    
    while (newpos < new_size) {
        int64_t ctrl_data[3];
        for (int i = 0; i < 3; i++) {
            if (ctrlpos + 8 > ctrl_len) {
                Serial.println("Control block underflow");
                free(old_data);
                free(new_data);
                free(ctrl);
                free(diff);
                free(extra);
                Update.abort();
                return false;
            }
            size_t temp_pos = ctrlpos;
            ctrl_data[i] = read_int64_from_buffer(ctrl, temp_pos);
            ctrlpos = temp_pos;
        }
        
        int64_t x = ctrl_data[0];
        int64_t y = ctrl_data[1];
        int64_t z = ctrl_data[2];
        
        if (newpos + x > new_size) {
            Serial.println("Output overflow");
            free(old_data);
            free(new_data);
            free(ctrl);
            free(diff);
            free(extra);
            Update.abort();
            return false;
        }
        
        if (diffpos + x > diff_len) {
            Serial.println("Diff block underflow");
            free(old_data);
            free(new_data);
            free(ctrl);
            free(diff);
            free(extra);
            Update.abort();
            return false;
        }
        
        for (int64_t i = 0; i < x; i++) {
            if (oldpos + i >= old_size) {
                new_data[newpos + i] = diff[diffpos + i];
            } else {
                new_data[newpos + i] = old_data[oldpos + i] + diff[diffpos + i];
            }
        }
        
        newpos += x;
        oldpos += x;
        diffpos += x;
        
        if (newpos + y > new_size) {
            Serial.println("Extra block overflow");
            free(old_data);
            free(new_data);
            free(ctrl);
            free(diff);
            free(extra);
            Update.abort();
            return false;
        }
        
        if (extrapos + y > extra_len) {
            Serial.println("Extra block underflow");
            free(old_data);
            free(new_data);
            free(ctrl);
            free(diff);
            free(extra);
            Update.abort();
            return false;
        }
        
        memcpy(&new_data[newpos], &extra[extrapos], y);
        newpos += y;
        extrapos += y;
        
        oldpos += z;
    }
    
    free(old_data);
    free(ctrl);
    free(diff);
    free(extra);
    
    size_t written = Update.write(new_data, new_size);
    free(new_data);
    
    if (written != new_size) {
        Serial.printf("Update.write failed: wrote %d of %lld\n", written, new_size);
        Update.abort();
        return false;
    }
    
    if (!Update.end()) {
        Serial.printf("Update.end failed: %s\n", Update.errorString());
        return false;
    }
    
    Serial.println("Patch applied successfully");
    return true;
}
