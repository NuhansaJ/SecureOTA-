import bz2
import os
import bsdiff4

def _offtin(buf: bytes) -> int:
    y = buf[7] & 0x7F
    for i in range(6, -1, -1):
        y = y * 256 + buf[i]
    if buf[7] & 0x80:
        y = -y
    return y

def _offtout(x: int) -> bytes:
    y = x
    neg = 0
    if y < 0:
        neg = 0x80
        y = -y
    out = bytearray(8)
    for i in range(8):
        out[i] = y & 0xFF
        y >>= 8
    out[7] |= neg
    return bytes(out)

def generate_patch(old_bin_path, new_bin_path, patch_output_path):
    try:
        # Use bsdiff4 library to create the patch
        with open(old_bin_path, "rb") as f:
            old_data = f.read()
        with open(new_bin_path, "rb") as f:
            new_data = f.read()
        
        patch_data = bsdiff4.diff(old_data, new_data)
        
        with open(patch_output_path, "wb") as f:
            f.write(patch_data)
        
        patch = patch_data

        if len(patch) < 32 or patch[:8] != b"BSDIFF40":
            return False

        ctrl_len_c = _offtin(patch[8:16])
        diff_len_c = _offtin(patch[16:24])
        new_size = _offtin(patch[24:32])
        if ctrl_len_c < 0 or diff_len_c < 0 or new_size < 0:
            return False

        end_ctrl = 32 + ctrl_len_c
        end_diff = end_ctrl + diff_len_c
        if end_ctrl > len(patch) or end_diff > len(patch):
            return False

        ctrl_c = patch[32:end_ctrl]
        diff_c = patch[end_ctrl:end_diff]
        extra_c = patch[end_diff:]

        ctrl = bz2.decompress(ctrl_c)
        diff = bz2.decompress(diff_c)
        extra = bz2.decompress(extra_c)

        old_size = os.path.getsize(old_bin_path)
        if len(ctrl) % 24 != 0:
            return False

        out = bytearray()
        out += b"BSDIFST1"
        out += _offtout(new_size)
        out += _offtout(old_size)
        out += _offtout(0)

        diff_pos = 0
        extra_pos = 0
        new_pos = 0

        for i in range(0, len(ctrl), 24):
            x = _offtin(ctrl[i:i+8])
            y = _offtin(ctrl[i+8:i+16])
            z = _offtin(ctrl[i+16:i+24])
            if x < 0 or y < 0:
                return False
            if new_pos + x + y > new_size:
                return False
            if diff_pos + x > len(diff):
                return False
            if extra_pos + y > len(extra):
                return False

            out += ctrl[i:i+24]
            out += diff[diff_pos:diff_pos + x]
            out += extra[extra_pos:extra_pos + y]

            diff_pos += x
            extra_pos += y
            new_pos += x + y

            if z < 0:
                pass

        with open(patch_output_path, "wb") as f:
            f.write(out)

        return True
    except Exception as e:
        print(f"Error generating patch: {str(e)}")
        return False
    finally:
        pass

