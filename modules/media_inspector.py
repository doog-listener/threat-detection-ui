import io
import math
from collections import Counter
import numpy as np
from PIL import Image, UnidentifiedImageError

def calculate_shannon_entropy(file_bytes: bytes):
    """
    Calculates Shannon entropy on uncompressed pixel data (for images)
    or raw byte streams (for raw executables/binaries).
    """
    if not file_bytes:
        return 0.0, "LOW (Empty File)"

    try:
        # For images: analyze uncompressed pixel value distribution (0-255)
        img = Image.open(io.BytesIO(file_bytes)).convert('L')
        data = np.array(img).flatten()
        length = len(data)
        counts = Counter(data)
    except Exception:
        # Fallback for raw binary payloads
        data = file_bytes
        length = len(data)
        counts = Counter(data)

    entropy = 0.0
    for count in counts.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)

    # Calibrated thresholds for uncompressed pixel distributions:
    # Standard UI / Screenshots / Photos: 2.0 - 6.5
    # High-texture images: 6.5 - 7.3
    # Encrypted / Obfuscated Steganographic payload noise: > 7.5
    if entropy > 7.5:
        risk = "HIGH (Encrypted/Obfuscated Payload Risk)"
    elif entropy > 6.8:
        risk = "MEDIUM (Suspicious or Dense Noise)"
    else:
        risk = "LOW (Standard Structure)"

    return entropy, risk

def extract_lsb_text(file_bytes: bytes) -> str:
    """Attempts to extract LSB text, safely failing if the file is not a valid image."""
    try:
        img = Image.open(io.BytesIO(file_bytes)).convert("RGB")
        pixels = list(img.getdata())

        binary_data = ""
        # Scan first 200 pixels to inspect sample
        for pixel in pixels[:200]:
            binary_data += str(pixel[0] & 1)

        extracted_chars = []
        for i in range(0, len(binary_data), 8):
            byte = binary_data[i:i+8]
            if len(byte) == 8:
                char_code = int(byte, 2)
                if 32 <= char_code <= 126:
                    extracted_chars.append(chr(char_code))
                else:
                    extracted_chars.append(".")

        sample = "".join(extracted_chars)
        return sample if sample else "No readable LSB data found."

    except UnidentifiedImageError:
        return "N/A (Non-image / Raw byte structure)"
    except Exception as e:
        return f"Extraction error: {str(e)}"