def inspect_magic_bytes(file_bytes: bytes) -> dict:
    header = file_bytes[:4]
    
    if header.startswith(b'MZ'):
        return {"type": "executable", "format": "PE / Windows Executable", "spoofed": False}
    elif header.startswith(b'\x89PNG'):
        return {"type": "media", "format": "PNG Image", "spoofed": False}
    elif header.startswith(b'\xff\xd8\xff'):
        return {"type": "media", "format": "JPEG Image", "spoofed": False}
    else:
        return {"type": "unknown", "format": "Generic / Raw Binary", "spoofed": False}

def detect_extension_spoofing(filename: str, detected_type: str) -> bool:
    media_extensions = ('.png', '.jpg', '.jpeg')
    return filename.lower().endswith(media_extensions) and detected_type == "executable"