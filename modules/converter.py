import math
import numpy as np
from PIL import Image

def bytes_to_matrix_image(file_bytes: bytes, target_size=(224, 224)) -> Image.Image:
    """
    Converts raw binary byte streams into a 2D grayscale texture matrix.
    For large executables, samples up to the first 256KB to preserve PE 
    headers and code sections rather than averaging bytes into flat gray.
    """
    if not file_bytes:
        raise ValueError("Empty byte sequence received.")

    # Cap sampling window to 256 KB to preserve PE structure & prevent gray wash
    SAMPLE_LIMIT = 262144  # 256 * 1024 bytes
    stream = file_bytes[:SAMPLE_LIMIT]
    length = len(stream)

    # Standard Nataraj et al. width rules based on binary size
    if length < 10240:
        width = 32
    elif length < 30720:
        width = 64
    elif length < 61440:
        width = 128
    elif length < 102400:
        width = 256
    elif length < 204800:
        width = 384
    else:
        width = 512

    height = int(math.ceil(length / width))
    total_expected = width * height

    # Pad trailing bytes with nulls if needed to complete the rectangular matrix
    raw_array = np.frombuffer(stream, dtype=np.uint8)
    if length < total_expected:
        padded = np.pad(raw_array, (0, total_expected - length), mode='constant', constant_values=0)
    else:
        padded = raw_array[:total_expected]

    matrix_2d = padded.reshape((height, width))
    img = Image.fromarray(matrix_2d, mode='L')
    
    # Resize to the ResNet-50 input dimension using nearest neighbor to preserve sharp opcode edges
    return img.resize(target_size, Image.Resampling.NEAREST).convert('RGB')