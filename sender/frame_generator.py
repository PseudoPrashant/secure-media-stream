# frame_generator.py - Simulates video frames as NumPy arrays
# Generates fake media frames that behave like real video data

import numpy as np
from shared.config import FRAME_COUNT

def generate_frame(frame_id: int) -> tuple[np.ndarray, tuple]:
    """
    Generates a simulated video frame as a NumPy array.

    Args:
        frame_id : the sequence number of this frame

    Returns:
        frame       : 2D NumPy array of pixel values (480 x 640)
        frame_shape : tuple of (height, width) → (480, 640)
    """
    # Generate a 480x640 frame of random pixel values between 0 and 255
    frame = np.random.randint(0, 256, (480, 640), dtype=np.uint8)

    # Embed the frame_id into the first pixel so receiver can verify ordering
    frame[0][0] = frame_id % 256

    # Get the shape of the frame
    frame_shape = frame.shape

    return frame, frame_shape

def frame_to_bytes(frame: np.ndarray) -> bytes:
    """
    Converts a NumPy frame array into raw bytes for encryption.

    Args:
        frame : 2D NumPy array of pixel values

    Returns:
        raw bytes of the frame ready for encryption
    """
    return frame.tobytes()

def get_frames():
    """
    Generator function that yields frames one by one.
    Used by sender.py to get frames for transmission.

    Yields:
        frame_id    : sequence number of the frame
        frame_bytes : raw bytes of the frame ready for encryption
        frame_shape : tuple of (height, width)
    """
    for frame_id in range(1, FRAME_COUNT + 1):
        frame, frame_shape = generate_frame(frame_id)
        frame_bytes = frame_to_bytes(frame)
        print(f"[GENERATOR] Frame {frame_id} generated → {len(frame_bytes)} bytes")
        yield frame_id, frame_bytes, frame_shape