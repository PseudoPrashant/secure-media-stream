# config.py - Shared settings (port, host, keys)
HOST = "127.0.0.1"       # Localhost (sender and receiver on same machine)
PORT = 9999              # Port both sender and receiver will use
 
# ── Sender Identity ───────────────────────────────────────────────
SENDER_ID = "CAM_DEVICE_01"   # Unique ID of the sending device
 
# ── Encryption Key (AES-256 = 32 bytes) ──────────────────────────
AES_KEY = b"01234567890123456789012345678901"  # 32 bytes exactly
 
# ── HMAC Secret Key (for packet authentication) ───────────────────
HMAC_KEY = b"super-secret-hmac-key-for-demo"
 
# ── Transmission Settings ─────────────────────────────────────────
FRAME_COUNT = 10         # Number of frames the sender will transmit
FRAME_DELAY = 0.5        # Seconds between each frame transmission
 
# ── Logging ───────────────────────────────────────────────────────
LOG_FILE = "logs/receiver.log"