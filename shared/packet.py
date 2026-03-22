# packet.py - Custom Packet Structure (Build & Parse)
# Defines how data is organized before transmission and reconstructed on arrival

import json
import time
import hmac
import hashlib
import struct


# ── Packet Structure Overview ─────────────────────────────────────
#
#  Every packet sent over the network has this exact layout:
#
#  [ HEADER (fixed 23 bytes) ] [ METADATA (variable) ] [ PAYLOAD (variable) ] [ HMAC (32 bytes) ]
#
#  HEADER fields (packed as binary using struct):
#    - magic_number  : 4 bytes  → always "SMSF" (SecureMediaStreamFrame)
#                                 receiver uses this to confirm it's our packet
#    - version       : 1 byte   → protocol version number (currently 1)
#    - frame_id      : 4 bytes  → sequential frame number (1, 2, 3 ...)
#    - timestamp     : 8 bytes  → unix time when frame was sent (float)
#    - metadata_len  : 2 bytes  → how many bytes the metadata section is
#    - payload_len   : 4 bytes  → how many bytes the payload section is
#
#  METADATA (variable length JSON):
#    - sender_id     : who sent this packet (e.g. "CAM_DEVICE_01")
#    - frame_width   : width of the simulated frame
#    - frame_height  : height of the simulated frame
#    - encoding      : data encoding type (e.g. "numpy_uint8")
#
#  PAYLOAD (variable):
#    - nonce         : first 12 bytes → AES GCM nonce
#    - ciphertext    : remaining bytes → encrypted frame data
#
#  HMAC (fixed 32 bytes):
#    - SHA256 HMAC signature of everything above
#    - receiver recalculates this and compares to verify authenticity
#
# ─────────────────────────────────────────────────────────────────

# Header format string for struct.pack / struct.unpack
# > = big-endian
# 4s = 4 char bytes (magic number)
# B  = unsigned char  (1 byte)  for version
# I  = unsigned int   (4 bytes) for frame_id
# d  = double         (8 bytes) for timestamp
# H  = unsigned short (2 bytes) for metadata_len
# I  = unsigned int   (4 bytes) for payload_len
HEADER_FORMAT = ">4sBIdHI"
HEADER_SIZE   = struct.calcsize(HEADER_FORMAT)  # 23 bytes

MAGIC_NUMBER  = b"SMSF"   # Identifies our custom protocol
VERSION       = 1          # Protocol version
HMAC_SIZE     = 32         # SHA256 produces 32 bytes


def build_packet(
    frame_id: int,
    sender_id: str,
    nonce: bytes,
    ciphertext: bytes,
    frame_shape: tuple,
    hmac_key: bytes
) -> bytes:
    """
    Assembles a complete packet from its components.

    Args:
        frame_id    : sequential frame number
        sender_id   : string ID of the sending device
        nonce       : 12-byte AES GCM nonce
        ciphertext  : encrypted frame bytes
        frame_shape : (height, width) of the original frame
        hmac_key    : secret key for HMAC signing

    Returns:
        packet      : complete byte string ready to send over the socket
    """

    # ── 1. Build Metadata ─────────────────────────────────────────
    metadata = json.dumps({
        "sender_id"    : sender_id,
        "frame_height" : frame_shape[0],
        "frame_width"  : frame_shape[1],
        "encoding"     : "numpy_uint8"
    }).encode("utf-8")

    # ── 2. Build Payload (nonce + ciphertext joined together) ─────
    payload = nonce + ciphertext

    # ── 3. Build Header ───────────────────────────────────────────
    header = struct.pack(
        HEADER_FORMAT,
        MAGIC_NUMBER,           # 4s
        VERSION,                # B
        frame_id,               # I
        time.time(),            # d  (current unix timestamp)
        len(metadata),          # H
        len(payload)            # I
    )

    # ── 4. Compute HMAC over header + metadata + payload ─────────
    # This signs everything so the receiver can verify nothing was changed
    mac = hmac.new(hmac_key, header + metadata + payload, hashlib.sha256).digest()

    # ── 5. Assemble final packet ──────────────────────────────────
    packet = header + metadata + payload + mac

    return packet


def parse_packet(raw: bytes, hmac_key: bytes) -> dict:
    """
    Parses and validates a raw received packet.

    Steps:
      1. Extract and decode the header
      2. Verify magic number and version
      3. Extract metadata and payload using lengths from header
      4. Verify HMAC signature — reject packet if invalid
      5. Split payload back into nonce and ciphertext
      6. Return all fields as a clean dictionary

    Args:
        raw      : the raw bytes received from the socket
        hmac_key : secret key to verify the HMAC signature

    Returns:
        parsed   : dictionary with all packet fields
                   or raises ValueError if packet is invalid
    """

    # ── 1. Unpack Header ──────────────────────────────────────────
    header_raw = raw[:HEADER_SIZE]
    magic, version, frame_id, timestamp, metadata_len, payload_len = struct.unpack(
        HEADER_FORMAT, header_raw
    )

    # ── 2. Validate Magic Number & Version ────────────────────────
    if magic != MAGIC_NUMBER:
        raise ValueError(f"Invalid magic number: {magic} — not an SMSF packet")

    if version != VERSION:
        raise ValueError(f"Unsupported protocol version: {version}")

    # ── 3. Extract Metadata & Payload ────────────────────────────
    meta_start    = HEADER_SIZE
    meta_end      = meta_start + metadata_len
    payload_start = meta_end
    payload_end   = payload_start + payload_len
    hmac_start    = payload_end

    metadata_raw  = raw[meta_start:meta_end]
    payload       = raw[payload_start:payload_end]
    received_mac  = raw[hmac_start:hmac_start + HMAC_SIZE]

    # ── 4. Verify HMAC ────────────────────────────────────────────
    # Recompute HMAC over header + metadata + payload
    expected_mac = hmac.new(
        hmac_key,
        header_raw + metadata_raw + payload,
        hashlib.sha256
    ).digest()

    # Use compare_digest to prevent timing attacks
    if not hmac.compare_digest(received_mac, expected_mac):
        raise ValueError("HMAC verification failed — packet may have been tampered with")

    # ── 5. Decode Metadata ────────────────────────────────────────
    metadata = json.loads(metadata_raw.decode("utf-8"))

    # ── 6. Split Payload into Nonce + Ciphertext ──────────────────
    nonce      = payload[:12]
    ciphertext = payload[12:]

    # ── 7. Return All Fields ──────────────────────────────────────
    return {
        "frame_id"     : frame_id,
        "timestamp"    : timestamp,
        "sender_id"    : metadata["sender_id"],
        "frame_height" : metadata["frame_height"],
        "frame_width"  : metadata["frame_width"],
        "encoding"     : metadata["encoding"],
        "nonce"        : nonce,
        "ciphertext"   : ciphertext,
    }