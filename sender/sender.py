# sender.py - Main Sender Logic
# Ties together frame generation, encryption, packet building and transmission

import socket
import time
import logging
import json
from shared.config import HOST, PORT, AES_KEY, HMAC_KEY, SENDER_ID, FRAME_DELAY
from shared.encryption import encrypt
from shared.packet import build_packet
from sender.frame_generator import get_frames


# ── Logging Setup ─────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SENDER] %(message)s",
    handlers=[
        logging.StreamHandler(),                        # prints to terminal
        logging.FileHandler("logs/sender.log")          # saves to log file
    ]
)

log = logging.getLogger(__name__)


def send_length_prefixed(sock: socket.socket, data: bytes):
    """
    Sends data over the socket with a 4 byte length prefix.

    Why? TCP is a stream protocol — it doesn't know where one packet ends
    and another begins. By sending the length first the receiver knows
    exactly how many bytes to read for each packet.

    Args:
        sock : the connected socket
        data : the complete packet bytes to send
    """
    # Pack the length as a 4 byte big endian integer
    length = len(data).to_bytes(4, byteorder="big")

    # [IMPROVEMENT]: Send length and data separately instead of concatenating.
    # This avoids copying the potentially large data byte string into a new object.
    sock.sendall(length)
    sock.sendall(data)


def run_sender():
    """
    Main sender function.
    Connects to receiver, transmits all frames, then closes connection.
    """

    log.info(f"Starting sender - Device ID: {SENDER_ID}")
    log.info(f"Connecting to receiver at {HOST}:{PORT}...")

    # ── 1. Create TCP Socket & Connect ───────────────────────────
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        log.info(f"Connected to receiver at {HOST}:{PORT}")

        # ── 2. Pre-compute Metadata ───────────────────────────────────
        # [IMPROVEMENT]: Generate JSON once since these values don't change per frame
        metadata_bytes = None

        # ── 3. Transmit Frames One by One ─────────────────────────
        for frame_id, frame_bytes, frame_shape in get_frames():
            
            if metadata_bytes is None:
                metadata_bytes = json.dumps({
                    "sender_id"    : SENDER_ID,
                    "frame_height" : frame_shape[0],
                    "frame_width"  : frame_shape[1],
                    "encoding"     : "numpy_uint8"
                }).encode("utf-8")

            # Step 1 — Encrypt the frame
            nonce, ciphertext = encrypt(frame_bytes, AES_KEY)
            log.info(f"Frame {frame_id} encrypted - {len(ciphertext)} bytes")

            # Step 2 — Build the packet
            packet = build_packet(
                frame_id=frame_id,
                metadata_bytes=metadata_bytes,
                nonce=nonce,
                ciphertext=ciphertext,
                hmac_key=HMAC_KEY
            )
            log.info(f"Frame {frame_id} packet built - {len(packet)} bytes total")

            # Step 3 — Send the packet over the socket
            send_length_prefixed(sock, packet)
            log.info(f"Frame {frame_id} sent successfully -OK ")

            # Step 4 — Wait before sending next frame
            time.sleep(FRAME_DELAY)

        # ── 3. Signal End of Transmission ─────────────────────────
        # Send a 4 byte zero signal to tell receiver we are done
        sock.sendall(b'\x00\x00\x00\x00')
        log.info("All frames transmitted - end signal sent")

    log.info("Connection closed - transmission complete")


if __name__ == "__main__":
    run_sender()