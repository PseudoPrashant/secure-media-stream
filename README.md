# secure-media-stream

A prototype system for **secure real-time media frame transmission** over a TCP network.  
Built as part of an internship challenge demonstrating networking, packet design, and security concepts.

---

## System Overview

This system simulates an intelligent monitoring platform where remote devices capture live visual data and transmit it securely to a central processing unit.

```
┌─────────────────────────┐         TCP Socket          ┌─────────────────────────┐
│      SENDER (Python)    │  ──── SMSF Packets ────►   │    RECEIVER (C++)       │
│                         │                             │                         │
│  • Generates frames     │                             │  • Accepts connection   │
│  • Encrypts with AES    │                             │  • Verifies HMAC        │
│  • Builds SMSF packet   │                             │  • Decrypts payload     │
│  • Transmits over TCP   │                             │  • Logs all activity    │
└─────────────────────────┘                             └─────────────────────────┘
```

---

## Project Structure

```
secure-media-stream/
│
├── sender/
│   ├── sender.py              # Main sender logic
│   └── frame_generator.py     # Simulates video frames using NumPy
│
├── receiver/
│   ├── receiver.cpp           # Main C++ receiver logic
│   ├── validator.cpp          # Packet validation & AES decryption
│   ├── validator.h            # Header file for validator
│   └── CMakeLists.txt         # C++ build configuration
│
├── shared/
│   ├── config.py              # Shared settings (host, port, keys)
│   ├── encryption.py          # AES-256 GCM encrypt/decrypt
│   └── packet.py              # Custom SMSF packet structure
│
├── logs/
│   └── receiver.log           # Auto-generated transmission logs
│
├── requirements.txt
└── README.md
```

---

## Custom Packet Format (SMSF Protocol)

Every packet follows this exact structure:

```
[ HEADER 23 bytes ] [ METADATA variable ] [ PAYLOAD variable ] [ HMAC 32 bytes ]
```

### Header Fields (Binary, Big-Endian)

| Field | Size | Description |
|---|---|---|
| Magic Number | 4 bytes | `SMSF` — Secure Media Stream Frame identifier |
| Version | 1 byte | Protocol version (currently 1) |
| Frame ID | 4 bytes | Sequential frame number |
| Timestamp | 8 bytes | Unix time when frame was sent |
| Metadata Length | 2 bytes | Size of metadata section in bytes |
| Payload Length | 4 bytes | Size of payload section in bytes |

### Metadata (JSON)
```json
{
    "sender_id"    : "CAM_DEVICE_01",
    "frame_height" : 480,
    "frame_width"  : 640,
    "encoding"     : "numpy_uint8"
}
```

### Payload
- First 12 bytes → AES-256 GCM nonce
- Remaining bytes → Encrypted frame data (ciphertext)

### HMAC
- 32-byte SHA-256 HMAC signature computed over header + metadata + payload
- Provides authenticity and tamper detection

---

## Security Implementation

### Encryption — AES-256 GCM
- Industry standard symmetric encryption
- GCM mode provides both **confidentiality** and **integrity** in one operation
- A fresh random 12-byte nonce is generated for every single frame
- Sender and receiver share a 32-byte key (symmetric encryption)

### Authentication — HMAC-SHA256
- Every packet is signed using a secret HMAC key
- Receiver independently recomputes the HMAC and compares using constant-time comparison (`hmac.compare_digest` / `CRYPTO_memcmp`) to prevent timing attacks
- Any modification to any byte of the packet is detected immediately

### Why Both AES and HMAC?

| | AES-256 GCM | HMAC-SHA256 |
|---|---|---|
| Purpose | Hides data from eavesdroppers | Proves packet authenticity |
| Protects against | Eavesdropping | Tampering & impersonation |
| Question answered | Can anyone read this? | Did it really come from our sender? |

---

## Communication Design

### Why TCP?
- Guarantees reliable, ordered delivery
- Connection-oriented — both sides know when the other disconnects
- Appropriate for a prototype demonstrating packet exchange

### Length Prefixing
TCP is a stream protocol with no built-in message boundaries. We solve this by sending a 4-byte length prefix before every packet so the receiver knows exactly how many bytes to read.

```
[ 4 bytes: packet length ][ N bytes: packet data ]
```

### End of Transmission Signal
After all frames are sent, the sender transmits `\x00\x00\x00\x00` (4 zero bytes) to signal the receiver that transmission is complete.

---

## Cross-Language Design

The sender is implemented in **Python** and the receiver in **C++**, demonstrating that the SMSF packet protocol is **language agnostic**. Both sides communicate using the same custom packet format, encryption scheme, and HMAC keys — proving the protocol works across completely different systems.

This design is inspired by real-world protocols like **RTP (Real-time Transport Protocol)** used by Zoom, YouTube Live, and WebRTC — where the packet format is defined independently of any specific implementation language.

---

## Setup & Installation

### Python Sender

**Requirements:**
- Python 3.10+
- Install dependencies:
```bash
pip install cryptography numpy
```

### C++ Receiver

**Requirements:**
- CMake 3.15+
- OpenSSL
- nlohmann/json (place `json.hpp` in `receiver/nlohmann/json.hpp`)
  - Download from: https://github.com/nlohmann/json/releases

**Build:**
```bash
cd receiver
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build .
```

---

## Running the System

Open two terminals side by side:

**Terminal 1 — Start receiver first:**
```bash
cd secure-media-stream/receiver/build
./receiver.exe
```

**Terminal 2 — Start sender:**
```bash
cd secure-media-stream
python sender/sender.py
```

---

## Expected Output

**Sender Terminal:**
```
2026-03-19 12:45:01 [SENDER] Starting sender — Device ID: CAM_DEVICE_01
2026-03-19 12:45:01 [SENDER] Connected to receiver at 127.0.0.1:9999
2026-03-19 12:45:01 [SENDER] Frame 1 encrypted → 307216 bytes
2026-03-19 12:45:01 [SENDER] Frame 1 packet built → 307354 bytes total
2026-03-19 12:45:01 [SENDER] Frame 1 sent successfully ✓
...
2026-03-19 12:45:06 [SENDER] All frames transmitted — end signal sent
```

**Receiver Terminal:**
```
2026-03-19 12:45:00 [RECEIVER] Waiting for sender to connect...
2026-03-19 12:45:01 [RECEIVER] Sender connected from 127.0.0.1
2026-03-19 12:45:01 [RECEIVER] Packet received — 307354 bytes
2026-03-19 12:45:01 [RECEIVER] Frame 1 received from CAM_DEVICE_01 — HMAC verified ✓
2026-03-19 12:45:01 [RECEIVER] Frame 1 decrypted successfully ✓ — 307200 bytes
2026-03-19 12:45:01 [RECEIVER] Frame 1 — embedded pixel ID: 1 — dimensions: 640x480
2026-03-19 12:45:01 [RECEIVER] Frame 1 transmission delay: 0s
2026-03-19 12:45:01 [RECEIVER] Frame 1 processed successfully ✓
...
2026-03-19 12:45:06 [RECEIVER] Transmission complete — 10 frames received
```

---

## Design Decisions & Justifications

| Decision | Justification |
|---|---|
| TCP over UDP | Reliability guaranteed — no dropped frames in prototype |
| AES-256 GCM | Industry standard — provides encryption + integrity in one operation |
| HMAC-SHA256 | Proves authenticity — encryption alone doesn't prevent impersonation |
| Binary header with `struct` | Precise byte control — demonstrates low level packet design |
| JSON metadata | Human readable — easy to inspect and debug during demonstration |
| Python sender + C++ receiver | Demonstrates cross-language protocol design |
| Length prefixing | Solves TCP stream boundary problem cleanly |
| Fresh nonce per frame | Reusing nonces with same key breaks AES-GCM security |
| `compare_digest` / `CRYPTO_memcmp` | Prevents timing attacks on HMAC comparison |

---

## Author
Built for Adaptive Networking & Secure Media Transmission Internship Challenge