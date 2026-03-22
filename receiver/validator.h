// validator.h - Header file for packet validation & integrity checks
// Declares all structures and functions used by validator.cpp and receiver.cpp

#ifndef VALIDATOR_H
#define VALIDATOR_H

#include <string>
#include <vector>
#include <cstdint>

// ── Packet Constants ──────────────────────────────────────────────
#define MAGIC_NUMBER    "SMSF"      // Our custom protocol identifier
#define PROTOCOL_VERSION 1          // Protocol version number
#define HEADER_SIZE     23          // Fixed header size in bytes
#define HMAC_SIZE       32          // SHA256 HMAC size in bytes
#define NONCE_SIZE      12          // AES GCM nonce size in bytes

// ── Parsed Packet Structure ───────────────────────────────────────
// Holds all fields extracted from a raw packet after validation
struct ParsedPacket {
    uint32_t    frame_id;           // Frame sequence number
    double      timestamp;          // Unix timestamp when frame was sent
    std::string sender_id;          // ID of the sending device
    uint32_t    frame_height;       // Height of the frame in pixels
    uint32_t    frame_width;        // Width of the frame in pixels
    std::string encoding;           // Pixel encoding type (numpy_uint8)

    std::vector<uint8_t> nonce;         // 12 byte AES GCM nonce
    std::vector<uint8_t> ciphertext;    // Encrypted frame data
    std::vector<uint8_t> plaintext;     // Decrypted frame data (filled after decryption)
};

// ── Function Declarations ─────────────────────────────────────────

/**
 * Validates and parses a raw packet received from the socket.
 * Checks magic number, version, and HMAC signature.
 *
 * @param raw       : raw bytes received from socket
 * @param hmac_key  : secret key for HMAC verification
 * @return          : ParsedPacket struct with all fields
 * @throws          : std::runtime_error if validation fails
 */
ParsedPacket parse_and_validate(
    const std::vector<uint8_t>& raw,
    const std::string& hmac_key
);

/**
 * Decrypts the ciphertext in a ParsedPacket using AES-256 GCM.
 * Fills the plaintext field of the ParsedPacket.
 *
 * @param packet    : ParsedPacket with nonce and ciphertext filled
 * @param aes_key   : 32 byte AES key for decryption
 * @return          : true if decryption succeeded, false otherwise
 */
bool decrypt_packet(
    ParsedPacket& packet,
    const std::vector<uint8_t>& aes_key
);

/**
 * Computes HMAC-SHA256 over the given data using the given key.
 *
 * @param key   : HMAC secret key
 * @param data  : data to sign
 * @return      : 32 byte HMAC signature
 */
std::vector<uint8_t> compute_hmac(
    const std::string& key,
    const std::vector<uint8_t>& data
);

#endif // VALIDATOR_H