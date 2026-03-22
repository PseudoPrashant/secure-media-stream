// validator.cpp - Packet Validation & Integrity Checks
// Parses raw packets, verifies HMAC, and decrypts payload using AES-256 GCM

#include "validator.h"

#include <stdexcept>
#include <cstring>
#include <iostream>
#include <sstream>

// JSON parsing using nlohmann/json (header only library)
#include <nlohmann/json.hpp>

// OpenSSL for HMAC and AES-256 GCM
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/err.h>

using json = nlohmann::json;


// ── Helper: Read Big Endian Values from Raw Bytes ─────────────────
// Network standard is big endian — we need to read values correctly on Windows
// which is little endian by default

static uint32_t read_uint32_be(const uint8_t* ptr) {
    return ((uint32_t)ptr[0] << 24) |
           ((uint32_t)ptr[1] << 16) |
           ((uint32_t)ptr[2] <<  8) |
           ((uint32_t)ptr[3]);
}

static uint16_t read_uint16_be(const uint8_t* ptr) {
    return ((uint16_t)ptr[0] << 8) |
           ((uint16_t)ptr[1]);
}

static double read_double_be(const uint8_t* ptr) {
    // Reverse bytes for big endian double on little endian machine
    uint8_t tmp[8];
    for (int i = 0; i < 8; i++) tmp[i] = ptr[7 - i];
    double val;
    memcpy(&val, tmp, 8);
    return val;
}


// ── compute_hmac ──────────────────────────────────────────────────
std::vector<uint8_t> compute_hmac(
    const std::string& key,
    const std::vector<uint8_t>& data
) {
    std::vector<uint8_t> result(HMAC_SIZE);
    unsigned int len = HMAC_SIZE;

    HMAC(
        EVP_sha256(),
        key.c_str(), (int)key.size(),
        data.data(), data.size(),
        result.data(), &len
    );

    return result;
}


// ── parse_and_validate ────────────────────────────────────────────
ParsedPacket parse_and_validate(
    const std::vector<uint8_t>& raw,
    const std::string& hmac_key
) {
    // ── 1. Check minimum size ─────────────────────────────────────
    if (raw.size() < HEADER_SIZE + HMAC_SIZE) {
        throw std::runtime_error("Packet too small to be valid");
    }

    const uint8_t* ptr = raw.data();

    // ── 2. Validate Magic Number ──────────────────────────────────
    if (memcmp(ptr, MAGIC_NUMBER, 4) != 0) {
        throw std::runtime_error("Invalid magic number — not an SMSF packet");
    }
    ptr += 4;

    // ── 3. Validate Protocol Version ─────────────────────────────
    uint8_t version = *ptr++;
    if (version != PROTOCOL_VERSION) {
        throw std::runtime_error("Unsupported protocol version: " + std::to_string(version));
    }

    // ── 4. Read Header Fields ─────────────────────────────────────
    uint32_t frame_id    = read_uint32_be(ptr); ptr += 4;
    double   timestamp   = read_double_be(ptr); ptr += 8;
    uint16_t meta_len    = read_uint16_be(ptr); ptr += 2;
    uint32_t payload_len = read_uint32_be(ptr); ptr += 4;

    // ── 5. Extract Sections ───────────────────────────────────────
    size_t meta_start    = HEADER_SIZE;
    size_t payload_start = meta_start + meta_len;
    size_t hmac_start    = payload_start + payload_len;

    // Verify packet is complete
    if (raw.size() < hmac_start + HMAC_SIZE) {
        throw std::runtime_error("Packet is incomplete or truncated");
    }

    std::vector<uint8_t> metadata_raw(raw.begin() + meta_start,    raw.begin() + payload_start);
    std::vector<uint8_t> payload     (raw.begin() + payload_start,  raw.begin() + hmac_start);
    std::vector<uint8_t> received_mac(raw.begin() + hmac_start,     raw.begin() + hmac_start + HMAC_SIZE);

    // ── 6. Verify HMAC ────────────────────────────────────────────
    // Recompute HMAC over header + metadata + payload
    std::vector<uint8_t> signed_data(raw.begin(), raw.begin() + hmac_start);
    std::vector<uint8_t> expected_mac = compute_hmac(hmac_key, signed_data);

    // Constant time comparison to prevent timing attacks
    if (CRYPTO_memcmp(received_mac.data(), expected_mac.data(), HMAC_SIZE) != 0) {
        throw std::runtime_error("HMAC verification failed — packet may have been tampered with");
    }

    // ── 7. Parse Metadata JSON ────────────────────────────────────
    std::string meta_str(metadata_raw.begin(), metadata_raw.end());
    json meta = json::parse(meta_str);

    // ── 8. Split Payload into Nonce + Ciphertext ──────────────────
    std::vector<uint8_t> nonce     (payload.begin(), payload.begin() + NONCE_SIZE);
    std::vector<uint8_t> ciphertext(payload.begin() + NONCE_SIZE, payload.end());

    // ── 9. Fill and Return ParsedPacket ───────────────────────────
    ParsedPacket packet;
    packet.frame_id     = frame_id;
    packet.timestamp    = timestamp;
    packet.sender_id    = meta["sender_id"].get<std::string>();
    packet.frame_height = meta["frame_height"].get<uint32_t>();
    packet.frame_width  = meta["frame_width"].get<uint32_t>();
    packet.encoding     = meta["encoding"].get<std::string>();
    packet.nonce        = nonce;
    packet.ciphertext   = ciphertext;

    return packet;
}


// ── decrypt_packet ────────────────────────────────────────────────
bool decrypt_packet(
    ParsedPacket& packet,
    const std::vector<uint8_t>& aes_key
) {
    // AES-256 GCM tag is the last 16 bytes of ciphertext
    const int GCM_TAG_SIZE = 16;

    if (packet.ciphertext.size() <= GCM_TAG_SIZE) {
        std::cerr << "Ciphertext too small for AES-GCM" << std::endl;
        return false;
    }

    // Split ciphertext and GCM authentication tag
    size_t cipher_len = packet.ciphertext.size() - GCM_TAG_SIZE;
    std::vector<uint8_t> cipher(packet.ciphertext.begin(), packet.ciphertext.begin() + cipher_len);
    std::vector<uint8_t> tag   (packet.ciphertext.begin() + cipher_len, packet.ciphertext.end());

    // Prepare output buffer
    packet.plaintext.resize(cipher_len);

    // Initialize OpenSSL AES-256 GCM decryption context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    int len = 0;
    bool success = false;

    do {
        // Initialize decryption with AES-256-GCM
        if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr)) break;

        // Set nonce length (12 bytes)
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_SIZE, nullptr)) break;

        // Set key and nonce
        if (!EVP_DecryptInit_ex(ctx, nullptr, nullptr, aes_key.data(), packet.nonce.data())) break;

        // Decrypt ciphertext
        if (!EVP_DecryptUpdate(ctx, packet.plaintext.data(), &len, cipher.data(), (int)cipher.size())) break;

        // Set expected GCM authentication tag
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_SIZE, tag.data())) break;

        // Finalize — verifies GCM tag automatically
        int final_len = 0;
        if (EVP_DecryptFinal_ex(ctx, packet.plaintext.data() + len, &final_len) <= 0) {
            std::cerr << "AES-GCM tag verification failed — data may be corrupted" << std::endl;
            break;
        }

        packet.plaintext.resize(len + final_len);
        success = true;

    } while (false);

    EVP_CIPHER_CTX_free(ctx);
    return success;
}