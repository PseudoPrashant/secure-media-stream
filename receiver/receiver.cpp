// receiver.cpp - Main C++ Receiver Logic
// Accepts TCP connections, receives packets, validates and decrypts frames

#include "validator.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <iomanip>

// Windows socket headers
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

// ── Configuration ─────────────────────────────────────────────────
// Must match shared/config.py exactly
const std::string HOST        = "127.0.0.1";
const int         PORT        = 9999;
const std::string HMAC_KEY    = "super-secret-hmac-key-for-demo";
const std::string LOG_FILE    = "logs/receiver.log";

// AES key must be exactly 32 bytes — matches config.py
const std::vector<uint8_t> AES_KEY = {
    '0','1','2','3','4','5','6','7','8','9',
    '0','1','2','3','4','5','6','7','8','9',
    '0','1','2','3','4','5','6','7','8','9',
    '0','1'
};


// ── Logging ───────────────────────────────────────────────────────
std::ofstream log_file;

void log(const std::string& message) {
    // Get current timestamp
    time_t now = time(nullptr);
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", localtime(&now));

    std::string line = std::string(buf) + " [RECEIVER] " + message;

    // Print to terminal
    std::cout << line << std::endl;

    // Write to log file
    if (log_file.is_open()) {
        log_file << line << std::endl;
        log_file.flush();
    }
}


// ── Receive Exact Bytes ───────────────────────────────────────────
// Keeps reading from socket until exactly n bytes are received
bool recv_exact(SOCKET sock, std::vector<uint8_t>& buf, size_t n) {
    buf.resize(n);
    size_t received = 0;
    while (received < n) {
        int result = recv(sock, (char*)buf.data() + received, (int)(n - received), 0);
        if (result <= 0) return false;
        received += result;
    }
    return true;
}


// ── Receive Length Prefixed Packet ────────────────────────────────
// Reads 4 byte length prefix first then reads that many bytes
bool recv_packet(SOCKET sock, std::vector<uint8_t>& packet) {
    // Read 4 byte length prefix
    std::vector<uint8_t> len_buf;
    if (!recv_exact(sock, len_buf, 4)) return false;

    // Parse length as big endian uint32
    uint32_t length = ((uint32_t)len_buf[0] << 24) |
                      ((uint32_t)len_buf[1] << 16) |
                      ((uint32_t)len_buf[2] <<  8) |
                      ((uint32_t)len_buf[3]);

    // Zero length means end of transmission signal
    if (length == 0) return false;

    // Read exactly that many bytes
    return recv_exact(sock, packet, length);
}


// ── Process Packet ────────────────────────────────────────────────
void process_packet(const std::vector<uint8_t>& raw) {
    try {
        // Step 1 — Parse and validate the packet
        ParsedPacket packet = parse_and_validate(raw, HMAC_KEY);
        log("Frame " + std::to_string(packet.frame_id) +
            " received from " + packet.sender_id +
            " — HMAC verified ✓");

        // Step 2 — Decrypt the payload
        if (!decrypt_packet(packet, AES_KEY)) {
            log("ERROR: Decryption failed for frame " + std::to_string(packet.frame_id));
            return;
        }
        log("Frame " + std::to_string(packet.frame_id) +
            " decrypted successfully ✓ — " +
            std::to_string(packet.plaintext.size()) + " bytes");

        // Step 3 — Verify frame dimensions
        size_t expected_size = packet.frame_height * packet.frame_width;
        if (packet.plaintext.size() != expected_size) {
            log("WARNING: Frame size mismatch — expected " +
                std::to_string(expected_size) + " got " +
                std::to_string(packet.plaintext.size()));
            return;
        }

        // Step 4 — Read embedded frame_id from first pixel
        uint8_t embedded_id = packet.plaintext[0];
        log("Frame " + std::to_string(packet.frame_id) +
            " — embedded pixel ID: " + std::to_string(embedded_id) +
            " — dimensions: " +
            std::to_string(packet.frame_width) + "x" +
            std::to_string(packet.frame_height));

        // Step 5 — Calculate transmission delay
        time_t now = time(nullptr);
        double delay = difftime(now, (time_t)packet.timestamp);
        log("Frame " + std::to_string(packet.frame_id) +
            " transmission delay: " + std::to_string(delay) + "s");

        log("Frame " + std::to_string(packet.frame_id) + " processed successfully ✓");
        log("─────────────────────────────────────────");

    } catch (const std::exception& e) {
        log("ERROR processing packet: " + std::string(e.what()));
    }
}


// ── Main ──────────────────────────────────────────────────────────
int main() {
    // Open log file
    log_file.open(LOG_FILE, std::ios::app);
    if (!log_file.is_open()) {
        std::cerr << "Warning: Could not open log file" << std::endl;
    }

    log("============================================");
    log("Secure Media Stream Receiver starting...");
    log("Listening on " + HOST + ":" + std::to_string(PORT));
    log("============================================");

    // ── Initialize Winsock ────────────────────────────────────────
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        log("ERROR: WSAStartup failed");
        return 1;
    }

    // ── Create Server Socket ──────────────────────────────────────
    SOCKET server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock == INVALID_SOCKET) {
        log("ERROR: Could not create socket");
        WSACleanup();
        return 1;
    }

    // Allow port reuse
    int opt = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));

    // ── Bind to Port ──────────────────────────────────────────────
    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_sock, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        log("ERROR: Bind failed on port " + std::to_string(PORT));
        closesocket(server_sock);
        WSACleanup();
        return 1;
    }

    // ── Listen for Connections ────────────────────────────────────
    listen(server_sock, 1);
    log("Waiting for sender to connect...");

    // ── Accept Connection ─────────────────────────────────────────
    sockaddr_in client_addr{};
    int client_len = sizeof(client_addr);
    SOCKET client_sock = accept(server_sock, (sockaddr*)&client_addr, &client_len);

    if (client_sock == INVALID_SOCKET) {
        log("ERROR: Accept failed");
        closesocket(server_sock);
        WSACleanup();
        return 1;
    }

    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
    log("Sender connected from " + std::string(client_ip));

    // ── Receive and Process Packets ───────────────────────────────
    int frame_count = 0;
    std::vector<uint8_t> raw_packet;

    while (recv_packet(client_sock, raw_packet)) {
        frame_count++;
        log("Packet received — " + std::to_string(raw_packet.size()) + " bytes");
        process_packet(raw_packet);
    }

    // ── Transmission Complete ─────────────────────────────────────
    log("============================================");
    log("Transmission complete — " + std::to_string(frame_count) + " frames received");
    log("============================================");

    // ── Cleanup ───────────────────────────────────────────────────
    closesocket(client_sock);
    closesocket(server_sock);
    WSACleanup();
    log_file.close();

    return 0;
}