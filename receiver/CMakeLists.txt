cmake_minimum_required(VERSION 3.15)
project(SecureMediaReceiver)

set(CMAKE_CXX_STANDARD 17)

# ── Find OpenSSL ──────────────────────────────────────────────────
find_package(OpenSSL REQUIRED)

# ── nlohmann/json (header only) ───────────────────────────────────
# Download from https://github.com/nlohmann/json/releases
# Place json.hpp in receiver/nlohmann/json.hpp
include_directories(${CMAKE_SOURCE_DIR})

# ── Build Receiver Executable ─────────────────────────────────────
add_executable(receiver
    receiver.cpp
    validator.cpp
)

# ── Link Libraries ────────────────────────────────────────────────
target_link_libraries(receiver
    OpenSSL::SSL
    OpenSSL::Crypto
    ws2_32          # Windows socket library
)

# ── Include OpenSSL Headers ───────────────────────────────────────
target_include_directories(receiver PRIVATE ${OPENSSL_INCLUDE_DIR})
