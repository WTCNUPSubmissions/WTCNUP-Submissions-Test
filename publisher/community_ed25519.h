#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace wtu::crypto {

struct Ed25519KeyPair {
    std::string public_key;   // 32 raw bytes
    std::string secret_key;   // 64 raw bytes (32-byte seed + 32-byte public key)
};

bool Ed25519GenerateKeyPair(Ed25519KeyPair* keys);
bool Ed25519KeyPairFromSeed(const std::string& seed32, Ed25519KeyPair* keys);
bool Ed25519Sign(const std::string& message, const std::string& secret_key64,
                 std::string* signature64);
bool Ed25519Verify(const std::string& message, const std::string& signature64,
                   const std::string& public_key32);

bool Ed25519SignFile(const std::string& path, const std::string& secret_key64,
                     std::string* signature64);
bool Ed25519VerifyFile(const std::string& path, const std::string& signature64,
                       const std::string& public_key32);

std::string Ed25519Hex(const std::string& raw);
bool Ed25519FromHex(const std::string& hex, std::string* raw);

}  // namespace wtu::crypto
