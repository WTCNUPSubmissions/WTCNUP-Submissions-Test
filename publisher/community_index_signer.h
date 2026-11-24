#pragma once

#include <string>

namespace wtu::publisher {

struct IndexSignature {
    std::string key_id;
    std::string algorithm = "ed25519";
    std::string signature_hex;
    std::string signed_sha256;
};

bool SignCommunityIndex(const std::string& index_bytes,
                        const std::string& secret_key64,
                        const std::string& key_id,
                        IndexSignature* signature,
                        std::string* error = nullptr);
bool VerifyCommunityIndexSignature(const std::string& index_bytes,
                                   const IndexSignature& signature,
                                   const std::string& public_key32,
                                   std::string* error = nullptr);
std::string SerializeIndexSignature(const IndexSignature& signature);
bool ParseIndexSignature(const std::string& text, IndexSignature* signature,
                         std::string* error = nullptr);

}  // namespace wtu::publisher
