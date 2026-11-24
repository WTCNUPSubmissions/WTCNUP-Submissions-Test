#include "community_index_signer.h"

#include "common.h"
#include "community_ed25519.h"

namespace wtu::publisher {
namespace {
bool Fail(std::string* error, const std::string& message) {
    if (error) *error = message;
    return false;
}
std::string S(const Json& object, const char* key) {
    const Json* value = object.find(key);
    return value && value->is_string() ? value->as_string() : std::string();
}
}  // namespace

bool SignCommunityIndex(const std::string& index_bytes,
                        const std::string& secret_key64,
                        const std::string& key_id,
                        IndexSignature* signature,
                        std::string* error) {
    if (!signature || key_id.empty() || secret_key64.size() != 64) {
        return Fail(error, "invalid index signer input");
    }
    std::string sig;
    if (!crypto::Ed25519Sign(index_bytes, secret_key64, &sig)) {
        return Fail(error, "ed25519 signing failed");
    }
    signature->key_id = key_id;
    signature->algorithm = "ed25519";
    signature->signature_hex = crypto::Ed25519Hex(sig);
    signature->signed_sha256 = Sha256Hex(index_bytes.data(), index_bytes.size());
    return true;
}

bool VerifyCommunityIndexSignature(const std::string& index_bytes,
                                   const IndexSignature& signature,
                                   const std::string& public_key32,
                                   std::string* error) {
    if (signature.algorithm != "ed25519" ||
        Sha256Hex(index_bytes.data(), index_bytes.size()) != signature.signed_sha256) {
        return Fail(error, "index sha256 does not match signature record");
    }
    std::string sig;
    if (!crypto::Ed25519FromHex(signature.signature_hex, &sig) ||
        !crypto::Ed25519Verify(index_bytes, sig, public_key32)) {
        return Fail(error, "ed25519 signature verification failed");
    }
    return true;
}

std::string SerializeIndexSignature(const IndexSignature& signature) {
    Json json = Json::MakeObject();
    json.set("algorithm", Json(signature.algorithm));
    json.set("key_id", Json(signature.key_id));
    json.set("signature", Json(signature.signature_hex));
    json.set("signed_sha256", Json(signature.signed_sha256));
    return json.dump(true);
}

bool ParseIndexSignature(const std::string& text, IndexSignature* signature,
                         std::string* error) {
    if (!signature) return Fail(error, "signature output is null");
    std::string parse_error;
    Json json = Json::parse(text, &parse_error);
    if (!parse_error.empty() || !json.is_object()) return Fail(error, "invalid signature JSON");
    signature->algorithm = S(json, "algorithm");
    signature->key_id = S(json, "key_id");
    signature->signature_hex = S(json, "signature");
    signature->signed_sha256 = S(json, "signed_sha256");
    if (signature->algorithm != "ed25519" || signature->key_id.empty() ||
        signature->signature_hex.size() != 128 || signature->signed_sha256.size() != 64) {
        return Fail(error, "invalid signature fields");
    }
    return true;
}

}  // namespace wtu::publisher
