#include "community_publisher.h"

#include "common.h"
#include "community_ed25519.h"
#include "community_index_signer.h"

#include <iostream>
#include <string>

namespace {

int Fail(const std::string& message) {
    std::cerr << "FAIL " << message << "\n";
    return 1;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc < 2) return Fail("commands: validate-merged | build-package");
    const std::wstring command = argv[1];
    if (command == L"sign-index") {
        std::string index_path;
        std::string output_path;
        std::string key_id = "community-index-2026-01";
        for (int i = 2; i + 1 < argc; i += 2) {
            const std::wstring key = argv[i];
            const std::string value = wtu::WideToUtf8(argv[i + 1]);
            if (key == L"--index") index_path = value;
            else if (key == L"--out") output_path = value;
            else if (key == L"--key-id") key_id = value;
            else return Fail("unknown sign-index argument");
        }
        if (index_path.empty() || output_path.empty()) return Fail("usage: sign-index --index <file> --out <sig>");
        std::string index;
        if (!wtu::ReadFileUtf8(wtu::Utf8ToWide(index_path), index)) return Fail("cannot read index");
        std::string secret_hex = wtu::WideToUtf8(wtu::GetEnv(L"COMMUNITY_INDEX_ED25519_PRIVATE_KEY"));
        std::string secret;
        if (!wtu::crypto::Ed25519FromHex(wtu::Trim(secret_hex), &secret) || secret.size() != 64) {
            return Fail("COMMUNITY_INDEX_ED25519_PRIVATE_KEY must be 64-byte hex");
        }
        wtu::publisher::IndexSignature signature;
        std::string error;
        if (!wtu::publisher::SignCommunityIndex(index, secret, key_id, &signature, &error)) {
            return Fail(error);
        }
        try {
            wtu::WriteFileUtf8Atomic(wtu::Utf8ToWide(output_path),
                                     wtu::publisher::SerializeIndexSignature(signature));
        } catch (const std::exception& error_value) {
            return Fail(std::string("cannot write signature: ") + error_value.what());
        }
        std::cout << "PASS " << signature.key_id << " " << signature.signed_sha256 << "\n";
        return 0;
    }
    if (command != L"validate-merged" && command != L"build-package" &&
        command != L"build-review") {
        return Fail("commands: validate-merged | build-package | build-review | sign-index");
    }
    wtu::publisher::MergedSubmissionInput input;
    std::string output_zip;
    for (int i = 2; i + 1 < argc; i += 2) {
        const std::wstring key = argv[i];
        const std::string value = wtu::WideToUtf8(argv[i + 1]);
        if (key == L"--repo") input.repository_path = value;
        else if (key == L"--base") input.base_sha = value;
        else if (key == L"--head") input.merge_sha = value;
        else if (key == L"--uid") input.submission_uid = value;
        else if (key == L"--author") input.pr_author = value;
        else if (key == L"--pr") {
            try {
                input.pr_number = std::stoi(value);
            } catch (...) {
                return Fail("invalid --pr");
            }
        } else if (key == L"--out") {
            output_zip = value;
        } else {
            return Fail("unknown argument");
        }
    }
    if (input.repository_path.empty() || input.base_sha.empty() || input.merge_sha.empty() ||
        input.submission_uid.empty() || input.pr_author.empty() || input.pr_number <= 0) {
        return Fail("missing required argument");
    }

    wtu::publisher::PublisherConfig config;
    config.repository_path = input.repository_path;
    wtu::publisher::TrustedPublisher publisher(config);
    wtu::v2::SubmissionV2Error error;
    wtu::publisher::PublisherResult result;
    if (command == L"validate-merged") result = publisher.ValidateMerged(input, &error);
    else if (command == L"build-package") result = publisher.BuildPackage(input, output_zip, &error);
    else result = publisher.BuildReviewPackage(input, output_zip, &error);
    if (!result.ok()) {
        std::cerr << "FAIL " << result.code << " " << result.message << "\n";
        return 1;
    }
    std::cout << "PASS " << result.validation.submission_uid << " "
              << result.validation.base_sha << " " << result.validation.merge_sha << " "
              << result.validation.author << " " << result.validation.file_count << " "
              << result.validation.total_size << " " << wtu::publisher::PublicationStateName(result.state);
    if (result.state == wtu::publisher::PublicationState::PackageReady) {
        std::cout << " " << result.package.zip_sha256 << " " << result.package.zip_size;
    }
    std::cout << "\n";
    return 0;
}
