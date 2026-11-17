// SHA-256 (FIPS 180-4) written from scratch: no OpenSSL, no dependencies.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace crypto {

using Digest = std::array<std::uint8_t, 32>;

class Sha256 {
public:
    Sha256();

    // Feed any number of bytes, in as many pieces as you like.
    void update(const std::uint8_t* data, std::size_t len);
    void update(std::string_view s) {
        update(reinterpret_cast<const std::uint8_t*>(s.data()), s.size());
    }

    // Pad, process the final block(s) and return the digest. A copy of a
    // partially-fed Sha256 can be finalized independently; miners use this to
    // reuse the "midstate" of the constant first 64 bytes of a block header.
    Digest finalize();

private:
    void compress(const std::uint8_t* block);

    std::array<std::uint32_t, 8> h_;
    std::array<std::uint8_t, 64> buf_{};
    std::size_t buf_len_ = 0;
    std::uint64_t total_len_ = 0;  // bytes
};

Digest sha256(const std::uint8_t* data, std::size_t len);
Digest sha256(std::string_view s);

// SHA-256 applied twice: Bitcoin's hash for blocks, transactions and Merkle trees.
Digest sha256d(const std::uint8_t* data, std::size_t len);

std::string to_hex(const std::uint8_t* data, std::size_t len);
inline std::string to_hex(const Digest& d) { return to_hex(d.data(), d.size()); }
std::vector<std::uint8_t> from_hex(std::string_view hex);  // throws on bad input

}  // namespace crypto
