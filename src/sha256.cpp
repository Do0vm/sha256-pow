#include "sha256.hpp"

#include <algorithm>
#include <cstring>
#include <stdexcept>

namespace crypto {
namespace {

// First 32 bits of the fractional parts of the cube roots of the first 64 primes.
constexpr std::uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

// First 32 bits of the fractional parts of the square roots of the first 8 primes.
constexpr std::array<std::uint32_t, 8> H0 = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};

constexpr std::uint32_t rotr(std::uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

std::uint32_t load_be32(const std::uint8_t* p) {
    return (std::uint32_t{p[0]} << 24) | (std::uint32_t{p[1]} << 16) |
           (std::uint32_t{p[2]} << 8) | std::uint32_t{p[3]};
}

void store_be32(std::uint8_t* p, std::uint32_t v) {
    p[0] = static_cast<std::uint8_t>(v >> 24);
    p[1] = static_cast<std::uint8_t>(v >> 16);
    p[2] = static_cast<std::uint8_t>(v >> 8);
    p[3] = static_cast<std::uint8_t>(v);
}

}  // namespace

Sha256::Sha256() : h_(H0) {}

void Sha256::compress(const std::uint8_t* block) {
    // Message schedule: 16 words from the block, 48 more derived from them.
    std::uint32_t w[64];
    for (int i = 0; i < 16; ++i) w[i] = load_be32(block + 4 * i);
    for (int i = 16; i < 64; ++i) {
        const std::uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        const std::uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    std::uint32_t a = h_[0], b = h_[1], c = h_[2], d = h_[3];
    std::uint32_t e = h_[4], f = h_[5], g = h_[6], h = h_[7];
    for (int i = 0; i < 64; ++i) {
        const std::uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const std::uint32_t ch = (e & f) ^ (~e & g);
        const std::uint32_t t1 = h + S1 + ch + K[i] + w[i];
        const std::uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        const std::uint32_t t2 = S0 + maj;
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    h_[0] += a; h_[1] += b; h_[2] += c; h_[3] += d;
    h_[4] += e; h_[5] += f; h_[6] += g; h_[7] += h;
}

void Sha256::update(const std::uint8_t* data, std::size_t len) {
    total_len_ += len;
    if (buf_len_ > 0) {  // top up a partially filled block first
        const std::size_t take = std::min(len, buf_.size() - buf_len_);
        std::memcpy(buf_.data() + buf_len_, data, take);
        buf_len_ += take;
        data += take;
        len -= take;
        if (buf_len_ < buf_.size()) return;
        compress(buf_.data());
        buf_len_ = 0;
    }
    while (len >= 64) {  // whole blocks straight from the input
        compress(data);
        data += 64;
        len -= 64;
    }
    if (len > 0) {
        std::memcpy(buf_.data(), data, len);
        buf_len_ = len;
    }
}

Digest Sha256::finalize() {
    const std::uint64_t bit_len = total_len_ * 8;
    // Padding: a single 1 bit, zeros, then the message length as 64-bit big-endian,
    // so the total is a multiple of 64 bytes.
    std::uint8_t pad[72] = {0x80};
    const std::size_t pad_len = (buf_len_ < 56) ? (56 - buf_len_) : (120 - buf_len_);
    for (int i = 0; i < 8; ++i) pad[pad_len + i] = static_cast<std::uint8_t>(bit_len >> (56 - 8 * i));
    update(pad, pad_len + 8);

    Digest out;
    for (int i = 0; i < 8; ++i) store_be32(out.data() + 4 * i, h_[i]);
    return out;
}

Digest sha256(const std::uint8_t* data, std::size_t len) {
    Sha256 ctx;
    ctx.update(data, len);
    return ctx.finalize();
}

Digest sha256(std::string_view s) {
    return sha256(reinterpret_cast<const std::uint8_t*>(s.data()), s.size());
}

Digest sha256d(const std::uint8_t* data, std::size_t len) {
    const Digest first = sha256(data, len);
    return sha256(first.data(), first.size());
}

std::string to_hex(const std::uint8_t* data, std::size_t len) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string s(len * 2, '0');
    for (std::size_t i = 0; i < len; ++i) {
        s[2 * i] = digits[data[i] >> 4];
        s[2 * i + 1] = digits[data[i] & 0x0f];
    }
    return s;
}

std::vector<std::uint8_t> from_hex(std::string_view hex) {
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        throw std::invalid_argument("invalid hex digit");
    };
    if (hex.size() % 2 != 0) throw std::invalid_argument("hex string has odd length");
    std::vector<std::uint8_t> out(hex.size() / 2);
    for (std::size_t i = 0; i < out.size(); ++i)
        out[i] = static_cast<std::uint8_t>(nibble(hex[2 * i]) << 4 | nibble(hex[2 * i + 1]));
    return out;
}

}  // namespace crypto
