#include "bitcoin.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstring>
#include <mutex>
#include <stdexcept>
#include <thread>

namespace btc {
namespace {

void put_le32(std::uint8_t* p, std::uint32_t v) {
    for (int i = 0; i < 4; ++i) p[i] = static_cast<std::uint8_t>(v >> (8 * i));
}

}  // namespace

Digest from_display_hex(std::string_view hex) {
    const auto bytes = crypto::from_hex(hex);
    if (bytes.size() != 32) throw std::invalid_argument("expected 32-byte hash");
    Digest d;
    std::reverse_copy(bytes.begin(), bytes.end(), d.begin());
    return d;
}

std::string to_display_hex(const Digest& d) {
    Digest r;
    std::reverse_copy(d.begin(), d.end(), r.begin());
    return crypto::to_hex(r);
}

std::array<std::uint8_t, 80> BlockHeader::serialize() const {
    std::array<std::uint8_t, 80> out{};
    put_le32(out.data(), version);
    std::memcpy(out.data() + 4, prev_block.data(), 32);
    std::memcpy(out.data() + 36, merkle_root.data(), 32);
    put_le32(out.data() + 68, time);
    put_le32(out.data() + 72, bits);
    put_le32(out.data() + 76, nonce);
    return out;
}

Digest BlockHeader::hash() const {
    const auto bytes = serialize();
    return crypto::sha256d(bytes.data(), bytes.size());
}

Digest merkle_root(std::vector<Digest> level) {
    if (level.empty()) throw std::invalid_argument("no transactions");
    while (level.size() > 1) {
        if (level.size() % 2 != 0) level.push_back(level.back());
        std::vector<Digest> next;
        next.reserve(level.size() / 2);
        for (std::size_t i = 0; i < level.size(); i += 2) {
            std::uint8_t pair[64];
            std::memcpy(pair, level[i].data(), 32);
            std::memcpy(pair + 32, level[i + 1].data(), 32);
            next.push_back(crypto::sha256d(pair, sizeof pair));
        }
        level = std::move(next);
    }
    return level[0];
}

std::array<std::uint8_t, 32> target_from_bits(std::uint32_t bits) {
    const int exponent = static_cast<int>(bits >> 24);
    std::uint32_t mantissa = bits & 0x007fffff;
    if (bits & 0x00800000) throw std::invalid_argument("negative target");
    if (exponent > 32) throw std::invalid_argument("target overflows 256 bits");

    // target = mantissa * 256^(exponent - 3), written big-endian.
    std::array<std::uint8_t, 32> t{};
    if (exponent <= 3) {
        mantissa >>= 8 * (3 - exponent);
        t[29] = static_cast<std::uint8_t>(mantissa >> 16);
        t[30] = static_cast<std::uint8_t>(mantissa >> 8);
        t[31] = static_cast<std::uint8_t>(mantissa);
    } else {
        const int pos = 32 - exponent;  // index of the mantissa's top byte
        for (int i = 0; i < 3; ++i) {
            const int idx = pos + i;
            if (idx >= 0 && idx < 32) t[idx] = static_cast<std::uint8_t>(mantissa >> (16 - 8 * i));
        }
    }
    return t;
}

bool meets_target(const Digest& hash, std::uint32_t bits) {
    const auto target = target_from_bits(bits);
    // hash bytes are little-endian; compare from the most significant byte.
    for (int i = 0; i < 32; ++i) {
        const std::uint8_t h = hash[31 - i];
        if (h != target[i]) return h < target[i];
    }
    return true;  // equal
}

double difficulty(std::uint32_t bits) {
    const int exponent = static_cast<int>(bits >> 24);
    const double mantissa = static_cast<double>(bits & 0x007fffff);
    return (static_cast<double>(0xffff) / mantissa) * std::pow(256.0, 0x1d - exponent);
}

int leading_zero_bits(const Digest& hash) {
    int n = 0;
    for (int i = 31; i >= 0; --i) {
        const std::uint8_t b = hash[i];
        if (b == 0) {
            n += 8;
            continue;
        }
        for (int bit = 7; bit >= 0 && !(b & (1u << bit)); --bit) ++n;
        break;
    }
    return n;
}

std::optional<MineResult> mine(BlockHeader header, std::uint32_t first, std::uint32_t last,
                               unsigned threads, int zero_bits) {
    threads = std::max(1u, threads);
    const auto bytes = header.serialize();

    // The first 64 bytes (version, prev hash, most of the merkle root) never
    // change while we vary the nonce, so hash them once.
    crypto::Sha256 midstate;
    midstate.update(bytes.data(), 64);

    std::atomic<bool> found{false};
    std::atomic<std::uint64_t> total{0};
    std::mutex m;
    std::optional<MineResult> result;
    const auto start = std::chrono::steady_clock::now();

    auto worker = [&](unsigned t) {
        std::uint8_t tail[16];
        std::memcpy(tail, bytes.data() + 64, 16);
        std::uint64_t local = 0;
        // Thread t tries first+t, first+t+threads, first+t+2*threads, ...
        for (std::uint64_t n = std::uint64_t{first} + t; n <= last; n += threads) {
            if ((local & 0xffff) == 0 && found.load(std::memory_order_relaxed)) break;
            put_le32(tail + 12, static_cast<std::uint32_t>(n));
            crypto::Sha256 ctx = midstate;  // copy of the cached state
            ctx.update(tail, sizeof tail);
            const Digest once = ctx.finalize();
            const Digest h = crypto::sha256(once.data(), once.size());
            ++local;
            const bool ok = zero_bits > 0 ? leading_zero_bits(h) >= zero_bits
                                          : meets_target(h, header.bits);
            if (ok) {
                std::lock_guard<std::mutex> lock(m);
                if (!result || n < result->nonce) {
                    result = MineResult{static_cast<std::uint32_t>(n), h, 0, 0.0};
                }
                found = true;
                break;
            }
        }
        total += local;
    };

    std::vector<std::thread> pool;
    for (unsigned t = 0; t < threads; ++t) pool.emplace_back(worker, t);
    for (auto& th : pool) th.join();

    if (result) {
        result->hashes = total.load();
        result->seconds =
            std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
    }
    return result;
}

}  // namespace btc
