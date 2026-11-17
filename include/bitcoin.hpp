// Bitcoin block headers, Merkle roots and proof-of-work targets.
//
// Byte order: Bitcoin hashes are computed over little-endian bytes but shown
// to humans reversed (big-endian). Functions named *_display_* work with the
// reversed form you see on block explorers.
#pragma once

#include <array>
#include <atomic>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "sha256.hpp"

namespace btc {

using crypto::Digest;

Digest from_display_hex(std::string_view hex);  // explorer form -> internal bytes
std::string to_display_hex(const Digest& d);      // internal bytes -> explorer form

struct BlockHeader {
    std::uint32_t version = 1;
    Digest prev_block{};   // internal byte order
    Digest merkle_root{};  // internal byte order
    std::uint32_t time = 0;
    std::uint32_t bits = 0;  // compact difficulty target
    std::uint32_t nonce = 0;

    std::array<std::uint8_t, 80> serialize() const;  // exact 80-byte wire format
    Digest hash() const;                              // sha256d of the 80 bytes
};

// Merkle root of transaction ids (internal byte order). An odd node at any
// level is paired with itself, exactly as Bitcoin Core does.
Digest merkle_root(std::vector<Digest> txids);

// 256-bit target, big-endian, from the compact "bits" field. Throws if invalid.
std::array<std::uint8_t, 32> target_from_bits(std::uint32_t bits);

// True if the block hash, read as a 256-bit number, is <= the target.
bool meets_target(const Digest& hash, std::uint32_t bits);

// Difficulty relative to the easiest target (bits 0x1d00ffff), as explorers show it.
double difficulty(std::uint32_t bits);

// Leading zero bits of the hash in display order (a quick "how lucky" measure).
int leading_zero_bits(const Digest& hash);

struct MineResult {
    std::uint32_t nonce;
    Digest hash;
    std::uint64_t hashes;  // total tried by all threads
    double seconds;
};

// Search nonces in [first, last] on `threads` threads until a hash meets
// `bits` (or, if zero_bits > 0, has at least that many leading zero bits).
// Uses the SHA-256 midstate of the first 64 header bytes, so each attempt
// costs 2 compressions instead of 3.
std::optional<MineResult> mine(BlockHeader header, std::uint32_t first, std::uint32_t last,
                               unsigned threads, int zero_bits = 0);

}  // namespace btc
