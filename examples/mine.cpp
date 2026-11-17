// Demo: verify real Bitcoin blocks, re-mine the genesis block, and measure hashrate.
#include <algorithm>
#include <cstdio>
#include <thread>

#include "bitcoin.hpp"

int main() {
    btc::BlockHeader g;
    g.merkle_root =
        btc::from_display_hex("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b");
    g.time = 1231006505;
    g.bits = 0x1d00ffff;
    g.nonce = 2083236893;
    const unsigned threads = std::max(1u, std::thread::hardware_concurrency());

    std::printf("Genesis block\n");
    std::printf("  hash        %s\n", btc::to_display_hex(g.hash()).c_str());
    std::printf("  target met  %s (difficulty %.0f, %d leading zero bits)\n\n",
                btc::meets_target(g.hash(), g.bits) ? "yes" : "no", btc::difficulty(g.bits),
                btc::leading_zero_bits(g.hash()));

    // 1) Re-mine the genesis block from 20 million nonces before the real one.
    const std::uint32_t start = g.nonce - 20'000'000;
    std::printf("Re-mining the genesis block from nonce %u on %u threads...\n", start, threads);
    if (auto r = btc::mine(g, start, 0xffffffffu, threads)) {
        std::printf("  found nonce %u  hash %s\n", r->nonce, btc::to_display_hex(r->hash).c_str());
        std::printf("  %.1f million hashes in %.2f s = %.2f MH/s\n\n", r->hashes / 1e6, r->seconds,
                    r->hashes / r->seconds / 1e6);
    }

    // 2) Hashrate scaling: find a 26-bit "toy difficulty" hash, 1 thread vs all.
    g.time += 1;  // a fresh header, so the answer is not already known
    for (unsigned t : {1u, threads}) {
        if (auto r = btc::mine(g, 0, 0xffffffffu, t, 26)) {
            std::printf("  %2u thread(s): 26 zero bits at nonce %10u after %6.1f M hashes, %.2f MH/s\n",
                        t, r->nonce, r->hashes / 1e6, r->hashes / r->seconds / 1e6);
        }
        if (t == threads) break;
    }
    std::printf("\nFor scale: the Bitcoin network does roughly 10^21 hashes per second.\n");
    return 0;
}
