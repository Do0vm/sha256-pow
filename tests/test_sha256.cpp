#include <cstdio>
#include <stdexcept>
#include <string>

#include "bitcoin.hpp"
#include "sha256.hpp"

static int g_failures = 0;
static int g_checks = 0;

#define CHECK(cond)                                                              \
    do {                                                                         \
        ++g_checks;                                                              \
        if (!(cond)) {                                                           \
            std::fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, \
                         #cond);                                                 \
            ++g_failures;                                                        \
        }                                                                        \
    } while (0)

using crypto::sha256;
using crypto::to_hex;

// NIST FIPS 180-4 / CAVP test vectors.
static void nist_vectors() {
    CHECK(to_hex(sha256("")) ==
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    CHECK(to_hex(sha256("abc")) ==
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    CHECK(to_hex(sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")) ==
          "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    CHECK(to_hex(sha256(std::string(1000000, 'a'))) ==
          "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}

// Feeding data in awkward chunk sizes must give the same answer as one shot,
// including lengths that land exactly on and around the 55/56/64-byte padding edges.
static void streaming_matches_one_shot() {
    std::string msg;
    for (int i = 0; i < 300; ++i) msg.push_back(static_cast<char>('A' + i % 57));
    for (std::size_t len : {0u, 1u, 55u, 56u, 57u, 63u, 64u, 65u, 119u, 120u, 128u, 300u}) {
        const std::string m = msg.substr(0, len);
        for (std::size_t chunk : {1u, 3u, 7u, 64u, 100u}) {
            crypto::Sha256 ctx;
            for (std::size_t i = 0; i < m.size(); i += chunk) ctx.update(m.substr(i, chunk));
            CHECK(ctx.finalize() == sha256(m));
        }
    }
}

static void hex_round_trip() {
    const auto bytes = crypto::from_hex("00ff10Ab");
    CHECK(bytes.size() == 4 && bytes[1] == 0xff && bytes[3] == 0xab);
    CHECK(to_hex(bytes.data(), bytes.size()) == "00ff10ab");
    bool threw = false;
    try {
        crypto::from_hex("abc");
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    CHECK(threw);
}

static btc::BlockHeader genesis() {
    btc::BlockHeader h;
    h.version = 1;
    h.prev_block = {};
    h.merkle_root =
        btc::from_display_hex("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b");
    h.time = 1231006505;  // 2009-01-03 18:15:05 UTC
    h.bits = 0x1d00ffff;
    h.nonce = 2083236893;
    return h;
}

static btc::BlockHeader block_100000() {
    btc::BlockHeader h;
    h.version = 1;
    h.prev_block =
        btc::from_display_hex("000000000002d01c1fccc21636b607dfd930d31d01c3a62104612a1719011250");
    h.merkle_root =
        btc::from_display_hex("f3e94742aca4b5ef85488dc37c06c3282295ffec960994b2c0d5ac2a25a95766");
    h.time = 1293623863;
    h.bits = 0x1b04864c;
    h.nonce = 274148111;
    return h;
}

static void real_block_hashes() {
    CHECK(btc::to_display_hex(genesis().hash()) ==
          "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f");
    CHECK(btc::to_display_hex(block_100000().hash()) ==
          "000000000003ba27aa200b1cecaad478d2b00432346c3f1f3986da1afd33e506");
    CHECK(btc::leading_zero_bits(genesis().hash()) == 43);
}

static void merkle_roots() {
    // Block 100,000 has 4 transactions.
    std::vector<btc::Digest> txids = {
        btc::from_display_hex("8c14f0db3df150123e6f3dbbf30f8b955a8249b62ac1d1ff16284aefa3d06d87"),
        btc::from_display_hex("fff2525b8931402dd09222c50775608f75787bd2b87e56995a7bdd30f79702c4"),
        btc::from_display_hex("6359f0868171b1d194cbee1af2f16ea598ae8fad666d9b012c8ed2b79a236ec4"),
        btc::from_display_hex("e9a66845e05d5abc0ad04ec80f774a7e585c6e8db975962d069a522137b80c1d"),
    };
    CHECK(btc::to_display_hex(btc::merkle_root(txids)) ==
          "f3e94742aca4b5ef85488dc37c06c3282295ffec960994b2c0d5ac2a25a95766");

    // Odd count: last txid is paired with itself (value cross-checked in Python).
    txids.pop_back();
    CHECK(btc::to_display_hex(btc::merkle_root(txids)) ==
          "fa435470825de273081dcc706b25514c936fa6dc80ab965ce6970d68ddd0b553");

    // A single transaction is its own Merkle root (the genesis block).
    const auto coinbase =
        btc::from_display_hex("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b");
    CHECK(btc::merkle_root({coinbase}) == coinbase);
}

static void targets_and_difficulty() {
    const auto t = btc::target_from_bits(0x1d00ffff);
    // 0x00000000ffff0000...0000
    CHECK(t[0] == 0 && t[3] == 0 && t[4] == 0xff && t[5] == 0xff && t[6] == 0 && t[31] == 0);

    CHECK(btc::meets_target(genesis().hash(), genesis().bits));
    CHECK(btc::meets_target(block_100000().hash(), block_100000().bits));

    auto wrong = genesis();
    wrong.nonce += 1;  // any other nonce is (overwhelmingly likely) invalid
    CHECK(!btc::meets_target(wrong.hash(), wrong.bits));

    CHECK(btc::difficulty(0x1d00ffff) == 1.0);
    const double d = btc::difficulty(0x1b04864c);
    CHECK(d > 14484.16 && d < 14484.17);
}

static void miner_finds_genesis_nonce() {
    // Start 2 million nonces early; the miner must land on the real one.
    const auto h = genesis();
    const auto r = btc::mine(h, h.nonce - 2'000'000, h.nonce + 1000, 4);
    CHECK(r.has_value());
    if (r) {
        CHECK(r->nonce == 2083236893u);
        CHECK(btc::to_display_hex(r->hash) ==
              "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f");
    }
}

int main() {
    nist_vectors();
    streaming_matches_one_shot();
    hex_round_trip();
    real_block_hashes();
    merkle_roots();
    targets_and_difficulty();
    miner_finds_genesis_nonce();
    std::printf("%d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
