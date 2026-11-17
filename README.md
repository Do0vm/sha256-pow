# sha256-pow

[![CI](https://github.com/Do0vm/sha256-pow/actions/workflows/ci.yml/badge.svg)](https://github.com/Do0vm/sha256-pow/actions/workflows/ci.yml)

**SHA-256 written from scratch in C++20, used to verify real Bitcoin blocks and to mine them.** No OpenSSL, no dependencies.

- SHA-256 per FIPS 180-4, checked against the NIST test vectors (including the one-million-`a` message) and against streaming input split at every awkward padding boundary
- Bitcoin block headers serialised byte-for-byte, then hashed: the genesis block and block 100,000 reproduce their real hashes
- Merkle roots, including Bitcoin's "duplicate the last hash when the count is odd" rule
- Compact `bits` → 256-bit target conversion, target checks and difficulty
- A **multithreaded proof-of-work miner** with **midstate caching** that re-mines the genesis block and finds Satoshi's nonce

## Demo output (GitHub Actions, 4 vCPUs)

```
Genesis block
  hash        000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
  target met  yes (difficulty 1, 43 leading zero bits)

Re-mining the genesis block from nonce 2063236893 on 4 threads...
  found nonce 2083236893  hash 000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
  20.5 million hashes in 2.73 s = 7.52 MH/s

   1 thread(s): 26 zero bits at nonce  148459632 after  148.5 M hashes, 2.54 MH/s
   4 thread(s): 26 zero bits at nonce  148459632 after  149.1 M hashes, 7.55 MH/s

For scale: the Bitcoin network does roughly 10^21 hashes per second.
```

Four threads give about a **3x** speed-up on the 4-vCPU runner. That last line is the real lesson: a CPU miner is roughly 10^14 times too slow to matter, which is why mining moved to ASICs.

## How a Bitcoin block hash works

```
header (80 bytes) = version | prev_block | merkle_root | time | bits | nonce
                    4 B LE    32 B         32 B          4 B LE  4 B LE  4 B LE
block hash        = SHA256(SHA256(header))
valid block       = hash, read as a 256-bit little-endian number, <= target(bits)
```

Explorers show hashes **byte-reversed**, so the leading zeros you see are the hash's most significant bytes. `from_display_hex` / `to_display_hex` handle the conversion, and getting this wrong is the most common bug in Bitcoin tooling.

**Target from `bits`:** `0x1d00ffff` → mantissa `0x00ffff` × 256^(0x1d − 3) = `0x00000000ffff0000…`. Difficulty is the easiest target divided by the current target, so block 100,000 (`0x1b04864c`) has difficulty 14,484.16, matching what explorers show.

## Miner optimisation: midstate

SHA-256 processes 64-byte blocks. An 80-byte header is two blocks, and only the second one contains the nonce. The miner hashes the first 64 bytes **once**, then for each nonce copies that saved state and processes only the remaining 16 bytes. Each attempt costs 2 compressions instead of 3 (about a third less work). Real ASIC miners rely on the same trick.

Threads split the nonce range by striding (thread *t* tries `first + t`, `first + t + T`, …) and stop when any thread finds a solution.

## Tests

`tests/test_sha256.cpp`:
- NIST vectors: `""`, `"abc"`, the 448-bit message, one million `a`s
- streaming in chunks of 1, 3, 7, 64 and 100 bytes, for lengths 0–300 around the 55/56/64-byte padding edges
- genesis block and block 100,000 hashes; Merkle roots for 1, 3 and 4 transactions (all cross-checked against Python's `hashlib` and the Blockstream API)
- target decoding, `meets_target` true for the real nonce and false for nonce + 1, difficulty
- the miner must find nonce 2,083,236,893 when started 2 million nonces early

CI builds on **GCC, Clang and MSVC** and reruns the tests under **AddressSanitizer + UndefinedBehaviorSanitizer**.

## Build

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
./build/pow_mine
```

*Educational code: use a vetted library (OpenSSL, libsecp256k1, Bitcoin Core) for anything real.*
