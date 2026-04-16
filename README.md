# zig-crypto

> Pure Zig cryptographic library for public blockchain — Chinese National Cryptographic Algorithms (SM2/SM3/SM4) & mainstream primitives

**[中文](./README_ZH.md)** | English

Pure Zig implementation with no C dependencies.

[![Zig 0.16.0](https://img.shields.io/badge/Zig-0.16.0-blue.svg)](https://ziglang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## Features

### Chinese National Cryptographic Standards (国密)

| Algorithm | Standard | Usage |
|-----------|----------|-------|
| **SM2** | GM/T 0003-2012 | Elliptic curve signature/verification/KEX |
| **SM3** | GM/T 0004-2012 | Hash algorithm (256-bit) |
| **SM4** | GM/T 0002-2012 | Block cipher (128-bit, CBC/ECB) |

### Mainstream Algorithms

| Algorithm | Standard | Usage |
|-----------|----------|-------|
| **secp256k1** | SECG | EVM-compatible curve (Bitcoin/Ethereum) |
| **Ed25519** | RFC 8032 | Modern signature algorithm |
| **SHA-256** | FIPS 180-4 | Widely-used hash |
| **HMAC** | RFC 2104 | Message authentication code |
| **Base58Check** | Bitcoin | Address encoding |
| **Bech32/Bech32m** | BIP 173/350 | SegWit address encoding |

### Architecture Layers

```
Layer 4 ┌─────────────────────────┐
        │  Encoding (Base58/Bech32) │
        └─────────────┬───────────┘
Layer 3 ┌─────────────┴───────────┐
        │  Protocols (HKDF/Merkle)  │
        └─────────────┬───────────┘
Layer 2 ┌─────────────┴───────────┐
        │  ECC (SM2/secp256k1/Ed25519) │
        └─────────────┬───────────┘
Layer 1 ┌─────────────┴───────────┐
        │  Hash/Sym (SM3/SHA256/SM4) │
        └─────────────┬───────────┘
Layer 0 ┌─────────────┴───────────┐
        │  Math (BigInt/Montgomery)  │
        └─────────────────────────┘
```

---

## Installation

### Add as Zig Module Dependency

In `build.zig.zon`:

```zig
.{
    .dependencies = .{
        .zig_crypto = .{
            .url = "https://github.com/knot3bot/zig-crypto",
            .hash = "<get latest hash from GitHub>",
        },
    },
}
```

### Clone Directly

```bash
git clone https://github.com/knot3bot/zig-crypto.git
cd zig-crypto
zig build test
```

---

## Quick Start

```zig
const zig_crypto = @import("zig_crypto");

pub fn main() void {
    // SM3 hash
    const msg = "Hello, Blockchain!";
    const digest = zig_crypto.sm3.hash(msg);
    std.debug.print("SM3: {s}\n", .{std.fmt.fmtSliceHexLower(&digest)});

    // SHA-256 hash
    const sha_digest = zig_crypto.sha256.hash(msg);
    std.debug.print("SHA256: {s}\n", .{std.fmt.fmtSliceHexLower(&sha_digest)});

    // SM4 encryption
    const key = [_]u8{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                       0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10};
    const plaintext = [_]u8{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                           0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10};
    const ciphertext = zig_crypto.sm4.encryptBlock(key, plaintext);
}
```

---

## API Reference

### Layer 0: Math Primitives

#### BigInt256 — 256-bit Unsigned Integer

```zig
const BigInt256 = zig_crypto.math_bigint.BigInt256;

// Create from bytes
const n = BigInt256.fromBytes(&bytes);  // 32 bytes, big-endian
const n = try BigInt256.fromHex("0xFFFF...");  // From hex string

// Basic operations
const sum = BigInt256.add(a, b);        // Returns {result, carry}
const diff = BigInt256.sub(a, b);       // Returns {result, borrow}
const prod = BigInt256.mul(a, b);       // Returns 256-bit result
const wide = BigInt256.mulWide(a, b);   // Returns {low, high} 512-bit

// Modular arithmetic
const mod_sum = BigInt256.addMod(a, b, m);
const mod_sub = BigInt256.subMod(a, b, m);
const mod_mul = BigInt256.mulMod(a, b, m);

// Comparison
const cmp_result = BigInt256.cmp(a, b);  // -1, 0, 1
const eq = a.eql(b);
const lt = BigInt256.ctLt(a, b);        // Constant-time comparison

// Bit operations
const bit = n.getBit(0);               // Get bit at position i
const bit_count = n.bitCount();         // Number of bits
```

#### MontgomeryContext — Montgomery Multiplication Context

```zig
const MontgomeryContext = zig_crypto.math_modint.MontgomeryContext;
const ctx = try MontgomeryContext.init(prime_modulus);

// Convert to Montgomery form
const a_mont = ctx.toMontgomery(a);
const a_reg = ctx.fromMontgomery(a_mont);

// Montgomery multiplication
const c = ctx.montMul(a_mont, b_mont);

// Modular exponentiation
const result = ctx.montExp(base, exponent);

// Modular inverse
const inv = ctx.modInverse(a);
```

---

### Layer 1: Hash & Symmetric Encryption

#### SM3 Hash Algorithm

```zig
const Sm3 = zig_crypto.sm3.Sm3;

// Single hash
const digest = Sm3.hash("message");

// Streaming hash
var ctx = Sm3.init();
ctx.update("part1");
ctx.update("part2");
const result = ctx.finalize();
```

**Test Vectors:**
```zig
SM3("")        = 1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b
SM3("abc")     = 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0
SM3("abcd...") = b80fe97a4da24afc277564f66a359ef440462ad28dcc6d63adb24d5c20a61595
```

#### SHA-256

```zig
const Sha256 = zig_crypto.sha256.Sha256;

// Single hash
const digest = Sha256.hash("message");

// Streaming hash
var ctx = Sha256.init();
ctx.update("data");
const result = ctx.finalize();
```

**Test Vectors:**
```zig
SHA256("")        = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
SHA256("abc")     = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
```

#### HMAC

```zig
const Sm3Hmac = zig_crypto.hmac.Sm3Hmac;

// Initialize
var ctx = Sm3Hmac.init("key");
ctx.update("message");
const tag = ctx.finalize();

// Convenience function
const result = zig_crypto.hmac.hmacSm3("key", "message");
```

#### SM4 Block Cipher

```zig
const Sm4 = zig_crypto.sm4.Sm4;

// Initialize
const key = [_]u8{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                   0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10};
var ctx = Sm4.init(key);

// Single block encrypt/decrypt
const ciphertext = ctx.encrypt(plaintext_block);
const decrypted = ctx.decrypt(ciphertext);

// ECB mode
ctx.encryptEcb(plaintext, ciphertext);
ctx.decryptEcb(ciphertext, plaintext);

// CBC mode
const iv = [_]u8{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                  0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
ctx.encryptCbc(iv, plaintext, ciphertext);
ctx.decryptCbc(iv, ciphertext, plaintext);

// Convenience functions
const ct = Sm4.encryptBlock(key, block);
const pt = Sm4.decryptBlock(key, block);
```

**Test Vector (GM/T 0002-2012):**
```zig
Key:        0123456789ABCDEFFEDCBA9876543210
Plaintext:  0123456789ABCDEFFEDCBA9876543210
Ciphertext: 681EDF342C58B5DB41B7387DA67B8A42
```

---

### Layer 2: Elliptic Curve Cryptography

#### SM2 Signature Algorithm

```zig
const sm2 = zig_crypto.sm2;
const point = zig_crypto.ecc_point;
const BigInt256 = zig_crypto.math_bigint.BigInt256;

// Initialize curve parameters
const curve = try point.initCurveParams(
    sm2.SM2_CURVE.p,
    sm2.SM2_CURVE.a,
    sm2.SM2_CURVE.b,
    sm2.SM2_CURVE.gx,
    sm2.SM2_CURVE.gy,
    sm2.SM2_CURVE.n,
    sm2.SM2_CURVE.h,
);

// Generate key pair
const key_pair = try sm2.KeyPair.generate(curve);
std.debug.print("Private key: {s}\n", .{key_pair.private_key.toHex()});

// Create from existing private key
const kp2 = try sm2.KeyPair.fromPrivateKey(private_key, curve);

// Sign
const id = "user@email.com";
const signature = try sm2.sign(key_pair.private_key, message, id, &curve);

// Verify
const valid = try sm2.verify(key_pair.public_key, message, signature, id, &curve);
std.debug.print("Signature valid: {}\n", .{valid});
```

#### secp256k1 (Bitcoin/Ethereum)

```zig
const secp256k1 = zig_crypto.secp256k1;
const point = zig_crypto.ecc_point;

// Initialize curve
const curve = try secp256k1.initCurve();

// Derive public key from private key
const G = point.AffinePoint.create(curve.gx, curve.gy);
const pub_key = point.scalarMul(private_key, G, &curve);
```

#### Elliptic Curve Point Operations

```zig
const point = zig_crypto.ecc_point;

// Point addition
const sum = point.pointAdd(p1, p2, &curve);

// Point doubling
const doubled = point.pointDouble(p, &curve);

// Scalar multiplication (double-and-add)
const product = point.scalarMul(scalar, point_affine, &curve);

// Jacobian to Affine conversion
const affine = jacobian.toAffine(&curve);
```

---

### Layer 3: Protocols

#### HKDF-SM3

```zig
const hkdf_sm3 = zig_crypto.hkdf_sm3;

// Extract
const prk = hkdf_sm3.extract(salt, ikm);

// Expand
var okm: [32]u8 = undefined;
hkdf_sm3.expand(&prk, info, &okm);

// One-shot
hkdf_sm3.hkdfSm3(salt, ikm, info, &okm);
```

#### Merkle Tree

```zig
const merkle = zig_crypto.merkle;

// Compute Merkle root (from hashed leaves)
const root = try merkle.merkleRoot(allocator, &leaves);

// Build from raw data (auto-hashes each leaf)
const root2 = try merkle.merkleRootFromData(allocator, &data_items);
```

---

### Layer 4: Encoding

#### Base58Check

```zig
const base58 = zig_crypto.base58;

// Encode
const encoded = try base58.encode(allocator, data);
defer allocator.free(encoded);

// Decode
const decoded = try base58.decode(allocator, encoded);
defer allocator.free(decoded);

// Base58Check (with checksum)
const addr = try base58.encodeCheck(allocator, 0x00, payload);  // version + payload + 4-byte checksum
```

#### Bech32/Bech32m

```zig
const bech32 = zig_crypto.bech32;

// Encode
const encoded = try bech32.encode(allocator, "bc", &data5, .bech32);
defer allocator.free(encoded);

// Decode
const decoded = try bech32.decode(allocator, encoded);
defer allocator.free(decoded.hrp);
defer allocator.free(decoded.data);

// 8-bit to 5-bit conversion
const data5 = try bech32.convertBits(data, 8, 5, true, allocator);
```

---

### Utilities

#### Random Numbers

```zig
const random = zig_crypto.utils_random;

// Fill with random bytes
var bytes: [32]u8 = undefined;
random.fillRandom(&bytes);
```

#### Secure Memory

```zig
const mem = zig_crypto.utils_mem;

// Constant-time comparison
const eq = mem.constantTimeEq(&a, &b);

// Secure zero
mem.secureZero(&sensitive_data);
```

---

## Build & Test

```bash
# Build library
zig build

# Run tests
zig build test

# View all build options
zig build -h
```

---

## Module Dependency Graph

```
lib.zig
├── math_utils
├── math_bigint
│   └── math_utils
├── math_modint
│   ├── math_utils
│   └── math_bigint
├── utils_random
├── utils_mem
├── sm3 (hash/sm3.zig)
├── sha256 (hash/sha256.zig)
├── hmac
│   └── sm3
├── sm4 (sym/sm4.zig)
├── ecc_field
│   ├── math_utils
│   ├── math_bigint
│   └── math_modint
├── ecc_point
│   ├── math_bigint
│   ├── math_modint
│   └── ecc_field
├── sm2
│   ├── math_bigint
│   ├── math_modint
│   ├── ecc_field
│   ├── ecc_point
│   ├── sm3
│   ├── utils_random
│   └── utils_mem
├── secp256k1
│   ├── math_bigint
│   ├── math_modint
│   ├── ecc_field
│   └── ecc_point
├── ed25519
│   ├── math_bigint
│   ├── ecc_field
│   ├── utils_random
│   └── utils_mem
├── hkdf_sm3
│   ├── sm3
│   └── hmac
├── merkle
│   └── sm3
├── base58
│   └── sha256
└── bech32
```

---

## Standards & References

### Chinese National Standards (GM/T)
- [GM/T 0002-2012](http://www.gmisp.cn/) — SM4 Block Cipher Algorithm
- [GM/T 0003-2012](http://www.gmisp.cn/) — SM2 Elliptic Curve Public Key Algorithm
- [GM/T 0004-2012](http://www.gmisp.cn/) — SM3 Cryptographic Hash Algorithm

### International Standards
- FIPS 180-4 — SHA-256
- RFC 2104 — HMAC
- RFC 5869 — HKDF
- RFC 8032 — Ed25519
- BIP 173 — Bech32
- BIP 350 — Bech32m
- SEC 2 — secp256k1 Curve Parameters

### Implementation References
- [OpenSSL](https://www.openssl.org/) — SM3/SM4 reference implementation
- [Linux Kernel crypto/sm4.c](https://github.com/torvalds/linux/blob/master/crypto/sm4.c) — SM4 optimized implementation

---

## License

MIT License

---

## Contributing

Issues and Pull Requests are welcome!

## Acknowledgments

- Chinese national cryptographic standards published by the State Cryptography Administration
- Implementation references from OpenSSL, Linux Kernel and other open source projects
