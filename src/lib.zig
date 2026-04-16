//! zig-crypto: 公链密码学库 (Public Chain Cryptographic Library)
//!
//! 包含国密算法 (GM/T 0002/0003/0004) 和主流密码算法,
//! 纯 Zig 实现, 无 C 依赖.
//!
//! ## 国密算法
//! - SM2: 椭圆曲线签名/验签/密钥交换 (GM/T 0003-2012)
//! - SM3: 杂凑算法 (GM/T 0004-2012)
//! - SM4: 分组密码 (GM/T 0002-2012)
//!
//! ## 链原语
//! - secp256k1: EVM 兼容曲线
//! - Ed25519: 现代签名算法
//! - SHA-256: 广泛使用的哈希
//! - HMAC: 消息认证码
//! - Base58/Bech32: 地址编码
//! - Merkle Tree: 默克尔树

// Layer 0: Math Primitives
pub const math_utils = @import("math_utils");
pub const math_bigint = @import("math_bigint");
pub const math_modint = @import("math_modint");

// Layer 0: Utilities
pub const utils_random = @import("utils_random");
pub const utils_mem = @import("utils_mem");

// Layer 1: Hash Functions
pub const sm3 = @import("sm3");
pub const sha256 = @import("sha256");
pub const hmac = @import("hmac");

// Layer 1: Symmetric Encryption
pub const sm4 = @import("sm4");

// Layer 2: Elliptic Curve
pub const ecc_field = @import("ecc_field");
pub const ecc_point = @import("ecc_point");
pub const sm2 = @import("sm2");
pub const secp256k1 = @import("secp256k1");
pub const ed25519 = @import("ed25519");

// Layer 3: Protocols
pub const hkdf_sm3 = @import("hkdf_sm3");
pub const merkle = @import("merkle");

// Layer 4: Encoding
pub const base58 = @import("base58");
pub const bech32 = @import("bech32");

// Note: usingnamespace removed in Zig 0.16.
// Access types via: zig_crypto.math_utils.*, zig_crypto.sm3.*, etc.
