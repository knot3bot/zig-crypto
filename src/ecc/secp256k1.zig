//! secp256k1 curve parameters (used by Bitcoin, Ethereum, etc.)
//!
//! Provides the standard secp256k1 curve defined over Fp:
//! y² = x³ + 7 (mod p)
//! where p = 2^256 - 2^32 - 977

const std = @import("std");
const bigint = @import("math_bigint");
const modint = @import("math_modint");
const point = @import("ecc_point");
const BigInt256 = bigint.BigInt256;
const MontgomeryContext = modint.MontgomeryContext;
const CurveParams = point.CurveParams;

/// secp256k1 curve parameters.
pub const SECP256K1_CURVE = struct {
    /// Prime p = 2^256 - 2^32 - 977
    pub const p_hex = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";
    /// Curve coefficient a = 0
    pub const a_hex = "0";
    /// Curve coefficient b = 7
    pub const b_hex = "7";
    /// Generator x-coordinate
    pub const gx_hex = "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
    /// Generator y-coordinate
    pub const gy_hex = "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";
    /// Group order n
    pub const n_hex = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
    /// Cofactor h = 1
    pub const h: u32 = 1;
};

/// Initialize secp256k1 curve parameters.
pub fn initCurve() !CurveParams {
    return point.initCurveParams(
        SECP256K1_CURVE.p_hex,
        SECP256K1_CURVE.a_hex,
        SECP256K1_CURVE.b_hex,
        SECP256K1_CURVE.gx_hex,
        SECP256K1_CURVE.gy_hex,
        SECP256K1_CURVE.n_hex,
        SECP256K1_CURVE.h,
    );
}

test "secp256k1 curve initialization" {
    const curve = try initCurve();
    try std.testing.expect(!curve.p.isZero());
    try std.testing.expect(!curve.n.isZero());
    try std.testing.expect(!curve.gx.isZero());
    try std.testing.expect(!curve.gy.isZero());
}
