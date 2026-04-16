//! Finite field arithmetic over Fp (prime field).
//!
//! Provides operations for elliptic curve cryptography over prime fields.
//! Uses Montgomery multiplication for efficient modular arithmetic.

const std = @import("std");
const bigint = @import("math_bigint");
const modint = @import("math_modint");
const BigInt256 = bigint.BigInt256;
const MontgomeryContext = modint.MontgomeryContext;

/// A finite field element over Fp, where p is a known prime.
/// Stores the element in Montgomery form for efficient arithmetic.
pub const FieldElement = struct {
    /// The value in Montgomery form.
    value: BigInt256,
    /// Montgomery context for this field.
    mont: *const MontgomeryContext,

    /// Create a field element from a regular (non-Montgomery) value.
    pub fn fromInt(mont: *const MontgomeryContext, x: BigInt256) FieldElement {
        return .{ .value = mont.toMontgomery(x), .mont = mont };
    }

    /// Create from Montgomery form directly.
    pub fn fromMontgomery(mont: *const MontgomeryContext, x: BigInt256) FieldElement {
        return .{ .value = x, .mont = mont };
    }

    /// Get the value in regular (non-Montgomery) form.
    pub fn toInt(self: FieldElement) BigInt256 {
        return self.mont.fromMontgomery(self.value);
    }

    /// Check if zero.
    pub fn isZero(self: FieldElement) bool {
        const regular = self.toInt();
        return regular.isZero();
    }

    /// Field addition: (a + b) mod p.
    pub fn add(a: FieldElement, b: FieldElement) FieldElement {
        std.debug.assert(a.mont == b.mont); // Same field
        const result_val = BigInt256.addMod(a.value, b.value, a.mont.modulus);
        return .{ .value = result_val, .mont = a.mont };
    }

    /// Field subtraction: (a - b) mod p.
    pub fn sub(a: FieldElement, b: FieldElement) FieldElement {
        std.debug.assert(a.mont == b.mont);
        return .{ .value = BigInt256.subMod(a.value, b.value, a.mont.modulus), .mont = a.mont };
    }

    /// Field multiplication: (a * b) mod p using Montgomery.
    pub fn mul(a: FieldElement, b: FieldElement) FieldElement {
        std.debug.assert(a.mont == b.mont);
        return .{ .value = a.mont.montMul(a.value, b.value), .mont = a.mont };
    }

    /// Field squaring: (a^2) mod p.
    pub fn sqr(a: FieldElement) FieldElement {
        return .{ .value = a.mont.montMul(a.value, a.value), .mont = a.mont };
    }

    /// Field negation: (-a) mod p.
    pub fn neg(a: FieldElement) FieldElement {
        if (a.value.isZero()) return a;
        const result = BigInt256.sub(a.mont.modulus, a.value).result;
        return .{ .value = result, .mont = a.mont };
    }

    /// Multiplicative inverse: a^(-1) mod p.
    pub fn inverse(a: FieldElement) FieldElement {
        const regular = a.toInt();
        const inv = a.mont.modInverse(regular);
        return .{ .value = a.mont.toMontgomery(inv), .mont = a.mont };
    }

    /// Double: (2 * a) mod p.
    pub fn dbl(a: FieldElement) FieldElement {
        return a.add(a);
    }

    /// Exponentiation: a^e mod p.
    pub fn pow(a: FieldElement, e: BigInt256) FieldElement {
        const result_mont = a.mont.montExp(a.value, e);
        return .{ .value = result_mont, .mont = a.mont };
    }
};

/// SM2 prime field parameters.
pub const SM2_PARAMS = struct {
    pub const p_hex = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF";
    pub const a_hex = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC";
    pub const b_hex = "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93";
    pub const n_hex = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54103";
    pub const gx_hex = "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A6880DA8A19";
    pub const gy_hex = "BC8B0B251C8C6A4DE1A8475A4CB1C2D6AF19F44F2EB18D9C40417A73E4E1F8B";
};

test "field element basic" {
    // Simple test with small prime p = 7
    const p = try BigInt256.fromHex("7");
    const mont = try MontgomeryContext.init(p);
    const a = FieldElement.fromInt(&mont, BigInt256.fromU64(3));
    const b = FieldElement.fromInt(&mont, BigInt256.fromU64(5));

    // 3 + 5 = 8 ≡ 1 (mod 7)
    const sum = a.add(b);
    const sum_int = sum.toInt();
    try std.testing.expect(sum_int.eql(BigInt256.fromU64(1)));
}
