//! Modular integer arithmetic for cryptographic operations.
//!
//! Implements Montgomery multiplication for efficient modular arithmetic
//! over prime fields, which is essential for elliptic curve operations.

const std = @import("std");
const bigint = @import("math_bigint");
const BigInt256 = bigint.BigInt256;

/// Montgomery modular arithmetic context.
/// Precomputes Montgomery parameters for efficient modular arithmetic.
pub const MontgomeryContext = struct {
    /// The modulus
    modulus: BigInt256,
    /// R = 2^256 mod m (Montgomery radix)
    r: BigInt256,
    /// R^2 mod m (used for Montgomery conversion)
    r2: BigInt256,
    /// R * R mod m (same as R^2 mod m)
    /// n_prime = -m^(-1) mod 2^64 (Montgomery coefficient)
    n0: u64,
    /// Number of bits in the modulus
    bits: usize,

    /// Initialize Montgomery context for the given modulus.
    /// Precomputes R, R^2, and n0 for Montgomery multiplication.
    pub fn init(modulus: BigInt256) !MontgomeryContext {
        if (modulus.isZero()) return error.ModulusIsZero;
        if (modulus.isOne()) return error.ModulusIsOne;

        const bits = modulus.bitCount();

        // R = 2^256 mod m (since we use 4 x u64 limbs, R = 2^(4*64) = 2^256)
        // For a 256-bit modulus, R = 2^256 mod m
        // Compute using binary long division
        var r = BigInt256.ZERO;
        // 2^256 = (1 << 256), which is just beyond our range
        // We need to compute 2^256 mod m using the wide mod function
        const one = BigInt256.ONE;
        const two_256_hi = one; // hi part = 1 (meaning 2^256)
        const two_256_lo = BigInt256.ZERO; // lo part = 0
        r = BigInt256.mod512(two_256_lo, two_256_hi, modulus);

        // R^2 = (2^256)^2 mod m = (R * R) mod m
        // We need 512-bit multiplication of r * r then mod m
        const wide_r = BigInt256.mulWide(r, r);
        const r2 = BigInt256.mod512(wide_r.low, wide_r.high, modulus);

        // Compute n0 = -m^(-1) mod 2^64 using extended Euclidean algorithm
        // Simplified: compute (1 - m * m^(-1)) / m using Newton's method
        // For now, we use a simpler approach: find n0 such that m * n0 ≡ -1 (mod 2^64)
        const n0 = computeN0(modulus.limbs[0]);

        return .{
            .modulus = modulus,
            .r = r,
            .r2 = r2,
            .n0 = n0,
            .bits = bits,
        };
    }

    /// Convert a BigInt256 to Montgomery form: a * R mod m.
    pub fn toMontgomery(self: MontgomeryContext, a: BigInt256) BigInt256 {
        return self.montMul(a, self.r2);
    }

    /// Convert from Montgomery form back to regular form: a * R^(-1) mod m.
    pub fn fromMontgomery(self: MontgomeryContext, a: BigInt256) BigInt256 {
        return self.montMul(a, BigInt256.ONE);
    }

    /// Montgomery multiplication: computes (a * b * R^(-1)) mod m.
    /// This is the core operation that makes Montgomery arithmetic efficient.
    pub fn montMul(self: MontgomeryContext, a: BigInt256, b: BigInt256) BigInt256 {
        // Coarsely Integrated Operand Scanning (CIOS) method
        var t: [5]u64 = .{0} ** 5;

        for (0..4) |i| {
            var carry: u64 = 0;
            const ai = a.limbs[i];

            // Multiply and add
            for (0..4) |j| {
                const prod = @as(u128, ai) * @as(u128, b.limbs[j]) + @as(u128, t[j]) + @as(u128, carry);
                t[j] = @truncate(prod);
                carry = @intCast(prod >> 64);
            }

            // Add carry to t[4]
            var sum = @as(u128, t[4]) + @as(u128, carry);
            t[4] = @truncate(sum);

            // Compute m * n0 to reduce
            const m = @as(u128, t[0]) * @as(u128, self.n0);
            const mi = @as(u64, @truncate(m));

            // t = t + mi * modulus
            var mcarry: u64 = 0;
            for (0..4) |j| {
                const mprod = @as(u128, mi) * @as(u128, self.modulus.limbs[j]) + @as(u128, t[j]) + @as(u128, mcarry);
                t[j] = @truncate(mprod);
                mcarry = @intCast(mprod >> 64);
            }
            // Propagate carry
            sum = @as(u128, t[4]) + @as(u128, mcarry);
            t[4] = @truncate(sum);
        }

        // Result is in t[0..4]
        var result = BigInt256{ .limbs = .{ t[0], t[1], t[2], t[3] } };

        // Final subtraction if needed
        if (BigInt256.cmp(result, self.modulus) >= 0) {
            result = BigInt256.sub(result, self.modulus).result;
        }

        return result;
    }

    /// Montgomery exponentiation: computes a^e mod m using Montgomery ladder.
    pub fn montExp(self: MontgomeryContext, a: BigInt256, e: BigInt256) BigInt256 {
        var result = self.r; // R mod m (Montgomery form of 1)
        var base = self.toMontgomery(a);

        const n = e.bitCount();
        if (n == 0) return self.fromMontgomery(result);

        for (0..n) |i| {
            const bit = e.getBit(n - 1 - i);
            if (bit == 1) {
                result = self.montMul(result, base);
            }
            base = self.montMul(base, base);
        }

        return self.fromMontgomery(result);
    }

    /// Modular multiplication using Montgomery: (a * b) mod m.
    pub fn mulMod(self: MontgomeryContext, a: BigInt256, b: BigInt256) BigInt256 {
        const a_mont = self.toMontgomery(a);
        const b_mont = self.toMontgomery(b);
        const result_mont = self.montMul(a_mont, b_mont);
        return self.fromMontgomery(result_mont);
    }

    /// Modular squaring: (a^2) mod m.
    pub fn sqrMod(self: MontgomeryContext, a: BigInt256) BigInt256 {
        return self.mulMod(a, a);
    }

    /// Modular inverse using Fermat's little theorem: a^(m-2) mod m.
    /// Requires m to be prime.
    pub fn modInverse(self: MontgomeryContext, a: BigInt256) BigInt256 {
        // a^(-1) mod m = a^(m-2) mod m (Fermat's little theorem)
        var exp = self.modulus;
        exp = BigInt256.sub(exp, BigInt256.ONE).result;
        exp = BigInt256.sub(exp, BigInt256.ONE).result; // m - 2
        return self.montExp(a, exp);
    }
};

/// Compute n0 for Montgomery reduction.
/// n0 satisfies: m * n0 ≡ -1 (mod 2^64)
/// Uses Newton's method: x_{i+1} = x_i * (2 - m * x_i) (mod 2^64)
fn computeN0(m0: u64) u64 {
    if (m0 == 0) return 0;

    // Newton's method for modular inverse mod 2^64
    // Start with x₀ ≈ m₀⁻¹ (mod 2^64)
    // Iteration: x_{i+1} = x_i * (2 - m₀ * x_i) (mod 2^64)
    // We want n0 = −(m₀⁻¹) mod 2^64
    var x: u64 = m0; // initial guess (m₀ is odd for crypto primes)
    x = x *% (2 -% m0 *% x);
    x = x *% (2 -% m0 *% x);
    x = x *% (2 -% m0 *% x);
    x = x *% (2 -% m0 *% x);
    // x is now m₀⁻¹ mod 2^64; return −m₀⁻¹ mod 2^64
    return 0 -% x;
}

/// Direct modular multiplication without Montgomery form.
/// Less efficient but simpler for one-off computations.
pub fn simpleMulMod(a: BigInt256, b: BigInt256, m: BigInt256) BigInt256 {
    const wide = BigInt256.mulWide(a, b);
    return BigInt256.mod512(wide.low, wide.high, m);
}

/// Modular exponentiation using binary method (square-and-multiply).
/// Slower than Montgomery for repeated operations.
pub fn simpleExpMod(a: BigInt256, e: BigInt256, m: BigInt256) BigInt256 {
    if (e.isZero()) return BigInt256.ONE;

    var result = BigInt256.ONE;
    var base = a;

    // Reduce base modulo m first
    if (BigInt256.cmp(base, m) >= 0) {
        base = BigInt256.mod512(base, BigInt256.ZERO, m);
    }

    const n = e.bitCount();
    for (0..n) |i| {
        if (e.getBit(i) == 1) {
            result = simpleMulMod(result, base, m);
        }
        base = simpleMulMod(base, base, m);
    }

    return result;
}

test "Montgomery context initialization" {
    // Use a small prime for testing: p = 7
    const p = try BigInt256.fromHex("7");
    const ctx = try MontgomeryContext.init(p);
    try std.testing.expect(!ctx.r.isZero());
}

test "Montgomery to/from conversion" {
    const p = try BigInt256.fromHex("7");
    const ctx = try MontgomeryContext.init(p);
    const a = BigInt256.fromU64(3);
    const a_mont = ctx.toMontgomery(a);
    const a_back = ctx.fromMontgomery(a_mont);
    try std.testing.expect(a_back.eql(a));
}

test "modular exponentiation" {
    // 2^10 mod 7 = 1024 mod 7 = 2
    const base = BigInt256.fromU64(2);
    const exp = BigInt256.fromU64(10);
    const mod = BigInt256.fromU64(7);
    const result = simpleExpMod(base, exp, mod);
    try std.testing.expect(result.eql(BigInt256.fromU64(2)));
}
