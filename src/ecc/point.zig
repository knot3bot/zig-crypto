//! Elliptic curve point operations.
//!
//! Provides affine and Jacobian point representations,
//! point addition, doubling, and scalar multiplication.

const std = @import("std");
const bigint = @import("math_bigint");
const modint = @import("math_modint");
const field = @import("ecc_field");
const BigInt256 = bigint.BigInt256;
const MontgomeryContext = modint.MontgomeryContext;
const FieldElement = field.FieldElement;

/// Curve parameters for a short Weierstrass curve y² = x³ + ax + b.
pub const CurveParams = struct {
    /// Field modulus p.
    p: BigInt256,
    /// Curve coefficient a.
    a: BigInt256,
    /// Curve coefficient b.
    b: BigInt256,
    /// Generator point x-coordinate.
    gx: BigInt256,
    /// Generator point y-coordinate.
    gy: BigInt256,
    /// Group order n.
    n: BigInt256,
    /// Cofactor h.
    h: u32,
    /// Montgomery context for the field.
    mont: MontgomeryContext,
};

/// Initialize curve parameters and Montgomery context.
pub fn initCurveParams(
    p_hex: []const u8,
    a_hex: []const u8,
    b_hex: []const u8,
    gx_hex: []const u8,
    gy_hex: []const u8,
    n_hex: []const u8,
    h: u32,
) !CurveParams {
    const p = try BigInt256.fromHex(p_hex);
    const a = try BigInt256.fromHex(a_hex);
    const b = try BigInt256.fromHex(b_hex);
    const gx = try BigInt256.fromHex(gx_hex);
    const gy = try BigInt256.fromHex(gy_hex);
    const n = try BigInt256.fromHex(n_hex);
    const mont = try MontgomeryContext.init(p);

    return .{ .p = p, .a = a, .b = b, .gx = gx, .gy = gy, .n = n, .h = h, .mont = mont };
}

/// Affine point on an elliptic curve (x, y).
/// Identity (point at infinity) is represented by x = y = 0 with infinity = true.
pub const AffinePoint = struct {
    x: BigInt256,
    y: BigInt256,
    infinity: bool,

    pub const IDENTITY = AffinePoint{
        .x = BigInt256.ZERO,
        .y = BigInt256.ZERO,
        .infinity = true,
    };

    /// Create an affine point.
    pub fn create(x: BigInt256, y: BigInt256) AffinePoint {
        return .{ .x = x, .y = y, .infinity = false };
    }

    /// Check if this is the point at infinity.
    pub fn isIdentity(self: AffinePoint) bool {
        return self.infinity;
    }
};

/// Jacobian point representation for efficient elliptic curve operations.
/// A point (X, Y, Z) corresponds to affine (X/Z², Y/Z³).
/// Identity is represented by Z = 0.
pub const JacobianPoint = struct {
    x: BigInt256,
    y: BigInt256,
    z: BigInt256,
    infinity: bool,

    pub const IDENTITY = JacobianPoint{
        .x = BigInt256.ONE,
        .y = BigInt256.ONE,
        .z = BigInt256.ZERO,
        .infinity = true,
    };

    /// Create a Jacobian point.
    pub fn create(x: BigInt256, y: BigInt256, z: BigInt256) JacobianPoint {
        return .{ .x = x, .y = y, .z = z, .infinity = z.isZero() };
    }

    /// Convert Jacobian point to affine coordinates.
    pub fn toAffine(self: JacobianPoint, curve: *const CurveParams) AffinePoint {
        if (self.infinity) return AffinePoint.IDENTITY;
        const mont = &curve.mont;

        // Z_inv = Z^(-1) mod p
        const z_int = mont.fromMontgomery(self.z);
        const z_inv = mont.modInverse(z_int);
        const z_inv_mont = mont.toMontgomery(z_inv);

        // Z²_inv = Z^(-2) mod p
        const z2_inv = mont.montMul(z_inv_mont, z_inv_mont);

        // Z³_inv = Z^(-3) mod p
        const z3_inv = mont.montMul(z2_inv, z_inv_mont);

        // x_affine = X * Z^(-2)
        const x_affine = mont.fromMontgomery(mont.montMul(self.x, z2_inv));

        // y_affine = Y * Z^(-3)
        const y_affine = mont.fromMontgomery(mont.montMul(self.y, z3_inv));

        return AffinePoint.create(x_affine, y_affine);
    }
};

/// Point addition on the elliptic curve (affine coordinates).
pub fn pointAdd(p1: AffinePoint, p2: AffinePoint, curve: *const CurveParams) AffinePoint {
    if (p1.isIdentity()) return p2;
    if (p2.isIdentity()) return p1;

    // lambda = (y2 - y1) / (x2 - x1) mod p
    const dy = BigInt256.subMod(p2.y, p1.y, curve.p);
    const dx = BigInt256.subMod(p2.x, p1.x, curve.p);
    const lambda = simpleFieldDiv(dy, dx, curve);

    // x3 = lambda² - x1 - x2 mod p
    const lambda2 = BigInt256.mulMod(lambda, lambda, curve.p);
    const x3_raw = BigInt256.sub(
        BigInt256.sub(lambda2, p1.x).result,
        p2.x,
    ).result;
    const x3_mod = if (BigInt256.cmp(x3_raw, BigInt256.ZERO) < 0)
        BigInt256.add(x3_raw, curve.p).result
    else if (BigInt256.cmp(x3_raw, curve.p) >= 0)
        BigInt256.sub(x3_raw, curve.p).result
    else
        x3_raw;

    // y3 = lambda * (x1 - x3) - y1 mod p
    const x1_minus_x3 = BigInt256.subMod(p1.x, x3_mod, curve.p);
    const lambda_x = BigInt256.mulMod(lambda, x1_minus_x3, curve.p);
    const y3_raw = BigInt256.sub(lambda_x, p1.y).result;
    const y3_mod = if (BigInt256.cmp(y3_raw, BigInt256.ZERO) < 0)
        BigInt256.add(y3_raw, curve.p).result
    else if (BigInt256.cmp(y3_raw, curve.p) >= 0)
        BigInt256.sub(y3_raw, curve.p).result
    else
        y3_raw;

    return AffinePoint.create(x3_mod, y3_mod);
}

/// Point doubling on the elliptic curve (affine coordinates).
pub fn pointDouble(p: AffinePoint, curve: *const CurveParams) AffinePoint {
    if (p.isIdentity()) return AffinePoint.IDENTITY;
    if (p.y.isZero()) return AffinePoint.IDENTITY;

    // lambda = (3 * x² + a) / (2 * y) mod p
    const x_sq = BigInt256.mulMod(p.x, p.x, curve.p);
    const three_x_sq = BigInt256.addMod(BigInt256.addMod(x_sq, x_sq, curve.p), x_sq, curve.p);
    const three_x_sq_plus_a = BigInt256.addMod(three_x_sq, curve.a, curve.p);
    const two_y = BigInt256.addMod(p.y, p.y, curve.p);
    const lambda = simpleFieldDiv(three_x_sq_plus_a, two_y, curve);

    // x3 = lambda² - 2*x mod p
    const lambda2 = BigInt256.mulMod(lambda, lambda, curve.p);
    const two_x = BigInt256.addMod(p.x, p.x, curve.p);
    var x3 = BigInt256.subMod(lambda2, two_x, curve.p);
    if (BigInt256.cmp(x3, BigInt256.ZERO) < 0) {
        x3 = BigInt256.add(x3, curve.p).result;
    }

    // y3 = lambda * (x - x3) - y mod p
    const x_minus_x3 = BigInt256.subMod(p.x, x3, curve.p);
    const lambda_x = BigInt256.mulMod(lambda, x_minus_x3, curve.p);
    var y3 = BigInt256.sub(lambda_x, p.y).result;
    if (BigInt256.cmp(y3, BigInt256.ZERO) < 0) {
        y3 = BigInt256.add(y3, curve.p).result;
    }

    return AffinePoint.create(x3, y3);
}

/// Scalar multiplication using double-and-add.
pub fn scalarMul(k: BigInt256, point: AffinePoint, curve: *const CurveParams) AffinePoint {
    if (k.isZero() or point.isIdentity()) return AffinePoint.IDENTITY;

    var result = AffinePoint.IDENTITY;
    var addend = point;
    const n = k.bitCount();

    for (0..n) |i| {
        if (k.getBit(i) == 1) {
            result = pointAdd(result, addend, curve);
        }
        addend = pointDouble(addend, curve);
    }

    return result;
}

/// Simple field division: a / b mod p computed as a * b^(p-2) mod p.
fn simpleFieldDiv(a: BigInt256, b: BigInt256, curve: *const CurveParams) BigInt256 {
    const mont = &curve.mont;
    const b_inv = mont.modInverse(b);
    return BigInt256.mulMod(a, b_inv, curve.p);
}

test "point at infinity" {
    try std.testing.expect(AffinePoint.IDENTITY.isIdentity());
    try std.testing.expect(!AffinePoint.create(BigInt256.ONE, BigInt256.ONE).isIdentity());
}
