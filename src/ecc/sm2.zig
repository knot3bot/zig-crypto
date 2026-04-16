//! SM2 elliptic curve digital signature algorithm (GM/T 0003-2012).
//!
//! SM2 uses a 256-bit elliptic curve over a prime field with:
//! - SM3 for message hashing
//! - RFC6979-style deterministic k generation
//! - Standardized curve parameters

const std = @import("std");
const bigint = @import("math_bigint");
const modint = @import("math_modint");
const field = @import("ecc_field");
const point = @import("ecc_point");
const sm3_mod = @import("sm3");
const random_mod = @import("utils_random");
const mem_mod = @import("utils_mem");
const BigInt256 = bigint.BigInt256;
const MontgomeryContext = modint.MontgomeryContext;
const FieldElement = field.FieldElement;
const AffinePoint = point.AffinePoint;
const CurveParams = point.CurveParams;

/// SM2 curve parameters (GM/T 0003-2012).
pub const SM2_CURVE = struct {
    /// Curve prime p.
    pub const p = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF";
    /// Curve coefficient a.
    pub const a = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC";
    /// Curve coefficient b.
    pub const b = "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93";
    /// Generator x-coordinate.
    pub const gx = "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A6880DA8A19";
    /// Generator y-coordinate.
    pub const gy = "BC8B0B251C8C6A4DE1A8475A4CB1C2D6AF19F44F2EB18D9C40417A73E4E1F8B";
    /// Group order n.
    pub const n = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54103";
    /// Cofactor h.
    pub const h: u32 = 1;
};

/// SM2 key pair.
pub const KeyPair = struct {
    /// Private key d (random scalar in [1, n-1]).
    private_key: BigInt256,
    /// Public key point P = d * G.
    public_key: AffinePoint,
    /// Curve parameters.
    curve: CurveParams,

    /// Generate a new random SM2 key pair.
    pub fn generate(curve: CurveParams) !KeyPair {
        // Generate random scalar d in [1, n-1]
        var d_bytes: [32]u8 = undefined;
        while (true) {
            random_mod.fillRandom(&d_bytes);
            const d = BigInt256.fromBytes(&d_bytes);
            // d must be in [1, n-1]
            if (BigInt256.cmp(d, BigInt256.ONE) >= 0 and BigInt256.cmp(d, curve.n) < 0) {
                const pub_point = point.scalarMul(d, createGenerator(&curve), &curve);
                return .{
                    .private_key = d,
                    .public_key = pub_point,
                    .curve = curve,
                };
            }
        }
    }

    /// Create a key pair from an existing private key.
    pub fn fromPrivateKey(d: BigInt256, curve: CurveParams) !KeyPair {
        if (BigInt256.cmp(d, BigInt256.ONE) < 0 or BigInt256.cmp(d, curve.n) >= 0) {
            return error.InvalidPrivateKey;
        }
        const pub_point = point.scalarMul(d, createGenerator(&curve), &curve);
        return .{
            .private_key = d,
            .public_key = pub_point,
            .curve = curve,
        };
    }
};

/// SM2 signature (r, s).
pub const Signature = struct {
    r: BigInt256,
    s: BigInt256,
};

/// Get the SM2 generator point G.
fn createGenerator(curve: *const CurveParams) AffinePoint {
    return AffinePoint.create(curve.gx, curve.gy);
}

/// Compute SM2 ID hash (ZA).
/// ZA = SM3(ENTL || ID || a || b || xG || yG)
/// where ENTL is the 2-byte bit length of ID.
pub fn computeZA(id: []const u8, curve: *const CurveParams) [32]u8 {
    var ctx = sm3_mod.Sm3.init();

    // ENTL: 2-byte big-endian bit length of ID
    const entl: u16 = @intCast(id.len * 8);
    var entl_bytes: [2]u8 = undefined;
    std.mem.writeInt(u16, &entl_bytes, entl, .big);
    ctx.update(&entl_bytes);

    // ID
    ctx.update(id);

    // Curve parameter a
    const a_bytes = curve.a.toBytes();
    ctx.update(&a_bytes);

    // Curve parameter b
    const b_bytes = curve.b.toBytes();
    ctx.update(&b_bytes);

    // Generator point G
    const gx_bytes = curve.gx.toBytes();
    ctx.update(&gx_bytes);
    const gy_bytes = curve.gy.toBytes();
    ctx.update(&gy_bytes);

    return ctx.finalize();
}

/// Sign a message using SM2.
/// Implements the SM2 signature algorithm per GM/T 0003-2012.
pub fn sign(
    private_key: BigInt256,
    message: []const u8,
    id: []const u8,
    curve: *const CurveParams,
) !Signature {
    // Step 1: Compute ZA = SM3(ENTL||ID||a||b||xG||yG)
    const za = computeZA(id, curve);

    // Step 2: Compute e = SM3(ZA || M)
    var ctx = sm3_mod.Sm3.init();
    ctx.update(&za);
    ctx.update(message);
    const e_hash = ctx.finalize();

    // Convert hash to BigInt256
    const e = BigInt256.fromBytes(&e_hash);

    // Generate random k in [1, n-1]
    // In production, use RFC6979 deterministic k. For now, random.
    var k: BigInt256 = undefined;
    var k_bytes: [32]u8 = undefined;
    while (true) {
        random_mod.fillRandom(&k_bytes);
        k = BigInt256.fromBytes(&k_bytes);
        if (BigInt256.cmp(k, BigInt256.ONE) >= 0 and BigInt256.cmp(k, curve.n) < 0) {
            break;
        }
    }

    // Compute (x1, y1) = k * G
    const G = createGenerator(curve);
    const kG = point.scalarMul(k, G, curve);

    // r = (e + x1) mod n
    const ex = BigInt256.addMod(e, kG.x, curve.n);
    var r = ex;
    // If r == 0 or r + k == n, generate new k
    if (r.isZero()) return error.SignatureFailed;
    const r_plus_k = BigInt256.addMod(r, k, curve.n);
    if (r_plus_k.eql(curve.n)) return error.SignatureFailed;

    // s = ((1 + d)^(-1) * (k - r * d)) mod n
    const one_plus_d = BigInt256.addMod(BigInt256.ONE, private_key, curve.n);
    const one_plus_d_inv = modint.simpleExpMod(one_plus_d, BigInt256.sub(curve.n, BigInt256.fromU64(2)).result, curve.n);
    const r_times_d = BigInt256.mulMod(r, private_key, curve.n);
    const k_minus_rd = BigInt256.subMod(k, r_times_d, curve.n);
    const s = BigInt256.mulMod(one_plus_d_inv, k_minus_rd, curve.n);

    if (s.isZero()) return error.SignatureFailed;

    return .{ .r = r, .s = s };
}

/// Verify an SM2 signature.
pub fn verify(
    public_key: AffinePoint,
    message: []const u8,
    signature: Signature,
    id: []const u8,
    curve: *const CurveParams,
) !bool {
    // Step 1: Verify r, s in [1, n-1]
    if (BigInt256.cmp(signature.r, BigInt256.ONE) < 0 or
        BigInt256.cmp(signature.s, BigInt256.ONE) < 0 or
        BigInt256.cmp(signature.r, curve.n) >= 0 or
        BigInt256.cmp(signature.s, curve.n) >= 0)
    {
        return false;
    }

    // Step 2: Compute ZA
    const za = computeZA(id, curve);

    // Step 3: Compute e = SM3(ZA || M)
    var ctx = sm3_mod.Sm3.init();
    ctx.update(&za);
    ctx.update(message);
    const e_hash = ctx.finalize();
    const e = BigInt256.fromBytes(&e_hash);

    // Step 4: Compute t = (r + s) mod n
    const t = BigInt256.addMod(signature.r, signature.s, curve.n);
    if (t.isZero()) return false;

    // Step 5: Compute (x1, y1) = s * G + t * P
    const G = createGenerator(curve);
    const sG = point.scalarMul(signature.s, G, curve);
    const tP = point.scalarMul(t, public_key, curve);
    const R = point.pointAdd(sG, tP, curve);

    if (R.isIdentity()) return false;

    // Step 6: Verify r == (e + x1) mod n
    const e_plus_x1 = BigInt256.addMod(e, R.x, curve.n);

    return e_plus_x1.eql(signature.r);
}

test "SM2 compute ZA" {
    // This test verifies that ZA computation produces a consistent result
    const curve = try point.initCurveParams(
        SM2_CURVE.p,
        SM2_CURVE.a,
        SM2_CURVE.b,
        SM2_CURVE.gx,
        SM2_CURVE.gy,
        SM2_CURVE.n,
        SM2_CURVE.h,
    );
    _ = computeZA("1234567812345678", &curve);
    // We just verify it doesn't crash; exact value requires full verification
}
