//! HKDF-SM3: HMAC-based Key Derivation Function using SM3.
//!
//! Implements HKDF (RFC 5869) with SM3 as the underlying hash function.

const std = @import("std");
const sm3_mod = @import("sm3");
const hmac_mod = @import("hmac");
const Sm3Hmac = hmac_mod.Sm3Hmac;

pub const DIGEST_SIZE = sm3_mod.DIGEST_SIZE;

/// HKDF-Extract: PRK = HMAC-SM3(salt, IKM).
pub fn extract(salt: []const u8, ikm: []const u8) [DIGEST_SIZE]u8 {
    var ctx = Sm3Hmac.init(salt);
    ctx.update(ikm);
    return ctx.finalize();
}

/// HKDF-Expand: OKM = T(1) || T(2) || ... || T(N) truncated.
pub fn expand(prk: []const u8, info: []const u8, okm: []u8) void {
    const n = (okm.len + DIGEST_SIZE - 1) / DIGEST_SIZE;
    std.debug.assert(n <= 255);

    var prev: [DIGEST_SIZE]u8 = undefined;
    var offset: usize = 0;

    for (1..n + 1) |i| {
        var ctx = Sm3Hmac.init(prk);
        if (i > 1) {
            ctx.update(&prev);
        }
        ctx.update(info);
        ctx.update(&[_]u8{@intCast(i)});

        const t = ctx.finalize();
        prev = t;

        const copy_len = @min(DIGEST_SIZE, okm.len - offset);
        @memcpy(okm[offset .. offset + copy_len], t[0..copy_len]);
        offset += copy_len;
    }
}

/// HKDF-SM3 convenience: extract then expand.
pub fn hkdfSm3(salt: []const u8, ikm: []const u8, info: []const u8, okm: []u8) void {
    const prk = extract(salt, ikm);
    expand(&prk, info, okm);
}

test "HKDF-SM3 basic" {
    const salt = "salt";
    const ikm = "input key material";
    var okm: [32]u8 = undefined;
    hkdfSm3(salt, ikm, "", &okm);

    // Verify non-zero output
    var all_zero = true;
    for (okm) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try std.testing.expect(!all_zero);
}

test "HKDF-SM3 extract determinism" {
    const prk1 = extract("salt", "ikm");
    const prk2 = extract("salt", "ikm");
    try std.testing.expectEqualSlices(u8, &prk1, &prk2);
}
