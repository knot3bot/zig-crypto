//! Secure random number generation for cryptographic operations.
//!
//! Uses the OS CSPRNG (getrandom/urandom) for all randomness.
//! NEVER use std.rand for cryptographic purposes.

const std = @import("std");

/// Fill a byte slice with cryptographically secure random bytes.
/// Uses the OS CSPRNG (/dev/urandom or getrandom syscall).
pub fn fillRandom(buf: []u8) void {
    std.crypto.random.bytes(buf);
}

/// Create a random integer of the given type.
pub fn randomInt(comptime T: type) T {
    var buf: [@sizeOf(T)]u8 = undefined;
    fillRandom(&buf);
    return std.mem.readInt(T, &buf, .little);
}

/// Create a random scalar in [1, n-1] for elliptic curve operations.
/// n must be the curve order. Uses rejection sampling.
pub fn randomScalar(n: []const u8) []const u8 {
    // This is a placeholder - the actual implementation needs
    // the full bigint modint module. For now, we provide
    // the OS-level randomness primitive.
    _ = n;
    @compileError("Use sm2.randomScalar() or secp256k1.randomScalar() instead");
}

/// Generate a random 256-bit unsigned integer (32 bytes).
pub fn randomU256() [32]u8 {
    var buf: [32]u8 = undefined;
    fillRandom(&buf);
    return buf;
}

test "fill random produces non-zero" {
    var buf: [32]u8 = undefined;
    fillRandom(&buf);
    // Extremely unlikely to be all zeros
    var all_zero = true;
    for (buf) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try std.testing.expect(!all_zero);
}

test "random U256 is non-deterministic" {
    const a = randomU256();
    const b = randomU256();
    // Extremely unlikely to be equal
    var equal = true;
    for (a, b) |aa, bb| {
        if (aa != bb) {
            equal = false;
            break;
        }
    }
    try std.testing.expect(!equal);
}
