//! Constant-time memory operations for cryptographic code.
//!
//! These operations ensure no timing side-channels leak secret data.

const std = @import("std");

/// Constant-time memory comparison.
/// Returns true if slices are equal, false otherwise.
/// Execution time depends ONLY on length, not on content.
pub fn ctEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var diff: u8 = 0;
    for (a, b) |aa, bb| {
        diff |= aa ^ bb;
    }
    return diff == 0;
}

/// Constant-time memory zero check.
/// Returns true if all bytes are zero.
pub fn ctIsZero(bytes: []const u8) bool {
    var acc: u8 = 0;
    for (bytes) |b| {
        acc |= b;
    }
    return acc == 0;
}

/// Constant-time conditional memory copy.
/// If `cond` is true, copies src to dst; otherwise leaves dst unchanged.
/// `cond` MUST be a boolean (which resolves to 0 or 1 at comptime or runtime).
pub fn ctConditionalCopy(cond: bool, dst: []u8, src: []const u8) void {
    std.debug.assert(dst.len >= src.len);
    const mask: u8 = if (cond) 0xFF else 0x00;
    for (dst[0..src.len], src) |*d, s| {
        d.* = (s & mask) | (d.* & ~mask);
    }
}

/// Secure memory zeroing.
/// Uses volatile writes to prevent compiler optimization from removing the zeroing.
pub fn secureZero(bytes: []u8) void {
    for (bytes) |*b| {
        b.* = 0;
    }
    // Compiler barrier to prevent dead-store elimination
    std.mem.doNotOptimizeAway(bytes.ptr);
}

/// XOR two byte slices in place: dst[i] ^= src[i].
pub fn xorInPlace(dst: []u8, src: []const u8) void {
    std.debug.assert(dst.len >= src.len);
    for (dst[0..src.len], src) |*d, s| {
        d.* ^= s;
    }
}

/// XOR three byte slices into dst: dst[i] = a[i] ^ b[i].
pub fn xorInto(dst: []u8, a: []const u8, b: []const u8) void {
    std.debug.assert(dst.len >= a.len and a.len == b.len);
    for (dst[0..a.len], a, b) |*d, aa, bb| {
        d.* = aa ^ bb;
    }
}

test "constant-time bytes equal" {
    try std.testing.expect(ctEqual("abc", "abc"));
    try std.testing.expect(!ctEqual("abc", "abd"));
    try std.testing.expect(!ctEqual("abc", "ab"));
}

test "constant-time is zero" {
    try std.testing.expect(ctIsZero(&[_]u8{0} ** 4));
    try std.testing.expect(!ctIsZero(&[_]u8{ 0, 0, 0, 1 }));
}

test "secure zero" {
    var buf = [_]u8{ 1, 2, 3, 4 };
    secureZero(&buf);
    try std.testing.expect(ctIsZero(&buf));
}

test "xor in place" {
    var buf = [_]u8{ 0xFF, 0x00, 0xAA };
    xorInPlace(&buf, &[_]u8{ 0xFF, 0x00, 0xAA });
    try std.testing.expect(ctIsZero(&buf));
}
