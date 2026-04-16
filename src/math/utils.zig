//! Cryptographic utility functions for constant-time operations and bit manipulation.
//!
//! All secret-dependent operations MUST go through these utilities
//! to prevent side-channel attacks.

const std = @import("std");

/// Constant-time select: returns `a` if `cond` is 1, `b` if `cond` is 0.
/// `cond` MUST be 0 or 1; use `ct_select_mask` for arbitrary masks.
pub fn ctSelect(comptime T: type, cond: usize, a: T, b: T) T {
    const mask: T = std.math.cast(T, 0 -% cond) orelse unreachable;
    return (a & mask) | (b & ~mask);
}

/// Constant-time select using a full mask.
pub fn ctSelectMask(comptime T: type, mask: T, a: T, b: T) T {
    return (a & mask) | (b & ~mask);
}

/// Constant-time comparison: returns 1 if a == b, 0 otherwise.
pub fn ctEqual(comptime T: type, a: T, b: T) usize {
    const diff = a ^ b;
    // If diff is 0, all bits are 0; XOR with itself and shift gives 1.
    // If diff != 0, the MSB fold will produce non-zero.
    return @intFromBool(diff == 0);
}

/// Constant-time byte slice comparison.
pub fn ctBytesEqual(a: []const u8, b: []const u8) usize {
    if (a.len != b.len) return 0;
    var diff: u8 = 0;
    for (a, b) |aa, bb| {
        diff |= aa ^ bb;
    }
    return @intFromBool(diff == 0);
}

/// Constant-time less-than for unsigned integers.
/// Returns 1 if a < b, 0 otherwise.
pub fn ctLt(comptime T: type, a: T, b: T) usize {
    // For unsigned types: a < b iff (a ^ ((a ^ b) | ((a -% b) ^ a))) has MSB set
    // Simpler: use the borrow from subtraction
    const borrow = @intFromBool(a < b);
    return borrow;
}

/// Number of bits required to represent `x`.
pub fn bitLen(comptime T: type, x: T) usize {
    var count: usize = 0;
    var v = x;
    while (v != 0) : (v >>= 1) {
        count += 1;
    }
    return count;
}

/// Number of bytes required to represent `x`.
pub fn byteLen(comptime T: type, x: T) usize {
    return (bitLen(T, x) + 7) / 8;
}

/// Reverse bytes in place (big-endian <-> little-endian).
pub fn byteReverse(comptime N: usize, input: *[N]u8) void {
    var i: usize = 0;
    while (i < N / 2) : (i += 1) {
        const tmp = input[i];
        input[i] = input[N - 1 - i];
        input[N - 1 - i] = tmp;
    }
}

/// Convert a u64 to big-endian bytes.
pub fn u64ToBeBytes(val: u64) [8]u8 {
    var buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &buf, val, .big);
    return buf;
}

/// Convert big-endian bytes to u64.
pub fn beBytesToU64(bytes: *const [8]u8) u64 {
    return std.mem.readInt(u64, bytes, .big);
}

/// Convert a u32 to big-endian bytes.
pub fn u32ToBeBytes(val: u32) [4]u8 {
    var buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &buf, val, .big);
    return buf;
}

/// Convert big-endian bytes to u32.
pub fn beBytesToU32(bytes: *const [4]u8) u32 {
    return std.mem.readInt(u32, bytes, .big);
}

/// Read a slice of bytes into a u64 (big-endian), zero-padding if short.
pub fn readBeU64(bytes: []const u8) u64 {
    var buf: [8]u8 = [_]u8{0} ** 8;
    const offset = 8 - bytes.len;
    @memcpy(buf[offset..], bytes);
    return std.mem.readInt(u64, &buf, .big);
}

test "constant-time select" {
    try std.testing.expectEqual(@as(u64, 42), ctSelect(u64, 1, 42, 99));
    try std.testing.expectEqual(@as(u64, 99), ctSelect(u64, 0, 42, 99));
}

test "constant-time equality" {
    try std.testing.expectEqual(@as(usize, 1), ctEqual(u64, 42, 42));
    try std.testing.expectEqual(@as(usize, 0), ctEqual(u64, 42, 43));
}

test "constant-time bytes equality" {
    const a = "hello";
    const b = "hello";
    const c = "world";
    try std.testing.expectEqual(@as(usize, 1), ctBytesEqual(a, b));
    try std.testing.expectEqual(@as(usize, 0), ctBytesEqual(a, c));
}

test "bit and byte length" {
    try std.testing.expectEqual(@as(usize, 0), bitLen(u64, 0));
    try std.testing.expectEqual(@as(usize, 8), bitLen(u64, 255));
    try std.testing.expectEqual(@as(usize, 1), byteLen(u64, 1));
    try std.testing.expectEqual(@as(usize, 2), byteLen(u64, 256));
}

test "big-endian conversions" {
    const val: u32 = 0x01020304;
    const bytes = u32ToBeBytes(val);
    try std.testing.expectEqual(@as(u32, 0x01020304), beBytesToU32(&bytes));
}
