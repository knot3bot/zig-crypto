//! Bech32 encoding/decoding (BIP 173/BIP 350).
//!
//! Bech32 is a checksummed base32 encoding used in SegWit addresses.
//! This implementation supports both Bech32 and Bech32m (BIP 350).

const std = @import("std");

const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// Bech32 encoding variant.
pub const Variant = enum { bech32, bech32m };

/// Bech32 checksum constants.
fn bech32Polymod(values: []const u5) u32 {
    const GEN = [_]u32{ 0x3B6A57B2, 0x26508E5D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3 };
    var chk: u32 = 1;
    for (values) |v| {
        const b = chk >> 25;
        chk = ((chk & 0x1FFFFFF) << 5) ^ v;
        for (0..5) |i| {
            if (((b >> @intCast(i)) & 1) != 0) {
                chk ^= GEN[i];
            }
        }
    }
    return chk;
}

/// Bech32 HRP expansion.
fn bech32HrpExpand(hrp: []const u8) []const u5 {
    // This is a helper; actual allocation handled by caller
    _ = hrp;
    return &[_]u5{};
}

/// Compute Bech32 checksum.
fn bech32ChecksumCreate(hrp: []const u8, data: []const u5, variant: Variant) [6]u5 {
    const values = std.mem.concat(std.testing.allocator, u5, &.{
        bech32HrpExpandList(hrp),
        data,
        &[_]u5{ 0, 0, 0, 0, 0, 0 },
    }) catch unreachable;
    defer std.testing.allocator.free(values);

    const polymod = bech32Polymod(values) ^ switch (variant) {
        .bech32 => @as(u32, 1),
        .bech32m => @as(u32, 0x2BC830A3),
    };

    var result: [6]u5 = undefined;
    for (0..6) |i| {
        result[i] = @intCast((polymod >> @intCast(5 * (5 - i))) & 31);
    }
    return result;
}

/// HRP expansion for Bech32 checksum computation.
fn bech32HrpExpandList(hrp: []const u8) []const u5 {
    var result = std.testing.allocator.alloc(u5, hrp.len * 2 + 1) catch unreachable;
    for (hrp, 0..) |c, i| {
        result[i] = @intCast(c >> 5);
    }
    result[hrp.len] = 0;
    for (hrp, 0..) |c, i| {
        result[hrp.len + 1 + i] = @intCast(c & 31);
    }
    return result;
}

/// Verify Bech32 checksum.
fn bech32VerifyChecksum(hrp: []const u8, data: []const u5, variant: Variant) bool {
    const values = std.mem.concat(std.testing.allocator, u5, &.{
        bech32HrpExpandList(hrp),
        data,
    }) catch unreachable;
    defer std.testing.allocator.free(values);

    const polymod = bech32Polymod(values);
    return switch (variant) {
        .bech32 => polymod == 1,
        .bech32m => polymod == 0x2BC830A3,
    };
}

/// Convert 8-bit data to 5-bit groups.
pub fn convertBits(data: []const u8, from_bits: u5, to_bits: u5, pad: bool, allocator: std.mem.Allocator) ![]u5 {
    var result = std.ArrayList(u5).init(allocator);
    defer result.deinit();

    var acc: u32 = 0;
    var bits: u5 = 0;
    const max_v: u32 = (1 << to_bits) - 1;

    for (data) |v| {
        if (v >> from_bits != 0) return error.InvalidData;
        acc = (acc << from_bits) | v;
        bits += from_bits;
        while (bits >= to_bits) {
            bits -= to_bits;
            try result.append(@intCast((acc >> bits) & max_v));
        }
    }

    if (pad) {
        if (bits > 0) {
            try result.append(@intCast((acc << (to_bits - bits)) & max_v));
        }
    } else if (bits >= from_bits) {
        return error.InvalidPadding;
    } else if ((acc << (to_bits - bits)) & max_v != 0) {
        return error.NonZeroPadding;
    }

    return result.toOwnedSlice();
}

/// Encode a Bech32/Bech32m string.
pub fn encode(allocator: std.mem.Allocator, hrp: []const u8, data: []const u5, variant: Variant) ![]u8 {
    const checksum = bech32ChecksumCreate(hrp, data, variant);
    var combined = std.ArrayList(u5).init(allocator);
    defer combined.deinit();
    try combined.appendSlice(data);
    try combined.appendSlice(&checksum);

    var result = std.ArrayList(u8).init(allocator);
    try result.appendSlice(hrp);
    try result.append('1');
    for (combined.items) |d| {
        try result.append(CHARSET[d]);
    }

    return result.toOwnedSlice();
}

/// Decode a Bech32/Bech32m string.
pub fn decode(allocator: std.mem.Allocator, str: []const u8) !struct { hrp: []u8, data: []u5, variant: Variant } {
    // Find separator
    var sep_pos: ?usize = null;
    for (str, 0..) |c, i| {
        if (c == '1') {
            sep_pos = i;
        }
    }
    const pos = sep_pos orelse return error.InvalidSeparator;

    const hrp = str[0..pos];
    const data_part = str[pos + 1 ..];

    // Decode data
    var data5 = try allocator.alloc(u5, data_part.len);
    errdefer allocator.free(data5);

    for (data_part, 0..) |c, i| {
        const idx = std.mem.indexOfScalar(u8, CHARSET, c) orelse return error.InvalidChar;
        data5[i] = @intCast(idx);
    }

    // Try both variants
    if (bech32VerifyChecksum(hrp, data5, .bech32)) {
        // Strip checksum (last 6 values)
        const data = try allocator.dupe(u5, data5[0 .. data5.len - 6]);
        allocator.free(data5);
        const hrp_copy = try allocator.dupe(u8, hrp);
        return .{ .hrp = hrp_copy, .data = data, .variant = .bech32 };
    } else if (bech32VerifyChecksum(hrp, data5, .bech32m)) {
        const data = try allocator.dupe(u5, data5[0 .. data5.len - 6]);
        allocator.free(data5);
        const hrp_copy = try allocator.dupe(u8, hrp);
        return .{ .hrp = hrp_copy, .data = data, .variant = .bech32m };
    }

    allocator.free(data5);
    return error.InvalidChecksum;
}

test "Bech32 encode/decode roundtrip" {
    const hrp = "bc";
    const data = [_]u5{ 0, 14, 20, 15, 7, 13, 14, 24, 6, 18, 17, 26, 22, 14, 12, 14, 19, 10, 3, 11, 17, 14 };
    const encoded = try encode(std.testing.allocator, hrp, &data, .bech32);
    defer std.testing.allocator.free(encoded);

    const decoded = try decode(std.testing.allocator, encoded);
    defer std.testing.allocator.free(decoded.hrp);
    defer std.testing.allocator.free(decoded.data);

    try std.testing.expectEqualSlices(u8, hrp, decoded.hrp);
}

test "convertBits 8-to-5" {
    const input = [_]u8{ 0xFF, 0xFF };
    const result = try convertBits(&input, 8, 5, true, std.testing.allocator);
    defer std.testing.allocator.free(result);
    try std.testing.expect(result.len > 0);
}
