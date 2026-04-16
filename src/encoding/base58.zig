//! Base58Check encoding/decoding for blockchain addresses.
//!
//! Base58 is a base-58 encoding scheme that avoids ambiguous characters
//! (0, O, I, l) commonly used in Bitcoin and other blockchain addresses.
//! Base58Check uses double-SHA-256 for the checksum.

const std = @import("std");
const sha256 = @import("sha256");

/// Base58 alphabet (Bitcoin style).
const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Base58 decode lookup table.
fn decodeLookup(c: u8) !u8 {
    return switch (c) {
        '1'...'9' => c - '1',
        'A'...'H' => c - 'A' + 9,
        'J'...'N' => c - 'J' + 17,
        'P'...'Z' => c - 'P' + 22,
        'a'...'k' => c - 'a' + 33,
        'm'...'z' => c - 'm' + 44,
        else => error.InvalidBase58Char,
    };
}

/// Encode bytes to Base58 string.
pub fn encode(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    if (input.len == 0) return allocator.alloc(u8, 0);

    // Count leading zeros
    var leading_zeros: usize = 0;
    for (input) |b| {
        if (b == 0) leading_zeros += 1 else break;
    }

    // Convert to big integer and then to base58
    // Simple implementation: use repeated division
    var result = std.ArrayList(u8).init(allocator);
    defer result.deinit();

    // Work with a copy of the input
    const bytes = try allocator.alloc(u8, input.len);
    defer allocator.free(bytes);
    @memcpy(bytes, input);

    while (true) {
        // Check if bytes is all zeros
        var all_zero = true;
        for (bytes) |b| {
            if (b != 0) {
                all_zero = false;
                break;
            }
        }
        if (all_zero) break;

        // Divide bytes by 58
        var remainder: u64 = 0;
        for (bytes) |*b| {
            const value = remainder * 256 + @as(u64, b.*);
            b.* = @intCast(value / 58);
            remainder = value % 58;
        }
        try result.append(ALPHABET[remainder]);
    }

    // Add leading '1's for leading zero bytes
    for (0..leading_zeros) |_| {
        try result.append('1');
    }

    // Reverse result
    var i: usize = 0;
    var j = result.items.len - 1;
    while (i < j) {
        const tmp = result.items[i];
        result.items[i] = result.items[j];
        result.items[j] = tmp;
        i += 1;
        j -= 1;
    }

    return allocator.dupe(u8, result.items);
}

/// Decode a Base58 string to bytes.
pub fn decode(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    if (input.len == 0) return allocator.alloc(u8, 0);

    // Count leading '1's (they represent leading zero bytes)
    var leading_ones: usize = 0;
    for (input) |c| {
        if (c == '1') leading_ones += 1 else break;
    }

    // Convert from base58 to big integer
    var bytes = std.ArrayList(u8).init(allocator);
    defer bytes.deinit();
    try bytes.append(0);

    for (input) |c| {
        // Multiply by 58
        var carry: u64 = try decodeLookup(c);
        for (bytes.items) |*b| {
            const value = @as(u64, b.*) * 58 + carry;
            b.* = @intCast(value % 256);
            carry = value / 256;
        }
        while (carry > 0) {
            try bytes.append(@intCast(carry % 256));
            carry /= 256;
        }
    }

    // Reverse bytes and add leading zeros
    var result = try allocator.alloc(u8, leading_ones + bytes.items.len);
    @memset(result[0..leading_ones], 0);

    // Reverse bytes
    var j = leading_ones;
    var k: usize = bytes.items.len;
    while (k > 0) : (k -= 1) {
        result[j] = bytes.items[k - 1];
        j += 1;
    }

    return result[0 .. leading_ones + bytes.items.len];
}

/// Encode bytes to Base58Check format (version byte + payload + 4-byte checksum).
/// Uses double-SHA-256 for the checksum (same as Bitcoin).
pub fn encodeCheck(allocator: std.mem.Allocator, version: u8, payload: []const u8) ![]u8 {
    // Prepend version byte
    var full_payload = try allocator.alloc(u8, 1 + payload.len);
    defer allocator.free(full_payload);
    full_payload[0] = version;
    @memcpy(full_payload[1..], payload);

    // Compute double-SHA-256 checksum (using first 4 bytes)
    const hash1 = sha256.hash(full_payload);
    const hash2 = sha256.hash(&hash1);
    const checksum = hash2[0..4];

    // Append checksum
    var with_checksum = try allocator.alloc(u8, full_payload.len + 4);
    @memcpy(with_checksum[0..full_payload.len], full_payload);
    @memcpy(with_checksum[full_payload.len..], checksum);

    return encode(allocator, with_checksum);
}

test "Base58 encode/decode roundtrip" {
    const data = "Hello, World!";
    const encoded = try encode(std.testing.allocator, data);
    defer std.testing.allocator.free(encoded);
    const decoded = try decode(std.testing.allocator, encoded);
    defer std.testing.allocator.free(decoded);
    try std.testing.expectEqualSlices(u8, data, decoded);
}

test "Base58 leading zeros" {
    var data = [_]u8{ 0, 0, 0, 5 }; // Leading zeros
    const encoded = try encode(std.testing.allocator, &data);
    defer std.testing.allocator.free(encoded);
    // Should start with '1's for leading zero bytes
    try std.testing.expect(encoded[0] == '1');
    try std.testing.expect(encoded[1] == '1');
    try std.testing.expect(encoded[2] == '1');
}
