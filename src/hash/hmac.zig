//! HMAC (Hash-based Message Authentication Code) construction.
//!
//! Generic HMAC that can work with any hash function following the
//! SM3/SHA-256 interface (init/update/finalize pattern).

const std = @import("std");
const sm3_mod = @import("sm3");

pub const Sm3Hmac = Hmac(sm3_mod.Sm3);

/// Generic HMAC implementation parameterized by the hash function.
/// The hash function type must have: init(), update(), finalize() methods.
pub fn Hmac(comptime Hash: type) type {
    return struct {
        const Self = @This();
        const block_size = switch (@TypeOf(Hash.init)) {
            // Infer block size from hash type
            else => 64, // Default 64 bytes (512 bits) for SM3/SHA-256
        };

        inner: Hash,
        outer: Hash,

        /// Initialize HMAC with the given key.
        pub fn init(key: []const u8) Self {
            // If key > block_size, hash it first
            var key_block: [block_size]u8 = [_]u8{0} ** block_size;

            if (key.len > block_size) {
                var h = Hash.init();
                h.update(key);
                const digest = h.finalize();
                @memcpy(key_block[0..digest.len], &digest);
            } else {
                @memcpy(key_block[0..key.len], key);
            }

            // Inner pad: key XOR ipad (0x36)
            var inner_pad: [block_size]u8 = undefined;
            for (0..block_size) |i| {
                inner_pad[i] = key_block[i] ^ 0x36;
            }

            // Outer pad: key XOR opad (0x5C)
            var outer_pad: [block_size]u8 = undefined;
            for (0..block_size) |i| {
                outer_pad[i] = key_block[i] ^ 0x5C;
            }

            var inner = Hash.init();
            inner.update(&inner_pad);

            var outer = Hash.init();
            outer.update(&outer_pad);

            return .{ .inner = inner, .outer = outer };
        }

        /// Update HMAC with message data.
        pub fn update(self: *Self, msg: []const u8) void {
            self.inner.update(msg);
        }

        /// Finalize HMAC and return the authentication tag.
        pub fn finalize(self: *Self) [Hash.DIGEST_SIZE]u8 {
            const inner_hash = self.inner.finalize();
            self.outer.update(&inner_hash);
            return self.outer.finalize();
        }
    };
}

/// Convenience: compute HMAC-SM3 in one shot.
pub fn hmacSm3(key: []const u8, msg: []const u8) [sm3_mod.DIGEST_SIZE]u8 {
    var ctx = Sm3Hmac.init(key);
    ctx.update(msg);
    return ctx.finalize();
}

test "HMAC-SM3 basic" {
    // HMAC-SM3 with a simple key and message
    const key = "123456";
    const msg = "hello world";
    var ctx = Sm3Hmac.init(key);
    ctx.update(msg);
    const result = ctx.finalize();

    // Verify that different keys produce different results
    var ctx2 = Sm3Hmac.init("different_key");
    ctx2.update(msg);
    const result2 = ctx2.finalize();

    var equal = true;
    for (result, result2) |a, b| {
        if (a != b) {
            equal = false;
            break;
        }
    }
    try std.testing.expect(!equal);
}

test "HMAC-SM3 streaming consistency" {
    const key = "test_key";
    const msg = "Hello, SM3 HMAC streaming test!";

    // Single shot
    const result1 = hmacSm3(key, msg);

    // Streaming
    var ctx = Sm3Hmac.init(key);
    ctx.update(msg[0..7]);
    ctx.update(msg[7..]);
    const result2 = ctx.finalize();

    try std.testing.expectEqualSlices(u8, &result1, &result2);
}
