//! SM3 cryptographic hash algorithm (GM/T 0004-2012).
//!
//! SM3 is a Chinese national standard hash function producing a 256-bit digest.
//! It is structurally similar to SHA-256 but with different constants,
//! different Boolean functions, and a different message expansion.
//!
//! Reference: GM/T 0004-2012 (SM3 Cryptographic Hash Algorithm)

const std = @import("std");

pub const DIGEST_SIZE = 32; // 256 bits = 32 bytes
pub const BLOCK_SIZE = 64; // 512 bits = 64 bytes
pub const WORD_SIZE = 4; // 32-bit words

/// SM3 initial hash values (IV).
const IV = [8]u32{
    0x7380166F,
    0x4914B2B9,
    0x172442D7,
    0xDA8A0600,
    0xA96F30BC,
    0x163138AA,
    0xE38DEE4D,
    0xB0FB0E4E,
};

/// SM3 constant T_j.
/// T_j = 0x79CC4519 when 0 <= j <= 15
/// T_j = 0x7A879D8A when 16 <= j <= 63
fn tConstant(j: usize) u32 {
    return if (j < 16) 0x79CC4519 else 0x7A879D8A;
}

/// Boolean function FF_j(X, Y, Z).
fn ff(x: u32, y: u32, z: u32, j: usize) u32 {
    return if (j < 16) (x ^ y ^ z) else ((x & y) | (x & z) | (y & z));
}

/// Boolean function GG_j(X, Y, Z).
fn gg(x: u32, y: u32, z: u32, j: usize) u32 {
    return if (j < 16) (x ^ y ^ z) else ((x & y) | ((~x) & z));
}

/// Permutation function P0(X) = X XOR (X <<< 9) XOR (X <<< 17).
fn p0(x: u32) u32 {
    return x ^ rotl32(x, 9) ^ rotl32(x, 17);
}

/// Permutation function P1(X) = X XOR (X <<< 15) XOR (X <<< 23).
fn p1(x: u32) u32 {
    return x ^ rotl32(x, 15) ^ rotl32(x, 23);
}

/// Rotate left (circular left shift) for u32.
/// Handles n=0 edge case properly.
fn rotl32(x: u32, n: u6) u32 {
    if (n == 0) return x;
    return (x << @intCast(n)) | (x >> @intCast(32 - n));
}

/// SM3 hash state.
pub const Sm3 = struct {
    /// Intermediate hash values (8 x 32-bit words).
    v: [8]u32,
    /// Message block buffer (64 bytes).
    block: [64]u8,
    /// Number of bytes in the current block buffer.
    block_len: usize,
    /// Total message length in bytes processed so far.
    total_len: u64,

    /// Initialize SM3 hash state.
    pub fn init() Sm3 {
        return .{
            .v = IV,
            .block = [_]u8{0} ** 64,
            .block_len = 0,
            .total_len = 0,
        };
    }

    /// Update hash state with additional message bytes.
    pub fn update(self: *Sm3, msg: []const u8) void {
        var offset: usize = 0;
        self.total_len += msg.len;

        // Fill remaining block buffer
        if (self.block_len > 0) {
            const remaining = BLOCK_SIZE - self.block_len;
            const to_copy = @min(remaining, msg.len);
            @memcpy(self.block[self.block_len .. self.block_len + to_copy], msg[0..to_copy]);
            self.block_len += to_copy;
            offset += to_copy;

            if (self.block_len == BLOCK_SIZE) {
                self.compress(self.block[0..]);
                self.block_len = 0;
            }
        }

        // Process full blocks directly
        while (offset + BLOCK_SIZE <= msg.len) {
            self.compress(msg[offset .. offset + BLOCK_SIZE]);
            offset += BLOCK_SIZE;
        }

        // Store remaining bytes
        if (offset < msg.len) {
            @memcpy(self.block[0 .. msg.len - offset], msg[offset..]);
            self.block_len = msg.len - offset;
        }
    }

    /// Finalize the hash and return the 256-bit digest.
    pub fn finalize(self: *Sm3) [DIGEST_SIZE]u8 {
        // Save the total length before we modify block
        const total_bits = self.total_len * 8;

        // Append the bit '1' (0x80 byte)
        self.block[self.block_len] = 0x80;
        self.block_len += 1;

        // If we need more than 8 bytes for the length, we need an extra block
        if (self.block_len > BLOCK_SIZE - 8) {
            // Pad current block with zeros
            @memset(self.block[self.block_len..BLOCK_SIZE], 0);
            self.compress(self.block[0..]);
            self.block_len = 0;
        }

        // Pad with zeros until we reach the length position
        @memset(self.block[self.block_len .. BLOCK_SIZE - 8], 0);

        // Append the 64-bit big-endian message length in bits
        std.mem.writeInt(u64, self.block[BLOCK_SIZE - 8 ..][0..8], total_bits, .big);

        self.compress(self.block[0..]);

        // Output hash
        var digest: [DIGEST_SIZE]u8 = undefined;
        for (0..8) |i| {
            std.mem.writeInt(u32, digest[i * 4 ..][0..4], self.v[i], .big);
        }
        return digest;
    }

    /// SM3 compression function.
    /// Processes a single 512-bit (64-byte) message block.
    fn compress(self: *Sm3, block: []const u8) void {
        std.debug.assert(block.len == BLOCK_SIZE);

        // Step 1: Message expansion
        var w: [68]u32 = undefined;
        var w1: [64]u32 = undefined;

        // W_0..W_15: parse block into 16 big-endian 32-bit words
        for (0..16) |i| {
            w[i] = std.mem.readInt(u32, block[i * 4 ..][0..4], .big);
        }

        // W_16..W_67: W_j = P1(W_{j-16} XOR W_{j-9} XOR (W_{j-3} <<< 15)) XOR (W_{j-13} <<< 7) XOR W_{j-6}
        for (16..68) |j| {
            const tmp = w[j - 16] ^ w[j - 9] ^ rotl32(w[j - 3], 15);
            w[j] = p1(tmp) ^ rotl32(w[j - 13], 7) ^ w[j - 6];
        }

        // W'_j = W_j XOR W_{j+4} for j = 0..63
        for (0..64) |j| {
            w1[j] = w[j] ^ w[j + 4];
        }

        // Step 2: Compression function
        var a = self.v[0];
        var b = self.v[1];
        var c = self.v[2];
        var d = self.v[3];
        var e = self.v[4];
        var f = self.v[5];
        var g = self.v[6];
        var h = self.v[7];

        // Rounds 0-15: use FF0, GG0, T_j = 0x79CC4519
        var j: usize = 0;
        while (j < 64) : (j += 1) {
            const ss1 = rotl32(rotl32(a, 12) +% e +% rotl32(tConstant(j), @intCast(j & 31)), 7);
            const ss2 = ss1 ^ rotl32(a, 12);

            const tt1 = ff(a, b, c, j) +% d +% ss2 +% w1[j];
            const tt2 = gg(e, f, g, j) +% h +% ss1 +% w[j];

            d = c;
            c = rotl32(b, 9);
            b = a;
            a = tt1;
            h = g;
            g = rotl32(f, 19);
            f = e;
            e = p0(tt2);
        }

        // Step 3: Update hash values (XOR with compression output)
        self.v[0] ^= a;
        self.v[1] ^= b;
        self.v[2] ^= c;
        self.v[3] ^= d;
        self.v[4] ^= e;
        self.v[5] ^= f;
        self.v[6] ^= g;
        self.v[7] ^= h;
    }
};

/// Convenience function: compute SM3 hash of a byte slice.
pub fn hash(msg: []const u8) [DIGEST_SIZE]u8 {
    var ctx = Sm3.init();
    ctx.update(msg);
    return ctx.finalize();
}

// GM/T 0004-2012 / OpenSSL verified test vectors
const expected_digest_empty = [32]u8{
    0x1a, 0xb2, 0x1d, 0x83, 0x55, 0xcf, 0xa1, 0x7f,
    0x8e, 0x61, 0x19, 0x48, 0x31, 0xe8, 0x1a, 0x8f,
    0x22, 0xbe, 0xc8, 0xc7, 0x28, 0xfe, 0xfb, 0x74,
    0x7e, 0xd0, 0x35, 0xeb, 0x50, 0x82, 0xaa, 0x2b,
};

test "SM3 empty string" {
    const digest = hash("");
    try std.testing.expectEqualSlices(u8, &expected_digest_empty, &digest);
}

test "SM3 'abc'" {
    // Verified with OpenSSL: echo -n "abc" | openssl sm3
    const expected = [32]u8{
        0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9,
        0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10, 0xe4, 0xe2,
        0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2,
        0x29, 0x7d, 0xa0, 0x2b, 0x8f, 0x4b, 0xa8, 0xe0,
    };
    const digest = hash("abc");
    try std.testing.expectEqualSlices(u8, &expected, &digest);
}

test "SM3 longer message" {
    // Verified with OpenSSL: echo -n "abcdefghijklmnopqrstuvwxyz" | openssl sm3
    const expected = [32]u8{
        0xb8, 0x0f, 0xe9, 0x7a, 0x4d, 0xa2, 0x4a, 0xfc,
        0x27, 0x75, 0x64, 0xf6, 0x6a, 0x35, 0x9e, 0xf4,
        0x40, 0x46, 0x2a, 0xd2, 0x8d, 0xcc, 0x6d, 0x63,
        0xad, 0xb2, 0x4d, 0x5c, 0x20, 0xa6, 0x15, 0x95,
    };
    const digest = hash("abcdefghijklmnopqrstuvwxyz");
    try std.testing.expectEqualSlices(u8, &expected, &digest);
}

test "SM3 streaming update" {
    // Test that streaming update produces same result as single-shot
    const msg = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    var ctx = Sm3.init();
    ctx.update(msg);
    const digest1 = ctx.finalize();

    var ctx2 = Sm3.init();
    ctx2.update(msg[0..26]);
    ctx2.update(msg[26..52]);
    ctx2.update(msg[52..]);
    const digest2 = ctx2.finalize();

    try std.testing.expectEqualSlices(u8, &digest1, &digest2);
}
