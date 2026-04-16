//! SHA-256 cryptographic hash algorithm (FIPS 180-4).
//!
//! Included for blockchain compatibility alongside SM3.

const std = @import("std");

pub const DIGEST_SIZE = 32;
pub const BLOCK_SIZE = 64;

/// SHA-256 initial hash values.
const IV = [8]u32{
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
};

/// SHA-256 round constants (first 32 bits of the fractional parts of the cube roots of the first 64 primes).
const K = [64]u32{
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
};

fn shr(x: u32, n: u5) u32 {
    return x >> n;
}

fn rotl(x: u32, n: u5) u32 {
    if (n == 0) return x;
    return (x << n) | (x >> @intCast(32 - @as(u6, n)));
}

fn ch(x: u32, y: u32, z: u32) u32 {
    return (x & y) ^ (~x & z);
}

fn maj(x: u32, y: u32, z: u32) u32 {
    return (x & y) ^ (x & z) ^ (y & z);
}

fn sigma0(x: u32) u32 {
    return rotl(x, 2) ^ rotl(x, 13) ^ rotl(x, 22);
}

fn sigma1(x: u32) u32 {
    return rotl(x, 6) ^ rotl(x, 11) ^ rotl(x, 25);
}

fn gamma0(x: u32) u32 {
    return rotl(x, 7) ^ rotl(x, 18) ^ shr(x, 3);
}

fn gamma1(x: u32) u32 {
    return rotl(x, 17) ^ rotl(x, 19) ^ shr(x, 10);
}

/// SHA-256 hash state.
pub const Sha256 = struct {
    v: [8]u32,
    block: [64]u8,
    block_len: usize,
    total_len: u64,

    pub fn init() Sha256 {
        return .{
            .v = IV,
            .block = [_]u8{0} ** 64,
            .block_len = 0,
            .total_len = 0,
        };
    }

    pub fn update(self: *Sha256, msg: []const u8) void {
        var offset: usize = 0;
        self.total_len += msg.len;

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

        while (offset + BLOCK_SIZE <= msg.len) {
            self.compress(msg[offset .. offset + BLOCK_SIZE]);
            offset += BLOCK_SIZE;
        }

        if (offset < msg.len) {
            @memcpy(self.block[0 .. msg.len - offset], msg[offset..]);
            self.block_len = msg.len - offset;
        }
    }

    pub fn finalize(self: *Sha256) [DIGEST_SIZE]u8 {
        const total_bits = self.total_len * 8;

        self.block[self.block_len] = 0x80;
        self.block_len += 1;

        if (self.block_len > BLOCK_SIZE - 8) {
            @memset(self.block[self.block_len..BLOCK_SIZE], 0);
            self.compress(self.block[0..]);
            self.block_len = 0;
        }

        @memset(self.block[self.block_len .. BLOCK_SIZE - 8], 0);
        std.mem.writeInt(u64, self.block[BLOCK_SIZE - 8 ..][0..8], total_bits, .big);
        self.compress(self.block[0..]);

        var digest: [DIGEST_SIZE]u8 = undefined;
        for (0..8) |i| {
            std.mem.writeInt(u32, digest[i * 4 ..][0..4], self.v[i], .big);
        }
        return digest;
    }

    fn compress(self: *Sha256, block: []const u8) void {
        std.debug.assert(block.len == BLOCK_SIZE);

        var w: [64]u32 = undefined;
        for (0..16) |i| {
            w[i] = std.mem.readInt(u32, block[i * 4 ..][0..4], .big);
        }
        for (16..64) |j| {
            w[j] = gamma1(w[j - 2]) +% w[j - 7] +% gamma0(w[j - 15]) +% w[j - 16];
        }

        var a = self.v[0];
        var b = self.v[1];
        var c = self.v[2];
        var d = self.v[3];
        var e = self.v[4];
        var f = self.v[5];
        var g = self.v[6];
        var h = self.v[7];

        for (0..64) |j| {
            const t1 = h +% sigma1(e) +% ch(e, f, g) +% K[j] +% w[j];
            const t2 = sigma0(a) +% maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d +% t1;
            d = c;
            c = b;
            b = a;
            a = t1 +% t2;
        }

        self.v[0] +%= a;
        self.v[1] +%= b;
        self.v[2] +%= c;
        self.v[3] +%= d;
        self.v[4] +%= e;
        self.v[5] +%= f;
        self.v[6] +%= g;
        self.v[7] +%= h;
    }
};

/// Convenience: compute SHA-256 hash of a byte slice.
pub fn hash(msg: []const u8) [DIGEST_SIZE]u8 {
    var ctx = Sha256.init();
    ctx.update(msg);
    return ctx.finalize();
}

test "SHA-256 empty string" {
    // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    const expected = [32]u8{
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
    };
    const digest = hash("");
    try std.testing.expectEqualSlices(u8, &expected, &digest);
}

test "SHA-256 'abc'" {
    // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    const expected = [32]u8{
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    };
    const digest = hash("abc");
    try std.testing.expectEqualSlices(u8, &expected, &digest);
}
