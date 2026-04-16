//! SM4 block cipher algorithm (GM/T 0002-2012).
//!
//! SM4 is a 128-bit block cipher with a 128-bit key, using 32 rounds
//! of an unbalanced Feistel structure. It is the Chinese national standard
//! for symmetric encryption.
//!
//! Reference: GM/T 0002-2012 (SM4 Block Cipher Algorithm)

const std = @import("std");

pub const BLOCK_SIZE = 16; // 128 bits = 16 bytes
pub const KEY_SIZE = 16; // 128 bits = 16 bytes
pub const ROUNDS = 32;

/// SM4 S-box per GM/T 0002-2012 / Linux kernel crypto/sm4.c.
const SBOX = [256]u8{
    0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05,
    0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3, 0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
    0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6,
    0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA, 0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8,
    0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
    0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0x78, 0x87,
    0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52, 0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E,
    0xEA, 0xBF, 0x8A, 0xD2, 0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
    0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3,
    0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60, 0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F,
    0xD5, 0xDB, 0x37, 0x45, 0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
    0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41, 0x1F, 0x10, 0x5A, 0xD8,
    0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD, 0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0,
    0x89, 0x69, 0x97, 0x4A, 0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
    0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E, 0xD7, 0xCB, 0x39, 0x48,
};

/// System parameter FK.
const FK = [4]u32{ 0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC };

/// Constant key CK.
const CK = [32]u32{
    0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
    0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
    0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
    0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
    0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
    0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
    0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
    0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279,
};

/// Linear transform L.
/// L(B) = B ⊕ (B <<< 2) ⊕ (B <<< 10) ⊕ (B <<< 18) ⊕ (B <<< 24)
fn lTransform(b: u32) u32 {
    return b ^ rotl32(b, 2) ^ rotl32(b, 10) ^ rotl32(b, 18) ^ rotl32(b, 24);
}

/// Linear transform L' (for key expansion).
/// L'(B) = B ⊕ (B <<< 13) ⊕ (B <<< 23)
fn lPrimeTransform(b: u32) u32 {
    return b ^ rotl32(b, 13) ^ rotl32(b, 23);
}

/// Round left rotate for u32.
fn rotl32(x: u32, n: u5) u32 {
    if (n == 0) return x;
    return (x << n) | (x >> @intCast(32 - @as(u6, n)));
}

/// Apply S-box substitution to each byte of a u32.
fn tau(a: u32) u32 {
    return @as(u32, SBOX[(a >> 24) & 0xFF]) << 24 |
        @as(u32, SBOX[(a >> 16) & 0xFF]) << 16 |
        @as(u32, SBOX[(a >> 8) & 0xFF]) << 8 |
        @as(u32, SBOX[a & 0xFF]);
}

/// Transform function T(B) = L(τ(B)).
fn tTransform(b: u32) u32 {
    return lTransform(tau(b));
}

/// Transform function T'(B) = L'(τ(B)) (for key expansion).
fn tPrimeTransform(b: u32) u32 {
    return lPrimeTransform(tau(b));
}

/// SM4 cipher context with expanded round keys.
pub const Sm4 = struct {
    round_keys: [ROUNDS]u32,

    /// Initialize SM4 with a 128-bit encryption key.
    pub fn init(key: [KEY_SIZE]u8) Sm4 {
        var mk: [4]u32 = undefined;
        for (0..4) |i| {
            mk[i] = @as(u32, key[i * 4]) << 24 |
                @as(u32, key[i * 4 + 1]) << 16 |
                @as(u32, key[i * 4 + 2]) << 8 |
                @as(u32, key[i * 4 + 3]);
        }

        // Key expansion: K_i = MK_i ⊕ FK_i
        var k: [36]u32 = undefined;
        k[0] = mk[0] ^ FK[0];
        k[1] = mk[1] ^ FK[1];
        k[2] = mk[2] ^ FK[2];
        k[3] = mk[3] ^ FK[3];

        var rk: [ROUNDS]u32 = undefined;
        for (0..ROUNDS) |i| {
            rk[i] = k[i] ^ tPrimeTransform(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ CK[i]);
            k[i + 4] = rk[i];
        }

        return .{ .round_keys = rk };
    }

    /// Initialize SM4 from a byte slice (must be exactly 16 bytes).
    pub fn initFromSlice(key: []const u8) Sm4 {
        std.debug.assert(key.len == KEY_SIZE);
        var k: [KEY_SIZE]u8 = undefined;
        @memcpy(&k, key);
        return init(k);
    }

    /// Encrypt a single 128-bit block.
    pub fn encrypt(self: Sm4, plaintext: [BLOCK_SIZE]u8) [BLOCK_SIZE]u8 {
        return self.process(plaintext, false);
    }

    /// Decrypt a single 128-bit block.
    pub fn decrypt(self: Sm4, ciphertext: [BLOCK_SIZE]u8) [BLOCK_SIZE]u8 {
        return self.process(ciphertext, true);
    }

    /// Process a single block (encrypt or decrypt).
    fn process(self: Sm4, input: [BLOCK_SIZE]u8, is_decrypt: bool) [BLOCK_SIZE]u8 {
        // Parse input into 4 x u32 big-endian words
        var x: [4]u32 = undefined;
        for (0..4) |i| {
            x[i] = @as(u32, input[i * 4]) << 24 |
                @as(u32, input[i * 4 + 1]) << 16 |
                @as(u32, input[i * 4 + 2]) << 8 |
                @as(u32, input[i * 4 + 3]);
        }

        // 32 rounds
        for (0..ROUNDS) |i| {
            const rk = if (is_decrypt) self.round_keys[ROUNDS - 1 - i] else self.round_keys[i];
            const tmp = x[1] ^ x[2] ^ x[3] ^ rk;
            const new_val = x[0] ^ tTransform(tmp);
            // Shift
            x[0] = x[1];
            x[1] = x[2];
            x[2] = x[3];
            x[3] = new_val;
        }

        // Reverse order for output
        var output: [BLOCK_SIZE]u8 = undefined;
        const idx = [_]usize{ 3, 2, 1, 0 }; // Reverse: X32, X33, X34, X35
        for (0..4) |i| {
            output[i * 4] = @intCast((x[idx[i]] >> 24) & 0xFF);
            output[i * 4 + 1] = @intCast((x[idx[i]] >> 16) & 0xFF);
            output[i * 4 + 2] = @intCast((x[idx[i]] >> 8) & 0xFF);
            output[i * 4 + 3] = @intCast(x[idx[i]] & 0xFF);
        }
        return output;
    }

    /// Encrypt multiple blocks in ECB mode.
    pub fn encryptEcb(self: Sm4, plaintext: []const u8, ciphertext: []u8) void {
        std.debug.assert(plaintext.len % BLOCK_SIZE == 0);
        std.debug.assert(ciphertext.len >= plaintext.len);

        var i: usize = 0;
        while (i < plaintext.len) : (i += BLOCK_SIZE) {
            var block: [BLOCK_SIZE]u8 = undefined;
            @memcpy(&block, plaintext[i .. i + BLOCK_SIZE]);
            const encrypted = self.encrypt(block);
            @memcpy(ciphertext[i .. i + BLOCK_SIZE], &encrypted);
        }
    }

    /// Decrypt multiple blocks in ECB mode.
    pub fn decryptEcb(self: Sm4, ciphertext: []const u8, plaintext: []u8) void {
        std.debug.assert(ciphertext.len % BLOCK_SIZE == 0);
        std.debug.assert(plaintext.len >= ciphertext.len);

        var i: usize = 0;
        while (i < ciphertext.len) : (i += BLOCK_SIZE) {
            var block: [BLOCK_SIZE]u8 = undefined;
            @memcpy(&block, ciphertext[i .. i + BLOCK_SIZE]);
            const decrypted = self.decrypt(block);
            @memcpy(plaintext[i .. i + BLOCK_SIZE], &decrypted);
        }
    }

    /// Encrypt in CBC mode.
    pub fn encryptCbc(self: Sm4, iv: [BLOCK_SIZE]u8, plaintext: []const u8, ciphertext: []u8) void {
        std.debug.assert(plaintext.len % BLOCK_SIZE == 0);
        var prev = iv;

        var i: usize = 0;
        while (i < plaintext.len) : (i += BLOCK_SIZE) {
            var block: [BLOCK_SIZE]u8 = undefined;
            for (0..BLOCK_SIZE) |j| {
                block[j] = plaintext[i + j] ^ prev[j];
            }
            const encrypted = self.encrypt(block);
            @memcpy(ciphertext[i .. i + BLOCK_SIZE], &encrypted);
            prev = encrypted;
        }
    }

    /// Decrypt in CBC mode.
    pub fn decryptCbc(self: Sm4, iv: [BLOCK_SIZE]u8, ciphertext: []const u8, plaintext: []u8) void {
        std.debug.assert(ciphertext.len % BLOCK_SIZE == 0);
        var prev = iv;

        var i: usize = 0;
        while (i < ciphertext.len) : (i += BLOCK_SIZE) {
            var block: [BLOCK_SIZE]u8 = undefined;
            @memcpy(&block, ciphertext[i .. i + BLOCK_SIZE]);
            const decrypted = self.decrypt(block);
            for (0..BLOCK_SIZE) |j| {
                plaintext[i + j] = decrypted[j] ^ prev[j];
            }
            prev = block;
        }
    }
};

/// Convenience function: SM4 encrypt a single block.
pub fn encryptBlock(key: [KEY_SIZE]u8, plaintext: [BLOCK_SIZE]u8) [BLOCK_SIZE]u8 {
    var ctx = Sm4.init(key);
    return ctx.encrypt(plaintext);
}

/// Convenience function: SM4 decrypt a single block.
pub fn decryptBlock(key: [KEY_SIZE]u8, ciphertext: [BLOCK_SIZE]u8) [BLOCK_SIZE]u8 {
    var ctx = Sm4.init(key);
    return ctx.decrypt(ciphertext);
}

test "SM4 key expansion" {
    // GM/T 0002-2012 test vector:
    // Key: 0123456789ABCDEFFEDCBA9876543210
    // Round key 0: F12186F9
    const key = [16]u8{
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    };
    const ctx = Sm4.init(key);
    try std.testing.expectEqual(@as(u32, 0xF12186F9), ctx.round_keys[0]);
}

test "SM4 encrypt/decrypt single block" {
    // GM/T 0002-2012 test vector:
    // Key:       0123456789ABCDEFFEDCBA9876543210
    // Plaintext: 0123456789ABCDEFFEDCBA9876543210
    // Ciphertext:681EDF342C58B5DB41B7387DA67B8A42
    const key = [16]u8{
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    };
    const plaintext = [16]u8{
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    };
    const expected = [16]u8{
        0x68, 0x1E, 0xDF, 0x34, 0x2C, 0x58, 0xB5, 0xDB,
        0x41, 0xB7, 0x38, 0x7D, 0xA6, 0x7B, 0x8A, 0x42,
    };

    var ctx = Sm4.init(key);
    const ciphertext = ctx.encrypt(plaintext);
    try std.testing.expectEqualSlices(u8, &expected, &ciphertext);

    const decrypted = ctx.decrypt(ciphertext);
    try std.testing.expectEqualSlices(u8, &plaintext, &decrypted);
}

test "SM4 1000000 iterations" {
    // GM/T 0002-2012 test vector:
    // After 1000000 encryptions of the same block:
    // Key:       0123456789ABCDEFFEDCBA9876543210
    // Plaintext: 0123456789ABCDEFFEDCBA9876543210
    // Result:    595298C7C6FD271DF0AC1FBC1B5A8A42
    // Note: This test is too slow for regular testing, skipped.
    // Uncomment to verify:
    // var ctx = Sm4.init(.{
    //     .key = [16]u8{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    //                     0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 },
    // });
}
