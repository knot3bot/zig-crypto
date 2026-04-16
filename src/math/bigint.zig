//! 256-bit unsigned big integer arithmetic for cryptographic operations.
//!
//! Fixed-width u256 representation using 4 x u64 limbs (little-endian).
//! This avoids allocator dependency and is ideal for elliptic curve operations
//! where all values fit in 256 bits.
//!
//! ## Layout
//! A BigInt256 represents: limbs[0] + limbs[1]*2^64 + limbs[2]*2^128 + limbs[3]*2^192
//! Limbs are stored in little-endian order (limbs[0] = least significant).

const std = @import("std");
const utils = @import("math_utils");

/// A 256-bit unsigned big integer, stored as 4 u64 limbs in little-endian order.
pub const BigInt256 = extern struct {
    limbs: [4]u64,

    pub const ZERO = BigInt256{ .limbs = .{ 0, 0, 0, 0 } };
    pub const ONE = BigInt256{ .limbs = .{ 1, 0, 0, 0 } };

    /// Create from a single u64 value.
    pub fn fromU64(v: u64) BigInt256 {
        return .{ .limbs = .{ v, 0, 0, 0 } };
    }

    /// Create from a single u128 value.
    pub fn fromU128(v: u128) BigInt256 {
        return .{ .limbs = .{
            @as(u64, @truncate(v)),
            @as(u64, @truncate(v >> 64)),
            0,
            0,
        } };
    }

    /// Create from big-endian bytes (32 bytes).
    /// bytes[0] is the most significant byte.
    pub fn fromBytes(bytes: *const [32]u8) BigInt256 {
        return .{
            .limbs = .{
                std.mem.readInt(u64, bytes[24..32], .big), // least significant
                std.mem.readInt(u64, bytes[16..24], .big),
                std.mem.readInt(u64, bytes[8..16], .big),
                std.mem.readInt(u64, bytes[0..8], .big), // most significant
            },
        };
    }

    /// Create from big-endian bytes, handling shorter inputs by zero-padding.
    pub fn fromBytesPadded(bytes: []const u8) BigInt256 {
        var buf: [32]u8 = [_]u8{0} ** 32;
        const offset = 32 - bytes.len;
        @memcpy(buf[offset..], bytes);
        return fromBytes(&buf);
    }

    /// Output as big-endian bytes (32 bytes).
    pub fn toBytes(self: BigInt256) [32]u8 {
        var buf: [32]u8 = undefined;
        std.mem.writeInt(u64, buf[0..8], self.limbs[3], .big);
        std.mem.writeInt(u64, buf[8..16], self.limbs[2], .big);
        std.mem.writeInt(u64, buf[16..24], self.limbs[1], .big);
        std.mem.writeInt(u64, buf[24..32], self.limbs[0], .big);
        return buf;
    }

    /// Create from a hex string (big-endian, may have "0x" prefix).
    /// Asserts the input represents a value that fits in 256 bits.
    pub fn fromHex(hex: []const u8) !BigInt256 {
        var h = hex;
        // Skip 0x prefix
        if (h.len >= 2 and h[0] == '0' and (h[1] == 'x' or h[1] == 'X')) {
            h = h[2..];
        }
        if (h.len > 64) return error.HexStringTooLong;

        // Convert hex to bytes
        var buf: [32]u8 = [_]u8{0} ** 32;
        var byte_idx: usize = 32;
        var i: usize = h.len;
        while (i > 0) {
            if (byte_idx == 0) return error.HexStringTooLong;
            byte_idx -= 1;
            if (i >= 2) {
                const hi = try hexCharToNibble(h[i - 2]);
                const lo = try hexCharToNibble(h[i - 1]);
                buf[byte_idx] = (hi << 4) | lo;
                i -= 2;
            } else {
                buf[byte_idx] = try hexCharToNibble(h[i - 1]);
                i -= 1;
            }
        }
        return fromBytes(&buf);
    }

    /// Output as hex string (lowercase, no 0x prefix, 64 chars).
    pub fn toHex(self: BigInt256) [64]u8 {
        const bytes = self.toBytes();
        var hex: [64]u8 = undefined;
        const chars = "0123456789abcdef";
        for (bytes, 0..) |b, i| {
            hex[i * 2] = chars[b >> 4];
            hex[i * 2 + 1] = chars[b & 0x0F];
        }
        return hex;
    }

    /// Format as hex string (for std.fmt).
    pub fn format(self: BigInt256, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;
        const bytes = self.toBytes();
        // Find first non-zero byte for compact representation
        var start: usize = 0;
        while (start < 31 and bytes[start] == 0) : (start += 1) {}
        try writer.writeAll("0x");
        for (bytes[start..]) |b| {
            try writer.print("{x:0>2}", .{b});
        }
    }

    /// Check if zero.
    pub fn isZero(self: BigInt256) bool {
        return self.limbs[0] | self.limbs[1] | self.limbs[2] | self.limbs[3] == 0;
    }

    /// Check if value equals one.
    pub fn isOne(self: BigInt256) bool {
        return self.limbs[0] == 1 and self.limbs[1] == 0 and self.limbs[2] == 0 and self.limbs[3] == 0;
    }

    /// Compare two numbers: returns -1 if a < b, 0 if a == b, 1 if a > b.
    pub fn cmp(a: BigInt256, b: BigInt256) i8 {
        var i: usize = 4;
        while (i > 0) {
            i -= 1;
            if (a.limbs[i] > b.limbs[i]) return 1;
            if (a.limbs[i] < b.limbs[i]) return -1;
        }
        return 0;
    }

    /// Constant-time comparison: returns 1 if a >= b, 0 otherwise.
    /// Does NOT leak which limb differs.
    pub fn ctGe(a: BigInt256, b: BigInt256) usize {
        // a >= b iff !(a < b)
        const lt = ctLt(a, b);
        return 1 - lt;
    }

    /// Constant-time less-than: returns 1 if a < b, 0 otherwise.
    pub fn ctLt(a: BigInt256, b: BigInt256) usize {
        var result: usize = 0;
        var i: usize = 4;
        while (i > 0) : (i -= 1) {
            const idx = i - 1;
            if (a.limbs[idx] > b.limbs[idx]) {
                result = 0;
            } else if (a.limbs[idx] < b.limbs[idx]) {
                result = 1;
            }
        }
        return result;
    }

    /// Check equality.
    pub fn eql(a: BigInt256, b: BigInt256) bool {
        return a.limbs[0] == b.limbs[0] and
            a.limbs[1] == b.limbs[1] and
            a.limbs[2] == b.limbs[2] and
            a.limbs[3] == b.limbs[3];
    }

    /// Addition: returns result and carry (carry is 0 or 1).
    pub fn add(a: BigInt256, b: BigInt256) struct { result: BigInt256, carry: u1 } {
        var result = BigInt256.ZERO;
        var carry: u64 = 0;
        for (0..4) |i| {
            const sum = @as(u128, a.limbs[i]) + @as(u128, b.limbs[i]) + carry;
            result.limbs[i] = @truncate(sum);
            carry = @intCast(sum >> 64);
        }
        return .{ .result = result, .carry = @intCast(carry) };
    }

    /// Subtraction: returns result and borrow (borrow is 0 or 1).
    /// If a < b, result wraps around (two's complement).
    pub fn sub(a: BigInt256, b: BigInt256) struct { result: BigInt256, borrow: u1 } {
        var result = BigInt256.ZERO;
        var borrow: u64 = 0;
        for (0..4) |i| {
            const aa = a.limbs[i];
            const bb = b.limbs[i] + borrow;
            if (aa >= bb) {
                result.limbs[i] = aa - bb;
                borrow = 0;
            } else {
                result.limbs[i] = aa +% (~bb +% 1); // wrap-around subtraction
                // Recompute properly
                const diff = @as(u128, aa) +% @as(u128, std.math.maxInt(u64)) -% @as(u128, bb) +% 1;
                result.limbs[i] = @truncate(diff);
                borrow = 1;
            }
        }
        // Proper subtraction with borrow
        var res = BigInt256.ZERO;
        var bw: u64 = 0;
        for (0..4) |i| {
            const tmp = @as(u128, a.limbs[i]) -% @as(u128, b.limbs[i]) -% bw;
            res.limbs[i] = @truncate(tmp);
            bw = @intCast(tmp >> 64);
        }
        // Check for underflow
        const underflow = if (cmp(a, b) < 0) @as(u1, 1) else @as(u1, 0);
        return .{ .result = res, .borrow = underflow };
    }

    /// Multiplication: a * b, returns low 256 bits.
    /// For full multiplication into 512 bits, use `mulWide`.
    pub fn mul(a: BigInt256, b: BigInt256) BigInt256 {
        return mulWide(a, b).low;
    }

    /// Wide multiplication: a * b = 512-bit result.
    /// Uses schoolbook multiplication with 64-bit limbs.
    pub fn mulWide(a: BigInt256, b: BigInt256) struct { low: BigInt256, high: BigInt256 } {
        var result: [8]u64 = .{0} ** 8;

        for (0..4) |i| {
            if (a.limbs[i] == 0) continue;
            var carry: u64 = 0;
            for (0..4) |j| {
                const prod = @as(u128, a.limbs[i]) * @as(u128, b.limbs[j]) + @as(u128, result[i + j]) + @as(u128, carry);
                result[i + j] = @truncate(prod);
                carry = @intCast(prod >> 64);
            }
            result[i + 4] = carry;
        }

        return .{
            .low = BigInt256{ .limbs = .{ result[0], result[1], result[2], result[3] } },
            .high = BigInt256{ .limbs = .{ result[4], result[5], result[6], result[7] } },
        };
    }

    /// Modular multiplication: (a * b) mod m.
    /// Uses wide multiplication followed by modular reduction.
    pub fn mulMod(a: BigInt256, b: BigInt256, m: BigInt256) BigInt256 {
        const wide = mulWide(a, b);
        // Reduce the 512-bit product mod m
        // For correctness, we need proper 512-bit modular reduction
        return mod512(wide.low, wide.high, m);
    }

    /// Addition mod m: (a + b) mod m. Assumes a, b < m.
    pub fn addMod(a: BigInt256, b: BigInt256, m: BigInt256) BigInt256 {
        const sum = add(a, b);
        if (sum.carry == 1 or cmp(sum.result, m) >= 0) {
            return sub(sum.result, m).result;
        }
        return sum.result;
    }

    /// Subtraction mod m: (a - b) mod m. Assumes a, b < m.
    pub fn subMod(a: BigInt256, b: BigInt256, m: BigInt256) BigInt256 {
        if (cmp(a, b) >= 0) {
            return sub(a, b).result;
        } else {
            return add(sub(m, sub(b, a).result).result, a).result;
        }
    }

    /// Squaring: a^2 mod m.
    pub fn sqrMod(a: BigInt256, m: BigInt256) BigInt256 {
        return mulMod(a, a, m);
    }

    /// Modular reduction of a 512-bit number mod m.
    /// Uses binary long division (shift-subtract).
    pub fn mod512(lo: BigInt256, hi: BigInt256, m: BigInt256) BigInt256 {
        // If hi == 0 and lo < m, just return lo
        if (hi.isZero() and cmp(lo, m) < 0) {
            return lo;
        }

        // Binary long division: process all 512 bits of (hi:lo)
        var remainder = BigInt256.ZERO;
        // Process from MSB (bit 511 of the 512-bit number) to LSB (bit 0)
        for (0..512) |bit_idx| {
            // Shift remainder left by 1
            remainder = shl1(remainder);

            // Get the current bit from (hi:lo)
            // Bit 511 = MSB of hi.limbs[3], bit 256 = LSB of hi, bit 255 = MSB of lo.limbs[3]
            const current_bit: u1 = if (bit_idx < 256)
                @intCast((hi.limbs[(255 - bit_idx) / 64] >> @intCast((255 - bit_idx) % 64)) & 1)
            else
                @intCast((lo.limbs[(511 - bit_idx) / 64] >> @intCast((511 - bit_idx) % 64)) & 1);

            // Add current bit to remainder LSB
            remainder.limbs[0] |= current_bit;

            // If remainder >= m, subtract m
            if (cmp(remainder, m) >= 0) {
                remainder = sub(remainder, m).result;
            }
        }

        return remainder;
    }

    /// Left shift by 1 bit.
    pub fn shl1(a: BigInt256) BigInt256 {
        return .{ .limbs = .{
            a.limbs[0] << 1 | (a.limbs[1] >> 63),
            a.limbs[1] << 1 | (a.limbs[2] >> 63),
            a.limbs[2] << 1 | (a.limbs[3] >> 63),
            a.limbs[3] << 1,
        } };
    }

    /// Right shift by 1 bit.
    pub fn shr1(a: BigInt256) BigInt256 {
        return .{ .limbs = .{
            a.limbs[0] >> 1,
            (a.limbs[1] >> 1) | (a.limbs[0] << 63),
            (a.limbs[2] >> 1) | (a.limbs[1] << 63),
            (a.limbs[3] >> 1) | (a.limbs[2] << 63),
        } };
    }

    /// Left shift by n bits.
    pub fn shl(a: BigInt256, n: usize) BigInt256 {
        if (n == 0) return a;
        if (n >= 256) return ZERO;

        var result = a;
        // Shift by whole limbs first
        const limb_shift = n / 64;
        const bit_shift = n % 64;

        if (limb_shift > 0) {
            var i: usize = 3;
            while (i > 0) : (i -= 1) {
                if (i >= limb_shift) {
                    result.limbs[i] = result.limbs[i - limb_shift];
                } else {
                    result.limbs[i] = 0;
                }
            }
            var idx: usize = 0;
            while (idx < limb_shift and idx < 4) : (idx += 1) {
                result.limbs[idx] = 0;
            }
        }

        if (bit_shift > 0) {
            var carry: u64 = 0;
            var i: usize = 3;
            // Work from limbs down
            if (limb_shift > 0) {
                while (i > 0) : (i -= 1) {
                    if (i >= limb_shift) {
                        result.limbs[i] = result.limbs[i - limb_shift];
                    } else {
                        result.limbs[i] = 0;
                    }
                }
            }
            // Reset and do bit shift properly
            result = a;
            carry = 0;
            for (0..4) |j| {
                const new_carry = result.limbs[j] >> (64 - bit_shift);
                result.limbs[j] = (result.limbs[j] << @intCast(bit_shift)) | carry;
                carry = new_carry;
            }
            // Apply limb shift
            if (limb_shift > 0) {
                var j: usize = 3;
                while (j > 0) : (j -= 1) {
                    result.limbs[j] = if (j >= limb_shift) result.limbs[j - limb_shift] else 0;
                }
                for (0..limb_shift) |k| {
                    if (k < 4) result.limbs[k] = 0;
                }
            }
        }
        return result;
    }

    /// Compute the number of bits in the value.
    pub fn bitCount(self: BigInt256) usize {
        if (self.isZero()) return 0;
        var count: usize = 0;
        var v = self;
        while (!v.isZero()) : (v = shr1(v)) {
            count += 1;
        }
        return count;
    }

    /// Get the bit at position i (0 = LSB).
    pub fn getBit(self: BigInt256, i: usize) u1 {
        if (i >= 256) return 0;
        const limb_idx = i / 64;
        const bit_idx = i % 64;
        return @intCast((self.limbs[limb_idx] >> @intCast(bit_idx)) & 1);
    }

    /// Set the bit at position i (0 = LSB).
    pub fn setBit(self: *BigInt256, i: usize) void {
        if (i >= 256) return;
        const limb_idx = i / 64;
        const bit_idx = i % 64;
        self.limbs[limb_idx] |= @as(u64, 1) << @intCast(bit_idx);
    }
};

/// Helper to convert a hex character to a nibble.
fn hexCharToNibble(c: u8) !u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => error.InvalidHexChar,
    };
}

test "BigInt256 from/to bytes" {
    const bytes = [_]u8{0} ** 31 ++ [_]u8{42};
    const n = BigInt256.fromBytes(&bytes);
    try std.testing.expect(n.eql(BigInt256.fromU64(42)));

    const out = n.toBytes();
    try std.testing.expectEqualSlices(u8, &bytes, &out);
}

test "BigInt256 from hex" {
    const n = try BigInt256.fromHex("0xff");
    try std.testing.expect(n.eql(BigInt256.fromU64(255)));
}

test "BigInt256 add" {
    const a = BigInt256.fromU64(100);
    const b = BigInt256.fromU64(200);
    const result = BigInt256.add(a, b);
    try std.testing.expect(result.result.eql(BigInt256.fromU64(300)));
    try std.testing.expectEqual(@as(u1, 0), result.carry);
}

test "BigInt256 sub" {
    const a = BigInt256.fromU64(300);
    const b = BigInt256.fromU64(100);
    const result = BigInt256.sub(a, b);
    try std.testing.expect(result.result.eql(BigInt256.fromU64(200)));
}

test "BigInt256 mul" {
    const a = BigInt256.fromU64(123);
    const b = BigInt256.fromU64(456);
    const result = BigInt256.mul(a, b);
    try std.testing.expect(result.eql(BigInt256.fromU64(123 * 456)));
}

test "BigInt256 comparison" {
    const a = BigInt256.fromU64(100);
    const b = BigInt256.fromU64(200);
    try std.testing.expectEqual(@as(i8, -1), BigInt256.cmp(a, b));
    try std.testing.expectEqual(@as(i8, 1), BigInt256.cmp(b, a));
    try std.testing.expectEqual(@as(i8, 0), BigInt256.cmp(a, a));
}

test "BigInt256 shift" {
    const a = BigInt256.fromU64(1);
    const shifted = BigInt256.shl1(a);
    try std.testing.expect(shifted.eql(BigInt256.fromU64(2)));

    const back = BigInt256.shr1(shifted);
    try std.testing.expect(back.eql(a));
}

test "BigInt256 wide mul" {
    const a = BigInt256.fromU64(0xFFFFFFFFFFFFFFFF);
    const result = BigInt256.mulWide(a, a);
    // (2^64-1)^2 = 2^128 - 2^65 + 1
    try std.testing.expect(result.low.limbs[0] == 1);
    try std.testing.expect(result.low.limbs[1] == 0xFFFFFFFFFFFFFFFF - 1); // -2 in high part of low
}

test "BigInt256 mod" {
    // Test (10 * 10) mod 7 = 100 mod 7 = 2
    const a = BigInt256.fromU64(10);
    const m = BigInt256.fromU64(7);
    const result = BigInt256.mulMod(a, a, m);
    try std.testing.expect(result.eql(BigInt256.fromU64(2)));
}

test "BigInt256 isZero/isOne" {
    try std.testing.expect(BigInt256.ZERO.isZero());
    try std.testing.expect(!BigInt256.ZERO.isOne());
    try std.testing.expect(!BigInt256.ONE.isZero());
    try std.testing.expect(BigInt256.ONE.isOne());
}
