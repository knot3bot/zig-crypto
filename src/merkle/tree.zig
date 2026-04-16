//! Merkle tree implementation using SM3 hash.
//!
//! Provides a binary Merkle tree for blockchain transaction verification.

const std = @import("std");
const sm3_mod = @import("sm3");

/// Merkle tree node.
pub const MerkleNode = struct {
    hash: [sm3_mod.DIGEST_SIZE]u8,
    left: ?*MerkleNode,
    right: ?*MerkleNode,
};

/// Compute the Merkle root hash from a list of leaf hashes.
/// Uses SM3 as the hash function.
pub fn merkleRoot(allocator: std.mem.Allocator, leaves: [][sm3_mod.DIGEST_SIZE]u8) ![sm3_mod.DIGEST_SIZE]u8 {
    if (leaves.len == 0) {
        return sm3_mod.hash("");
    }

    if (leaves.len == 1) {
        return leaves[0];
    }

    var current = std.ArrayList([sm3_mod.DIGEST_SIZE]u8).initCapacity(allocator, (leaves.len + 1) / 2) catch unreachable;
    defer current.deinit();

    // Hash pairs of leaves
    var i: usize = 0;
    while (i < leaves.len) : (i += 2) {
        if (i + 1 < leaves.len) {
            var combined: [2 * sm3_mod.DIGEST_SIZE]u8 = undefined;
            @memcpy(combined[0..sm3_mod.DIGEST_SIZE], &leaves[i]);
            @memcpy(combined[sm3_mod.DIGEST_SIZE..], &leaves[i + 1]);
            current.append(sm3_mod.hash(&combined)) catch unreachable;
        } else {
            // Odd number: duplicate the last leaf
            var combined: [2 * sm3_mod.DIGEST_SIZE]u8 = undefined;
            @memcpy(combined[0..sm3_mod.DIGEST_SIZE], &leaves[i]);
            @memcpy(combined[sm3_mod.DIGEST_SIZE..], &leaves[i]);
            current.append(sm3_mod.hash(&combined)) catch unreachable;
        }
    }

    if (current.items.len == 1) {
        return current.items[0];
    }

    // Recurse
    return merkleRoot(allocator, current.items);
}

/// Compute Merkle root from raw data items (hashes each item first).
pub fn merkleRootFromData(allocator: std.mem.Allocator, data_items: []const []const u8) ![sm3_mod.DIGEST_SIZE]u8 {
    var leaves = std.ArrayList([sm3_mod.DIGEST_SIZE]u8).initCapacity(allocator, data_items.len) catch unreachable;
    defer leaves.deinit();

    for (data_items) |item| {
        leaves.append(sm3_mod.hash(item)) catch unreachable;
    }

    return merkleRoot(allocator, leaves.items);
}

test "Merkle root single leaf" {
    const leaf = sm3_mod.hash("hello");
    const root = try merkleRoot(std.testing.allocator, &[_][sm3_mod.DIGEST_SIZE]u8{leaf});
    try std.testing.expectEqualSlices(u8, &leaf, &root);
}

test "Merkle root two leaves" {
    const leaf1 = sm3_mod.hash("hello");
    const leaf2 = sm3_mod.hash("world");
    var combined: [64]u8 = undefined;
    @memcpy(combined[0..32], &leaf1);
    @memcpy(combined[32..64], &leaf2);
    const expected = sm3_mod.hash(&combined);

    const root = try merkleRoot(std.testing.allocator, &[_][sm3_mod.DIGEST_SIZE]u8{ leaf1, leaf2 });
    try std.testing.expectEqualSlices(u8, &expected, &root);
}
