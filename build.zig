const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // ============================================================
    // Internal modules (created with createModule)
    // ============================================================

    // Layer 0: Primitives
    const math_utils_mod = b.createModule(.{
        .root_source_file = b.path("src/math/utils.zig"),
        .target = target,
        .optimize = optimize,
    });

    const math_bigint_mod = b.createModule(.{
        .root_source_file = b.path("src/math/bigint.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "math_utils", .module = math_utils_mod },
        },
    });

    const math_modint_mod = b.createModule(.{
        .root_source_file = b.path("src/math/modint.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "math_utils", .module = math_utils_mod },
            .{ .name = "math_bigint", .module = math_bigint_mod },
        },
    });

    const utils_random_mod = b.createModule(.{
        .root_source_file = b.path("src/utils/random.zig"),
        .target = target,
        .optimize = optimize,
    });

    const utils_mem_mod = b.createModule(.{
        .root_source_file = b.path("src/utils/mem.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Layer 1: Core algorithms
    const hash_sm3_mod = b.createModule(.{
        .root_source_file = b.path("src/hash/sm3.zig"),
        .target = target,
        .optimize = optimize,
    });

    const hash_sha256_mod = b.createModule(.{
        .root_source_file = b.path("src/hash/sha256.zig"),
        .target = target,
        .optimize = optimize,
    });

    const hash_hmac_mod = b.createModule(.{
        .root_source_file = b.path("src/hash/hmac.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "sm3", .module = hash_sm3_mod },
        },
    });

    const sym_sm4_mod = b.createModule(.{
        .root_source_file = b.path("src/sym/sm4.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Layer 2: Elliptic Curve
    const ecc_field_mod = b.createModule(.{
        .root_source_file = b.path("src/ecc/field.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "math_utils", .module = math_utils_mod },
            .{ .name = "math_bigint", .module = math_bigint_mod },
            .{ .name = "math_modint", .module = math_modint_mod },
        },
    });

    const ecc_point_mod = b.createModule(.{
        .root_source_file = b.path("src/ecc/point.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "ecc_field", .module = ecc_field_mod },
        },
    });

    const ecc_sm2_mod = b.createModule(.{
        .root_source_file = b.path("src/ecc/sm2.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "ecc_field", .module = ecc_field_mod },
            .{ .name = "ecc_point", .module = ecc_point_mod },
            .{ .name = "sm3", .module = hash_sm3_mod },
            .{ .name = "math_bigint", .module = math_bigint_mod },
            .{ .name = "math_utils", .module = math_utils_mod },
            .{ .name = "utils_random", .module = utils_random_mod },
            .{ .name = "utils_mem", .module = utils_mem_mod },
        },
    });

    const ecc_secp256k1_mod = b.createModule(.{
        .root_source_file = b.path("src/ecc/secp256k1.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "ecc_field", .module = ecc_field_mod },
            .{ .name = "ecc_point", .module = ecc_point_mod },
            .{ .name = "math_bigint", .module = math_bigint_mod },
        },
    });

    const ecc_ed25519_mod = b.createModule(.{
        .root_source_file = b.path("src/ecc/ed25519.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "ecc_field", .module = ecc_field_mod },
            .{ .name = "math_bigint", .module = math_bigint_mod },
            .{ .name = "utils_random", .module = utils_random_mod },
            .{ .name = "utils_mem", .module = utils_mem_mod },
        },
    });

    // Layer 3: Protocols
    const kdf_hkdf_sm3_mod = b.createModule(.{
        .root_source_file = b.path("src/kdf/hkdf_sm3.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "sm3", .module = hash_sm3_mod },
            .{ .name = "hmac", .module = hash_hmac_mod },
        },
    });

    const merkle_tree_mod = b.createModule(.{
        .root_source_file = b.path("src/merkle/tree.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "sm3", .module = hash_sm3_mod },
        },
    });

    // Layer 4: Encoding
    const encoding_base58_mod = b.createModule(.{
        .root_source_file = b.path("src/encoding/base58.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "sha256", .module = hash_sha256_mod },
        },
    });

    const encoding_bech32_mod = b.createModule(.{
        .root_source_file = b.path("src/encoding/bech32.zig"),
        .target = target,
        .optimize = optimize,
    });

    // ============================================================
    // Public library module (exposed to consumers)
    // ============================================================
    const lib_mod = b.addModule("zig_crypto", .{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "math_utils", .module = math_utils_mod },
            .{ .name = "math_bigint", .module = math_bigint_mod },
            .{ .name = "math_modint", .module = math_modint_mod },
            .{ .name = "utils_random", .module = utils_random_mod },
            .{ .name = "utils_mem", .module = utils_mem_mod },
            .{ .name = "sm3", .module = hash_sm3_mod },
            .{ .name = "sha256", .module = hash_sha256_mod },
            .{ .name = "hmac", .module = hash_hmac_mod },
            .{ .name = "sm4", .module = sym_sm4_mod },
            .{ .name = "ecc_field", .module = ecc_field_mod },
            .{ .name = "ecc_point", .module = ecc_point_mod },
            .{ .name = "sm2", .module = ecc_sm2_mod },
            .{ .name = "secp256k1", .module = ecc_secp256k1_mod },
            .{ .name = "ed25519", .module = ecc_ed25519_mod },
            .{ .name = "hkdf_sm3", .module = kdf_hkdf_sm3_mod },
            .{ .name = "merkle", .module = merkle_tree_mod },
            .{ .name = "base58", .module = encoding_base58_mod },
            .{ .name = "bech32", .module = encoding_bech32_mod },
        },
    });

    _ = lib_mod;

    // Static library artifact
    const lib = b.addLibrary(.{
        .name = "zig_crypto",
        .linkage = .static,
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/lib.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "math_utils", .module = math_utils_mod },
                .{ .name = "math_bigint", .module = math_bigint_mod },
                .{ .name = "math_modint", .module = math_modint_mod },
                .{ .name = "utils_random", .module = utils_random_mod },
                .{ .name = "utils_mem", .module = utils_mem_mod },
                .{ .name = "sm3", .module = hash_sm3_mod },
                .{ .name = "sha256", .module = hash_sha256_mod },
                .{ .name = "hmac", .module = hash_hmac_mod },
                .{ .name = "sm4", .module = sym_sm4_mod },
                .{ .name = "ecc_field", .module = ecc_field_mod },
                .{ .name = "ecc_point", .module = ecc_point_mod },
                .{ .name = "sm2", .module = ecc_sm2_mod },
                .{ .name = "secp256k1", .module = ecc_secp256k1_mod },
                .{ .name = "ed25519", .module = ecc_ed25519_mod },
                .{ .name = "hkdf_sm3", .module = kdf_hkdf_sm3_mod },
                .{ .name = "merkle", .module = merkle_tree_mod },
                .{ .name = "base58", .module = encoding_base58_mod },
                .{ .name = "bech32", .module = encoding_bech32_mod },
            },
        }),
    });
    b.installArtifact(lib);

    // ============================================================
    // Tests
    // ============================================================
    const test_lib_mod = b.createModule(.{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "math_utils", .module = math_utils_mod },
            .{ .name = "math_bigint", .module = math_bigint_mod },
            .{ .name = "math_modint", .module = math_modint_mod },
            .{ .name = "utils_random", .module = utils_random_mod },
            .{ .name = "utils_mem", .module = utils_mem_mod },
            .{ .name = "sm3", .module = hash_sm3_mod },
            .{ .name = "sha256", .module = hash_sha256_mod },
            .{ .name = "hmac", .module = hash_hmac_mod },
            .{ .name = "sm4", .module = sym_sm4_mod },
            .{ .name = "ecc_field", .module = ecc_field_mod },
            .{ .name = "ecc_point", .module = ecc_point_mod },
            .{ .name = "sm2", .module = ecc_sm2_mod },
            .{ .name = "secp256k1", .module = ecc_secp256k1_mod },
            .{ .name = "ed25519", .module = ecc_ed25519_mod },
            .{ .name = "hkdf_sm3", .module = kdf_hkdf_sm3_mod },
            .{ .name = "merkle", .module = merkle_tree_mod },
            .{ .name = "base58", .module = encoding_base58_mod },
            .{ .name = "bech32", .module = encoding_bech32_mod },
        },
    });

    const run_lib_tests = b.addRunArtifact(b.addTest(.{
        .name = "zig_crypto_tests",
        .root_module = test_lib_mod,
    }));

    const test_step = b.step("test", "Run all tests");
    test_step.dependOn(&run_lib_tests.step);
}
