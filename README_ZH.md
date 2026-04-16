# zig-crypto

> 纯 Zig 实现的公链密码学库 — 包含国密算法 (SM2/SM3/SM4) 和主流密码原语

**[English](./README.md)** | 中文

纯 Zig 实现，无 C 依赖。

[![Zig 0.16.0](https://img.shields.io/badge/Zig-0.16.0-blue.svg)](https://ziglang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## 特性

### 国密算法 (Chinese National Cryptographic Standards)

| 算法 | 标准 | 用途 |
|------|------|------|
| **SM2** | GM/T 0003-2012 | 椭圆曲线签名/验签/密钥交换 |
| **SM3** | GM/T 0004-2012 | 杂凑算法 (256-bit) |
| **SM4** | GM/T 0002-2012 | 分组密码 (128-bit, CBC/ECB) |

### 主流算法

| 算法 | 标准 | 用途 |
|------|------|------|
| **secp256k1** | SECG | EVM 兼容曲线 (比特币/以太坊) |
| **Ed25519** | RFC 8032 | 现代签名算法 |
| **SHA-256** | FIPS 180-4 | 广泛使用的哈希 |
| **HMAC** | RFC 2104 | 消息认证码 |
| **Base58Check** | Bitcoin | 地址编码 |
| **Bech32/Bech32m** | BIP 173/350 | SegWit 地址编码 |

### 架构分层

```
Layer 4 ┌─────────────────────────┐
        │  Encoding (Base58/Bech32) │
        └─────────────┬───────────┘
Layer 3 ┌─────────────┴───────────┐
        │  Protocols (HKDF/Merkle)  │
        └─────────────┬───────────┘
Layer 2 ┌─────────────┴───────────┐
        │  ECC (SM2/secp256k1/Ed25519) │
        └─────────────┬───────────┘
Layer 1 ┌─────────────┴───────────┐
        │  Hash/Sym (SM3/SHA256/SM4) │
        └─────────────┬───────────┘
Layer 0 ┌─────────────┴───────────┐
        │  Math (BigInt/Montgomery)  │
        └─────────────────────────┘
```

---

## 安装

### 添加为 Zig 模块依赖

在 `build.zig.zon` 中添加:

```zig
.{
    .dependencies = .{
        .zig_crypto = .{
            .url = "https://github.com/knot3bot/zig-crypto",
            .hash = "<从 GitHub 获取最新 hash>",
        },
    },
}
```

### 直接克隆

```bash
git clone https://github.com/knot3bot/zig-crypto.git
cd zig-crypto
zig build test
```

---

## 快速开始

```zig
const zig_crypto = @import("zig_crypto");

pub fn main() void {
    // SM3 哈希
    const msg = "Hello, Blockchain!";
    const digest = zig_crypto.sm3.hash(msg);
    std.debug.print("SM3: {s}\n", .{std.fmt.fmtSliceHexLower(&digest)});

    // SHA-256 哈希
    const sha_digest = zig_crypto.sha256.hash(msg);
    std.debug.print("SHA256: {s}\n", .{std.fmt.fmtSliceHexLower(&sha_digest)});

    // SM4 加密
    const key = [_]u8{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                       0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10};
    const plaintext = [_]u8{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                           0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10};
    const ciphertext = zig_crypto.sm4.encryptBlock(key, plaintext);
}
```

---

## API 参考

### Layer 0: 数学原语

#### BigInt256 — 256位无符号整数

```zig
const BigInt256 = zig_crypto.math_bigint.BigInt256;

// 从字节创建
const n = BigInt256.fromBytes(&bytes);  // 32字节, big-endian
const n = try BigInt256.fromHex("0xFFFF...");  // 从十六进制字符串

// 基本运算
const sum = BigInt256.add(a, b);        // 返回 {result, carry}
const diff = BigInt256.sub(a, b);       // 返回 {result, borrow}
const prod = BigInt256.mul(a, b);       // 返回 256位结果
const wide = BigInt256.mulWide(a, b);   // 返回 {low, high} 512位

// 模运算
const mod_sum = BigInt256.addMod(a, b, m);
const mod_sub = BigInt256.subMod(a, b, m);
const mod_mul = BigInt256.mulMod(a, b, m);

// 比较
const cmp_result = BigInt256.cmp(a, b);  // -1, 0, 1
const eq = a.eql(b);
const lt = BigInt256.ctLt(a, b);        // 常数时间比较

// 位操作
const bit = n.getBit(0);               // 获取第 i 位
const bit_count = n.bitCount();         // 位数
```

#### MontgomeryContext — 蒙哥马利乘法上下文

```zig
const MontgomeryContext = zig_crypto.math_modint.MontgomeryContext;
const ctx = try MontgomeryContext.init(prime_modulus);

// 转换为蒙哥马利形式
const a_mont = ctx.toMontgomery(a);
const a_reg = ctx.fromMontgomery(a_mont);

// 蒙哥马利乘法
const c = ctx.montMul(a_mont, b_mont);

// 模幂
const result = ctx.montExp(base, exponent);

// 模逆
const inv = ctx.modInverse(a);
```

---

### Layer 1: 哈希与对称加密

#### SM3 杂凑算法

```zig
const Sm3 = zig_crypto.sm3.Sm3;

// 单次哈希
const digest = Sm3.hash("message");

// 分步哈希
var ctx = Sm3.init();
ctx.update("part1");
ctx.update("part2");
const result = ctx.finalize();
```

**测试向量:**
```zig
SM3("")        = 1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b
SM3("abc")     = 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0
SM3("abcd...") = b80fe97a4da24afc277564f66a359ef440462ad28dcc6d63adb24d5c20a61595
```

#### SHA-256

```zig
const Sha256 = zig_crypto.sha256.Sha256;

// 单次哈希
const digest = Sha256.hash("message");

// 分步哈希
var ctx = Sha256.init();
ctx.update("data");
const result = ctx.finalize();
```

**测试向量:**
```zig
SHA256("")        = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
SHA256("abc")     = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
```

#### HMAC

```zig
const Sm3Hmac = zig_crypto.hmac.Sm3Hmac;

// 初始化
var ctx = Sm3Hmac.init("key");
ctx.update("message");
const tag = ctx.finalize();

// 便捷函数
const result = zig_crypto.hmac.hmacSm3("key", "message");
```

#### SM4 分组密码

```zig
const Sm4 = zig_crypto.sm4.Sm4;

// 初始化
const key = [_]u8{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                   0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10};
var ctx = Sm4.init(key);

// 单块加密/解密
const ciphertext = ctx.encrypt(plaintext_block);
const decrypted = ctx.decrypt(ciphertext);

// ECB 模式
ctx.encryptEcb(plaintext, ciphertext);
ctx.decryptEcb(ciphertext, plaintext);

// CBC 模式
const iv = [_]u8{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                  0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
ctx.encryptCbc(iv, plaintext, ciphertext);
ctx.decryptCbc(iv, ciphertext, plaintext);

// 便捷函数
const ct = Sm4.encryptBlock(key, block);
const pt = Sm4.decryptBlock(key, block);
```

**测试向量 (GM/T 0002-2012):**
```zig
Key:        0123456789ABCDEFFEDCBA9876543210
Plaintext:  0123456789ABCDEFFEDCBA9876543210
Ciphertext: 681EDF342C58B5DB41B7387DA67B8A42
```

---

### Layer 2: 椭圆曲线密码学

#### SM2 签名算法

```zig
const sm2 = zig_crypto.sm2;
const point = zig_crypto.ecc_point;
const BigInt256 = zig_crypto.math_bigint.BigInt256;

// 初始化曲线参数
const curve = try point.initCurveParams(
    sm2.SM2_CURVE.p,
    sm2.SM2_CURVE.a,
    sm2.SM2_CURVE.b,
    sm2.SM2_CURVE.gx,
    sm2.SM2_CURVE.gy,
    sm2.SM2_CURVE.n,
    sm2.SM2_CURVE.h,
);

// 生成密钥对
const key_pair = try sm2.KeyPair.generate(curve);
std.debug.print("Private key: {s}\n", .{key_pair.private_key.toHex()});

// 从私钥创建
const kp2 = try sm2.KeyPair.fromPrivateKey(private_key, curve);

// 签名
const id = "user@email.com";
const signature = try sm2.sign(key_pair.private_key, message, id, &curve);

// 验签
const valid = try sm2.verify(key_pair.public_key, message, signature, id, &curve);
std.debug.print("Signature valid: {}\n", .{valid});
```

#### secp256k1 (比特币/以太坊)

```zig
const secp256k1 = zig_crypto.secp256k1;
const point = zig_crypto.ecc_point;

// 初始化曲线
const curve = try secp256k1.initCurve();

// 从私钥推导公钥
const G = point.AffinePoint.create(curve.gx, curve.gy);
const pub_key = point.scalarMul(private_key, G, &curve);
```

#### 椭圆曲线点运算

```zig
const point = zig_crypto.ecc_point;

// 点加法
const sum = point.pointAdd(p1, p2, &curve);

// 点倍乘
const doubled = point.pointDouble(p, &curve);

// 标量乘法 (double-and-add)
const product = point.scalarMul(scalar, point_affine, &curve);

// Jacobian 坐标转换
const affine = jacobian.toAffine(&curve);
```

---

### Layer 3: 协议层

#### HKDF-SM3

```zig
const hkdf_sm3 = zig_crypto.hkdf_sm3;

// Extract
const prk = hkdf_sm3.extract(salt, ikm);

// Expand
var okm: [32]u8 = undefined;
hkdf_sm3.expand(&prk, info, &okm);

// 一步完成
hkdf_sm3.hkdfSm3(salt, ikm, info, &okm);
```

#### Merkle 树

```zig
const merkle = zig_crypto.merkle;

// 计算 Merkle 根 (从已哈希的叶子)
const root = try merkle.merkleRoot(allocator, &leaves);

// 从原始数据构建 (自动哈希每个叶子)
const root2 = try merkle.merkleRootFromData(allocator, &data_items);
```

---

### Layer 4: 编码

#### Base58Check

```zig
const base58 = zig_crypto.base58;

// 编码
const encoded = try base58.encode(allocator, data);
defer allocator.free(encoded);

// 解码
const decoded = try base58.decode(allocator, encoded);
defer allocator.free(decoded);

// Base58Check (带校验和)
const addr = try base58.encodeCheck(allocator, 0x00, payload);  // 版本号 + payload + 4字节校验
```

#### Bech32/Bech32m

```zig
const bech32 = zig_crypto.bech32;

// 编码
const encoded = try bech32.encode(allocator, "bc", &data5, .bech32);
defer allocator.free(encoded);

// 解码
const decoded = try bech32.decode(allocator, encoded);
defer allocator.free(decoded.hrp);
defer allocator.free(decoded.data);

// 8位转5位转换
const data5 = try bech32.convertBits(data, 8, 5, true, allocator);
```

---

### 工具函数

#### 随机数

```zig
const random = zig_crypto.utils_random;

// 填充随机字节
var bytes: [32]u8 = undefined;
random.fillRandom(&bytes);
```

#### 安全内存

```zig
const mem = zig_crypto.utils_mem;

// 恒定时间比较
const eq = mem.constantTimeEq(&a, &b);

// 安全清零
mem.secureZero(&sensitive_data);
```

---

## 构建与测试

```bash
# 构建库
zig build

# 运行测试
zig build test

# 查看所有构建选项
zig build -h
```

---

## 模块依赖图

```
lib.zig
├── math_utils
├── math_bigint
│   └── math_utils
├── math_modint
│   ├── math_utils
│   └── math_bigint
├── utils_random
├── utils_mem
├── sm3 (hash/sm3.zig)
├── sha256 (hash/sha256.zig)
├── hmac
│   └── sm3
├── sm4 (sym/sm4.zig)
├── ecc_field
│   ├── math_utils
│   ├── math_bigint
│   └── math_modint
├── ecc_point
│   ├── math_bigint
│   ├── math_modint
│   └── ecc_field
├── sm2
│   ├── math_bigint
│   ├── math_modint
│   ├── ecc_field
│   ├── ecc_point
│   ├── sm3
│   ├── utils_random
│   └── utils_mem
├── secp256k1
│   ├── math_bigint
│   ├── math_modint
│   ├── ecc_field
│   └── ecc_point
├── ed25519
│   ├── math_bigint
│   ├── ecc_field
│   ├── utils_random
│   └── utils_mem
├── hkdf_sm3
│   ├── sm3
│   └── hmac
├── merkle
│   └── sm3
├── base58
│   └── sha256
└── bech32
```

---

## 参考标准

### 国密标准 (GM/T)
- [GM/T 0002-2012](http://www.gmisp.cn/) — SM4 分组密码算法
- [GM/T 0003-2012](http://www.gmisp.cn/) — SM2 椭圆曲线公钥密码算法
- [GM/T 0004-2012](http://www.gmisp.cn/) — SM3 密码杂凑算法

### 国际标准
- FIPS 180-4 — SHA-256
- RFC 2104 — HMAC
- RFC 5869 — HKDF
- RFC 8032 — Ed25519
- BIP 173 — Bech32
- BIP 350 — Bech32m
- SEC 2 — secp256k1 曲线参数

### 实现参考
- [OpenSSL](https://www.openssl.org/) — SM3/SM4 参考实现
- [Linux Kernel crypto/sm4.c](https://github.com/torvalds/linux/blob/master/crypto/sm4.c) — SM4 优化实现

---

## 许可证

MIT License

---

## 贡献

欢迎提交 Issues 和 Pull Requests！

## 致谢

- 国密算法标准由国家密码管理局发布
- 参考了 OpenSSL、Linux Kernel 等开源项目
