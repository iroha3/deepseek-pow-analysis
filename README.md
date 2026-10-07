# DeepSeekHashV1 / PoW 逆向分析

> 研究性文档。对象是 DeepSeek 前端公开分发的 PoW wasm（`sha3_wasm_bg.*.wasm`），
> 目的是理解本仓库 `ds_core/src/accounts/pow.rs` 到底在算什么，并提供一个可离线
> 复算的参考实现，便于排查 PoW 相关问题。请勿用于绕过任何风控或滥用服务。

## 1. 背景

`ds_core` 并不在 Rust 里实现 PoW 算法，而是：

1. `POST /api/v0/chat/create_pow_challenge` 拿一个 challenge
2. `wasmtime` 加载 DeepSeek 的 wasm，调用导出函数 `wasm_solve`
3. 把结果 base64 成 `X-Ds-Pow-Response` header

因为算子在 wasm 里，算法一度是黑箱。本文用 `wabt` 反编译 + 动态调用把它拆开了。

## 2. wasm 模块事实

`sha3_wasm_bg.7b9ca65ddd.wasm`（约 26 KB）自包含，**没有任何 import**（自带
`dlmalloc`、`sha3-wasm/src/lib.rs` 等符号）。导出：

| 导出 | 作用 |
|------|------|
| `wasm_solve` | PoW 主入口（brute-force） |
| `wasm_deepseek_hash_v1` | 底层哈希：`DeepSeekHashV1` |
| `memory` | 线性内存 |
| `__wbindgen_export_0` / `_1` / `_2` | malloc / 其它 wasm-bindgen shim |
| `__wbindgen_add_to_stack_pointer` | 栈指针辅助（返回区在 wasm 栈上） |

## 3. `DeepSeekHashV1` = 改版 SHA3-256

参数和标准 SHA3-256 完全一样，**只改了轮函数**：

| 项目 | 标准 SHA3-256 | DeepSeekHashV1 |
|------|---------------|----------------|
| 置换 | Keccak-f[1600] | Keccak-f[1600]（theta/rho/pi/chi 一致） |
| rate / capacity | 136 / 512 | 136 / 512 ✅ |
| 输出 | 256 bit | 256 bit ✅ |
| 填充 | `0x06 … ^0x80` | `0x06 … ^0x80` ✅ |
| **轮常量 / 轮数** | `RC[0..23]`，**24 轮** | **`RC[1..23]`，只需 23 轮** ❌ |

也就是说：轮常量表本身是标准的，但 iota 从 `RC[1]` 开始、且只跑 23 轮，跳过了
`RC[0]`。效果是它**不是任何标准哈希**——所以直接调 `openssl dgst -sha3-256`、
`hashlib.sha3_256`、`ethereum keccak256` 全都对不上。这正是「黑箱」的来源。

`hasattr` 级别的一句话总结：**它是 SHA3-256 少跑一轮、并把轮常量错一位的变体。**

## 4. `wasm_solve` = 原像搜索

关键结论：**challenge 不是随机数，它本身就是哈希输出**。

服务端先选一个答案 `n`，算出
`challenge = DeepSeekHashV1(prefix + str(n))` 当作靶子；客户端从 0 开始穷举 `n`
直到哈希命中。`difficulty` 是 `n` 的取值范围（`n < difficulty`），期望工作量
≈ `difficulty / 2` 次哈希。

```
prefix = f"{salt}_{expire_at}_"
target = bytes.fromhex(challenge)          # 32 字节
for n in 0 .. difficulty:
    if DeepSeekHashV1((prefix + str(n)).encode()) == target:
        return n                            # 以 f64 写回 retptr+8
```

`wasm_solve` 的 ABI 与返回：

```
wasm_solve(retptr, challenge_ptr, challenge_len, prefix_ptr, prefix_len, difficulty:f64)
  retptr+0: i32  status   (1=找到, 0=无解/参数非法)
  retptr+8: f64  answer   (命中的 n)
```

Rust 侧 `pow.rs` 的 `PowSolver::solve` 就是：读 `status`（0 → `PowError::NoSolution`），
读 `value` 并 `as i64` 当作 `answer`，再 `to_header()` 拼 JSON+base64。

## 5. 实测印证

用服务端真实 challenge 验证（见 `vectors.json`）：

```
challenge = 7ffc9d19b6eed96a6fca68f8ffe30ee61035d4959e4180f187bf85b356016a96
salt      = 3bde54628ea8413fee87
expire_at = 1775380966945
difficulty= 144000
answer    = 107544            # wasm_solve 返回

DeepSeekHashV1("3bde54628ea8413fee87_1775380966945_" + "107544")
  == 7ffc9d19…016a96        # 恰好等于 challenge
```

## 6. 文件

| 文件 | 说明 |
|------|------|
| `deepseek_hash_v1.py` | 纯 Python 参考实现（改版 Keccak + `solve`），含自检 |
| `vectors.json` | 测试向量：9 组哈希 + 1 组 solve（由 wasm 生成） |
| `verify_against_wasm.mjs` | 用真实 wasm 复算 `vectors.json`，交叉验证 |

## 7. 使用

```bash
cd pow-analysis

# Python 参考实现自检（不依赖 wasm）
python deepseek_hash_v1.py selftest
python deepseek_hash_v1.py hash "abc"

# 对着 wasm 复算所有向量（需把 wasm 放在仓库根目录，或传路径）
node verify_against_wasm.mjs
node verify_against_wasm.mjs /path/to/sha3_wasm_bg.xxxx.wasm
```

> `solve()` 是纯 Python，逐候选一次置换，跑满 10 万量级会偏慢——仅供离线核对；
> 实际计算交给 `wasm_solve`。

## 8. 复现步骤（怎么拆的）

```bash
# 1. 拿一个反编译器（wabt 的 Node 包最省事）
bun add wabt   # 提供 wasm2wat / wasm-decompile / wasm-objdump

# 2. 看结构和导出
wasm-objdump -x sha3_wasm_bg.*.wasm

# 3. 伪 C / WAT
wasm-decompile sha3_wasm_bg.*.wasm -o pow.dcmp
wasm2wat sha3_wasm_bg.*.wasm -o pow.wat

# 4. 动态跑：Node 内置 WebAssembly 即可，无需依赖
#    - wasm_deepseek_hash_v1 与标准 sha3 对比 → 发现不一致
#    - 读内存里的轮常量表 → 是标准值
#    - 逐步假设(域字节/轮数/RC 偏移)在 Python 里复现 → 定位到 RC[1..23] 23 轮
```

## 9. 相关工作

外部项目 [deepseek-pow](https://github.com/Jerry-Wu-GitHub/deepseek-pow)（PyPI 同名）
用 Python + wasmtime 求解，思路与本仓库 `pow.rs` 一致——**同样把 wasm 当黑箱调用**，
并不了解内部算法。它的价值在工程封装（按算法名注册求解器、pydantic 模型、异常体系、
线程安全说明、打包），可参考其结构；但缺少本文的算法还原。

附带的交叉验证：该项目 `test/test_v1.py` 里独立的 `challenge=10855c4d…`、`answer=64630`
用例，经本目录实现复算 `DeepSeekHashV1(prefix + "64630")` 逐字节等于其 challenge，
反证了本文第 3、4 节的结论。

## 10. 免责声明

本文与实现仅用于协议理解、离线校验和故障排查。算法归属 DeepSeek 官方；
分析与本仓库的 PoW 模块交互相关，不涉及绕过服务端风控。
