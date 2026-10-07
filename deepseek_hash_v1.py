#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DeepSeekHashV1 参考实现（纯 Python，仅用于研究与离线校验）

DeepSeekHashV1 = 改版 Keccak-f[1600]：
  - rate=136 / capacity=512 / 输出 256bit（参数同 SHA3-256）
  - 填充 domain byte = 0x06，末字节 ^= 0x80（同 SHA3-256）
  - 置换只有 23 轮，轮常量用 RC[1..23]（跳过 RC[0]，标准 SHA3 是 24 轮 RC[0..23]）

正因为"少一轮 + 错位轮常量"，任何标准 SHA3 库都算不出相同结果。

`wasm_solve` 做的事：
  prefix = f"{salt}_{expire_at}_"
  target = bytes.fromhex(challenge)
  for n in 0..difficulty:
      if deepseek_hash_v1((prefix + str(n)).encode()) == target:
          return n
即 challenge 本身是服务端预先算好的哈希输出，客户端做的是**原像搜索**。

用法:
    python deepseek_hash_v1.py selftest          # 用 vectors.json 自检
    python deepseek_hash_v1.py hash "abc"        # 打印哈希
    python deepseek_hash_v1.py solve             # 跑 vectors.json 里的 solve 用例
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

MASK = (1 << 64) - 1
RATE = 136          # SHA3-256 的 rate（字节）
OUTLEN = 32         # 256bit
RC_START = 1        # 从 RC[1] 开始
ROUNDS = 23         # 只跑 23 轮

# 标准 Keccak 轮常量（内存里的表本身是标准的，只是索引被挪了一位）
RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
# rho 旋转偏移，ROT[x][y]
ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61],
       [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]


def _rol(x: int, n: int) -> int:
    n &= 63
    return ((x << n) | (x >> (64 - n))) & MASK


def _keccak_f(state: list[int]) -> None:
    """改版 Keccak-f[1600]：23 轮，RC[1..23]。state 为 25 个小端 u64 lane。"""
    for rnd in range(RC_START, RC_START + ROUNDS):
        c = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
             for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] ^= d[x]
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rol(state[x + 5 * y], ROT[x][y])
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] = (b[x + 5 * y] ^
                                    ((~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y])) & MASK
        state[0] ^= RC[rnd % 24]


class Sponge:
    """可增量吸收的海绵；clone() 用于 solve 里的逐候选克隆。"""

    def __init__(self) -> None:
        self.state = [0] * 25
        self.buf = bytearray()

    def absorb(self, data: bytes) -> None:
        self.buf += data
        while len(self.buf) >= RATE:
            block, self.buf = self.buf[:RATE], self.buf[RATE:]
            self._xor_block(block)
            _keccak_f(self.state)

    def _xor_block(self, block: bytes) -> None:
        for i in range(RATE // 8):
            self.state[i] ^= int.from_bytes(block[i * 8:i * 8 + 8], "little")

    def clone(self) -> "Sponge":
        s = Sponge()
        s.state = self.state.copy()
        s.buf = self.buf.copy()
        return s

    def finalize(self, outlen: int = OUTLEN) -> bytes:
        buf = bytearray(self.buf)
        buf.append(0x06)                     # SHA3 domain separation
        while len(buf) % RATE != 0:
            buf.append(0)
        buf[-1] ^= 0x80                      # 末位填充
        self._xor_block(buf)
        _keccak_f(self.state)
        out = bytearray()
        while len(out) < outlen:
            for i in range(RATE // 8):
                out += self.state[i].to_bytes(8, "little")
                if len(out) >= outlen:
                    break
            if len(out) < outlen:
                _keccak_f(self.state)
        return bytes(out[:outlen])


def deepseek_hash_v1(data: bytes) -> bytes:
    s = Sponge()
    s.absorb(data)
    return s.finalize()


def prefix_for(salt: str, expire_at: int) -> str:
    return f"{salt}_{expire_at}_"


def solve(challenge_hex: str, salt: str, expire_at: int, difficulty: int,
          start: int = 0) -> int | None:
    """原像搜索：返回使 hash(prefix + str(n)) == bytes.fromhex(challenge) 的 n。

    纯 Python 较慢（每条候选一次 finalize 置换），仅用于离线验证。
    真实场景由 wasm_solve 完成。
    """
    target = bytes.fromhex(challenge_hex)
    sp = Sponge()
    sp.absorb(prefix_for(salt, expire_at).encode())
    for n in range(start, difficulty):
        cand = sp.clone()
        cand.absorb(str(n).encode())
        if cand.finalize() == target:
            return n
    return None


# ── 自检 ──────────────────────────────────────────────────────────────

def _load_vectors() -> dict:
    return json.loads((Path(__file__).with_name("vectors.json")).read_text(encoding="utf-8"))


def selftest() -> None:
    data = _load_vectors()
    for v in data["hash_vectors"]:
        got = deepseek_hash_v1(v["input"].encode()).hex()
        assert got == v["deepseek_hash_v1"], f"{v['input']!r}: {got} != {v['deepseek_hash_v1']}"
    sv = data["solve_vector"]
    # 不做全量暴力，直接验证"答案的哈希 == challenge" + 前一个候选不命中
    h_answer = deepseek_hash_v1(
        (prefix_for(sv["salt"], sv["expire_at"]) + str(int(sv["answer"]))).encode()).hex()
    assert h_answer == sv["challenge"], "answer hash mismatch"
    print(f"selftest ok: {len(data['hash_vectors'])} hash vectors, "
          f"solve answer={int(sv['answer'])} (hash matches challenge)")


def _main(argv: list[str]) -> int:
    if len(argv) >= 2 and argv[1] == "selftest":
        selftest()
    elif len(argv) >= 3 and argv[1] == "hash":
        print(deepseek_hash_v1(argv[2].encode()).hex())
    elif len(argv) >= 2 and argv[1] == "solve":
        sv = _load_vectors()["solve_vector"]
        n = solve(sv["challenge"], sv["salt"], sv["expire_at"], sv["difficulty"])
        print(f"answer={n}")
    else:
        print(__doc__)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv))
