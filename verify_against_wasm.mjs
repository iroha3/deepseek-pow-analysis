// 用真实的 DeepSeek PoW wasm 交叉验证 pow-analysis/vectors.json。
// 这些向量同时被 deepseek_hash_v1.py 自检，两边一起保证实现一致。
//
// 用法:
//   node verify_against_wasm.mjs [wasm路径]
// 默认 wasm 路径: ../sha3_wasm_bg.7b9ca65ddd.wasm (相对本脚本)

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const wasmPath = process.argv[2] ?? join(here, "..", "sha3_wasm_bg.7b9ca65ddd.wasm");
const vectors = JSON.parse(readFileSync(join(here, "vectors.json"), "utf8"));

const { instance } = await WebAssembly.instantiate(readFileSync(wasmPath), {});
const {
  memory,
  wasm_deepseek_hash_v1: hashV1,
  wasm_solve: solve,
  __wbindgen_export_0: malloc,
  __wbindgen_add_to_stack_pointer: stack,
} = instance.exports;
const te = new TextEncoder(), td = new TextDecoder();

function writeStr(s) {
  const b = te.encode(s);
  const p = malloc(b.length, 1);
  new Uint8Array(memory.buffer, p, b.length).set(b);
  return [p, b.length];
}
function hash(s) {
  const [p, len] = writeStr(s);
  const ret = stack(-16);
  hashV1(ret, p, len);
  const dv = new DataView(memory.buffer);
  return td.decode(new Uint8Array(memory.buffer, dv.getInt32(ret, true), dv.getInt32(ret + 4, true)));
}
function runSolve(challenge, prefix, difficulty) {
  const [cp, cl] = writeStr(challenge);
  const [pp, pl] = writeStr(prefix);
  const ret = stack(-16);
  solve(ret, cp, cl, pp, pl, difficulty);
  const dv = new DataView(memory.buffer);
  return { status: dv.getInt32(ret, true), value: dv.getFloat64(ret + 8, true) };
}

let failed = 0;
for (const v of vectors.hash_vectors) {
  const got = hash(v.input);
  const ok = got === v.deepseek_hash_v1;
  if (!ok) failed++;
  console.log(`hash(${JSON.stringify(v.input.slice(0, 24))}${v.input.length > 24 ? "…" : ""})`.padEnd(40),
    ok ? "OK" : `FAIL got=${got} want=${v.deepseek_hash_v1}`);
}

const sv = vectors.solve_vector;
const got = runSolve(
  sv.challenge,
  `${sv.salt}_${Number(sv.expire_at)}_`,
  sv.difficulty,
);
const okSolve = got.status === sv.status && got.value === Number(sv.answer);
if (!okSolve) failed++;
console.log(`solve()`.padEnd(40), okSolve ? "OK" : `FAIL got=${JSON.stringify(got)} want=${JSON.stringify({ status: sv.status, value: sv.answer })}`);

console.log(failed === 0 ? "\nall vectors verified against wasm" : `\n${failed} mismatch(es)`);
process.exit(failed === 0 ? 0 : 1);
