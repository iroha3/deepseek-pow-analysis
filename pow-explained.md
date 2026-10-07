# 工作量证明（PoW）到底在证明什么？

> 草稿 · 以机制科普为主，不针对任何具体服务
> 目标读者：写过 API、对"接口防刷"有点好奇的工程师

---

## 一、背景：当一个接口必须"验明正身"之外再收点费

任何暴露在公网的开放接口，迟早会遇到同一类麻烦：

- **脚本刷量**：有人写个循环，每秒几百上千次地打你的接口。
- **爬虫与注册机**：批量注册、批量拉数据、薅羊毛。
- **IP 限流很容易被绕过**：换代理池、换 IP、分布式肉鸡，成本低得可以忽略。
- **验证码影响体验**：正经用户要停下来看图点字，还可能被外包打码平台破解；而且它把成本转嫁给了"人"，而不是"机器"。

这些手段的共同问题是：**它们只在"身份"或"来源"上设卡，而没有让"发起一次请求"本身产生代价。**

于是有了工作量证明（Proof of Work，PoW）的思路：

> 不想验明你是谁，只想让你为这一次请求**付出一点计算代价**。对正常客户端这点代价可以忽略，对想放大规模的攻击者，代价会随着请求数线性上涨。

PoW 最迷人的性质是一条**不对称性**：

> **验证一方极便宜，产出答案的一方极昂贵。**

这条不对称性是整套机制的支点。下面我们把它拆成一个可以自己动手复现的小问题。

---

## 二、简化的问题

先把场景剥到只剩骨架。设想我们有一个需要保护的接口，规则如下：

- 客户端每次请求前，必须先从服务端拿一道"题"；
- 客户端把题解出来，随请求一起交回；
- 服务端**立刻**判断该不该放行。

把需求写成清单：

| 编号 | 需求 | 原因 |
|------|------|------|
| R1 | 验证比求解便宜得多 | 否则服务端会被验证本身压垮 |
| R2 | 求解成本**可控可调** | 要能按压力调节"难度旋钮" |
| R3 | 答案**不可复用** | 防重放、防预计算、防一个答案卖给一百人 |
| R4 | 题目**有生命周期** | 攒一堆题的答案稍后一起用，必须被挡住 |
| R5 | 题目**不可伪造、不可篡改** | 客户端不能自己造题、不能改字段 |
| R6 | 服务端验证尽量**无状态 / 低存储** | 不想为每道题存一份记录 |

注意，这六条里**没有一条要求"保密"**。PoW 不是密码，它不怕你知道规则——它只要求"做起来贵"。

---

## 三、解决方案：用单向函数造一道不对称的题

要满足 R1，我们需要一个**易算难逆**的函数。最现成的就是**密码学哈希**，例如 SHA-256 / SHA-3：

- **正向**：给任意输入，几微秒算出固定长度的输出；
- **反向**：给定输出，想要找一个输入得到它，除了暴力穷举没有便宜办法；
- **雪崩**：输入改一个比特，输出面目全非，看不出规律；
- **抗碰撞**：找不到两个不同输入得到同一输出。

"难逆"就是 R1 里那个"贵"。围绕它，业界形成两种经典范式。

### 范式 A：阈值搜索（hashcash 式）

给客户端一个前缀 `prefix` 和一个目标阈值 `T`，要求找一个 `n`：

```
H(prefix ‖ n) < T
```

输出是个随机数，所以找到一个"落在阈值以下"的 `n` 需要反复试，平均要试 `2^k` 次（`k` 由阈值大小决定）。**满足条件的 `n` 有很多个**，撞上任意一个都算数。

这是比特币、反垃圾邮件 hashcash 用的范式。

### 范式 B：原像反演（本文重点）

换一个方向：**服务端自己先选好答案，算出哈希，把这个哈希当作"靶子"发出去**。

```
服务端：随机选答案 a  →  challenge = H(prefix ‖ a)   → 把 challenge 发出去
客户端：从 0 开始试    →  直到 H(prefix ‖ k) == challenge  → 返回 k
```

直觉上会让人一愣：平时都是"你找个 nonce 去满足条件"，这里怎么是"服务端已经把标准答案的哈希给你了，你反推它"？

关键就在于**哈希不可逆**：虽然靶子 `challenge` 是公开的，但你无法从它算出 `a`，只能暴力枚举。因为哈希抗碰撞，**能命中这个靶子的 `a` 只有一个**——服务端当初选的那个。

范式 B 有一个漂亮的副作用：**难度天然地被答案的取值范围约束**。服务端只要在 `[0, difficulty)` 里随机挑 `a`，客户端从 0 往上撞，期望就要试 `difficulty / 2` 次。难度旋钮就是 `difficulty` 这个整数。

---

## 四、方案本身：一次完整的 PoW 往返

下面把范式 B 落成一个具体、可运行的方案。整个协议只有三个角色、三步。

### 4.1 角色与字段

**服务端下发的"题"包含：**

| 字段 | 含义 | 是否参与哈希 |
|------|------|--------------|
| `algorithm` | 算法标识，便于将来升级 | 否 |
| `salt` | 一次性随机盐 | **是**（拼进前缀） |
| `expire_at` | 过期时间戳 | **是**（拼进前缀） |
| `difficulty` | 难度：答案的取值范围 | 否（当循环上界） |
| `challenge` | 靶值：`H(prefix ‖ answer)` 的十六进制 | 作为比较目标 |
| `signature` | 服务端对上述字段的签名 | 否 |
| `target_path` | 这道题授权哪个接口/用途 | 否（回传校验） |

**客户端交回的"答卷"**：把 `algorithm / challenge / salt / answer / signature / target_path` 原样打包。

### 4.2 三步流程

```
        ┌────────────────────────── 服务端 ──────────────────────────┐
 ① 出题  │  a ← 随机取 [0, difficulty)                                 │
        │  prefix = f"{salt}_{expire_at}_"                            │
        │  challenge = H(prefix ‖ str(a))      # 答案的哈希当靶子      │
        │  signature = Sign(algorithm, challenge, salt, difficulty,   │
        │                   expire_at, target_path)                   │
        │  下发 {algorithm, challenge, salt, difficulty, expire_at,   │
        │        signature, target_path}                              │
        └─────────────────────────────────────────────────────────────┘
                              │
                              ▼
 ② 解题  │  for k in 0 .. difficulty:                                  │
(客户端) │      if H(prefix ‖ str(k)) == challenge:                    │
        │          answer = k; break                                  │
                              │
                              ▼
 ③ 答题  │  交回 {algorithm, challenge, salt, answer, signature,        │
        │        target_path}  （通常塞进一个 HTTP 头）                 │
                              │
                              ▼
        ┌────────────────────────── 服务端 ──────────────────────────┐
 ④ 验题  │  VerifySign(signature, 字段...) ?                           │
        │  now < expire_at ?                                          │
        │  H(prefix ‖ str(answer)) == challenge ?                     │
        │  都通过 → 放行                                              │
        └─────────────────────────────────────────────────────────────┘
```

### 4.3 伪代码（教学版，用标准哈希即可）

```python
import hashlib, hmac, os, time

def H(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

# —— 服务端：出题 ——
def issue(difficulty=20000, ttl=300, purpose="/api/do", key=b"server-secret"):
    salt = os.urandom(8).hex()
    expire_at = int(time.time() * 1000) + ttl * 1000
    prefix = f"{salt}_{expire_at}_".encode()

    answer = int.from_bytes(os.urandom(8), "big") % difficulty   # 只用来造题
    challenge = H(prefix + str(answer).encode()).hex()

    fields = f"{challenge}{salt}{difficulty}{expire_at}{purpose}".encode()
    signature = hmac.new(key, fields, hashlib.sha256).hexdigest()

    return dict(challenge=challenge, salt=salt, difficulty=difficulty,
                expire_at=expire_at, signature=signature, target_path=purpose)

# —— 客户端：解题 ——
def solve(ch):
    prefix = f"{ch['salt']}_{ch['expire_at']}_".encode()
    target = bytes.fromhex(ch["challenge"])
    for k in range(ch["difficulty"]):
        if H(prefix + str(k).encode()) == target:
            return k
    return None

# —— 服务端：验题 ——
def verify(ch, answer, purpose, key=b"server-secret"):
    if int(time.time() * 1000) >= ch["expire_at"]:
        return False
    if ch["target_path"] != purpose:
        return False
    fields = f"{ch['challenge']}{ch['salt']}{ch['difficulty']}{ch['expire_at']}{ch['target_path']}".encode()
    if not hmac.compare_digest(ch["signature"], hmac.new(key, fields, hashlib.sha256).hexdigest()):
        return False
    prefix = f"{ch['salt']}_{ch['expire_at']}_".encode()
    return H(prefix + str(answer).encode()).hex() == ch["challenge"]
```

> 教学版用标准 SHA-256，重点是协议结构。真实系统可能出于工程原因使用**非标准哈希**（见第五节末尾的讨论）。

---

## 五、方案如何解决第二节列出的问题

把六条需求逐条对回去，每条都由方案里的一个具体设计承接：

### R1 · 验证比求解便宜得多
- **求解**：期望 `difficulty / 2` 次哈希，`difficulty` 取几万时，客户端要算几万次。
- **验证**：服务端只做 **1 次哈希** + 1 次签名校验。
- 不对称性完全来自哈希的"易算难逆"。

### R2 · 成本可控可调
- `difficulty` 就是那个旋钮。压力大就调大，客户端平均工作量随之上升。
- 因为答案的取值范围就是这个整数区间，工作量是**可精确估算**的，不像"估摸着加点延迟"。

### R3 · 答案不可复用
- `salt` 每次请求都重新随机，而且**拼进了哈希输入**。
- 于是"同一个答案"在不同请求里算出的 `challenge` 完全不同：
  - 你辛苦解出的答案不能拿去解下一道题；
  - 也不能预先算一张哈希表来查（盐让每次的搜索空间都不一样）。

### R4 · 题目有生命周期
- `expire_at` 既拼进哈希、又被验证时单独检查。
- 攒一批题、过一会儿再把答案集中用掉的做法被挡住。
- 想改时间戳？改了 `challenge` 就对不上（因为哈希输入变了），签名也会失效。

### R5 · 题目不可伪造、不可篡改
- 客户端**拿不到**造题的能力：造一道题的合法靶子需要先挑答案再哈希，而这需要服务端的 `signature` 背书。
- 任何字段被改动，要么哈希对不上，要么签名对不上。
- `target_path` 把这道题**绑定到具体用途**：完成接口的答案不能拿去授权上传接口。

### R6 · 服务端验证尽量无状态
- 服务端不需要为每道题存一条数据库记录。
- 它用 `signature`（对字段做 HMAC/签名）**自证**这道题是自己发的、且字段没被动过；验证时重算签名即可。
- 这也让水平扩容变得轻松：任意一台机器都能独立验题。

### 这套方案解决不了什么（同样重要）

- **挡不住专业攻击者，只是"涨价"**：`difficulty` 调高能提高单次成本，但 GPU/ASIC 每秒能算几十亿次哈希，普通哈希的 PoW 对它们几乎不设防。要抗专用硬件，得换 **memory-hard** 函数（scrypt / Argon2 一类），而不是普通 SHA。
- **obscurity 不是安全**：有些实现会**故意改动标准哈希**（比如微调轮数或常量），让算法"不标准"，从而逼客户端必须运行官方实现、抬高复刻门槛。这能挡住顺手抄的人，但挡不住决心——规则公开后，任何人都可以用任意语言重写一份。
- **它证明的是"花了算力"，不是"是好人"**：PoW 只加成本，不做识别。它常常和限流、风控、身份体系配合使用，而不是替代它们。

---

## 收尾

回到最初那句话：

> **让"发起请求"本身有成本，而验证这个成本几乎免费。**

PoW 的全部魔法，就是找到一个**易算难逆**的函数，把"贵"留在生产答案的一侧，把"便宜"留给验证的一侧，再用**盐、过期时间、签名、用途绑定**把这道题变成一次性、不可复用、不可伪造的凭证。

理解了这一点，你就能自己设计或读懂形形色色的 PoW 变体——无论是"找小于阈值的 nonce"，还是"反推服务端预先算好的哈希"。

---

### 附：想深入的方向

- 阈值搜索的经典应用：hashcash、比特币的工作量证明；
- 抗专用硬件的方向：memory-hard 函数、可验证延迟函数（VDF）；
- 弱化版本的"证明做过事"：等价于一次带随机盐的、可验证的 KDF 计算。
