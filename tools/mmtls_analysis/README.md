# WeChat mmtls 协议逆向分析 (Linux 4.1.8)

针对 `/opt/wechat` 原生 Linux 版微信 (mars 框架) 的 mmtls 协议被动抓包逆向结果。

## 0. 结论摘要

- 微信核心进程 `/usr/bin/wechat` 使用 **mars 框架** 的 mmtls 库进行通信。
- 协议有两种承载方式，记录层（record layer）完全相同：
  1. **长连接 / mmtls over TCP**：端口 80/443/8080，裸 TCP，记录直接连排。
  2. **短连接 / mmtls over HTTP**：端口 80，HTTP 请求体/响应体承载 mmtls 记录，`Upgrade: mmtls`。
- mmtls 记录头是 **TLS 风格的 5 字节定长头**，但版本字段恒为 `f1 04`（不是 `03 03`）。
- 应用数据 (0x17) 为 AEAD 密文。二进制静态链接 BoringSSL，**同时支持
  ChaCha20-Poly1305 与 AES-128/256-GCM**（`TLS_CHACHA20_POLY1305_SHA256`、
  `TLS_PSK_WITH_CHACHA20_POLY1305_SHA256`、`AESGCM` 等字符串均存在）。

## 1. mmtls 记录格式 (RECORD LAYER)

```
偏移  长度  字段
0     1     type       0x16=握手响应(服务端) / 0x19=握手请求(客户端)
                       0x17=应用数据 / 0x15=会话通知(结束)
1     2     version    恒为 f1 04
3     2     length     大端 uint16，body 字节数
5     n     body
```

示例（长连接抓包，正是你抓到的 `17 f1 04 00 ...`）：

```
17 f1 04 00 b0  |  <176 字节密文>          <- 请求, 共 181 字节
17 f1 04 00 98  |  <152 字节密文>          <- 响应, 共 157 字节
```

校验：`0x00b0=176`, 176+5=181 ✓ ; `0x0098=152`, 152+5=157 ✓

## 2. 短连接 mmtls over HTTP

客户端请求（一次完整短连接交换的抓包原文）：

```
POST /mmtls/581e6729 HTTP/1.1
Accept: */*
Cache-Control: no-cache
Connection: Keep-Alive
Content-Length: 507
Content-Type: application/octet-stream
Host: szextshort.weixin.qq.com
Upgrade: mmtls
User-Agent: MicroMessenger Client

<mmtls 记录流>
```

服务端响应：

```
HTTP/1.1 200 OK
Connection: close
Content-Type: application/octet-stream
Content-Length: 232

<mmtls 记录流>
```

响应体 (232 字节) 里 4 条记录，其中一条有回显说明正确解析：

```
body @   0  type=0x16 handshake  len=46
body @  51  type=0x16 handshake  len=55
body @ 111  type=0x17 appdata   len=104
body @ 220  type=0x15 notify    len=23     (51+60+109+28 = 248 ✓)
```

## 3. 握手消息结构 (HANDSHAKE)

每条 handshake 记录的 body 内部：

```
u32   length       大端，= 本条消息剩余字节数
u8    type         0x01 客户端 ClientHello / 0x02 服务端 ServerHello
u8[]  version      观测为 04 f1 01 00(客户端) / 04 f1 00 a8(服务端)
u8[32] random      随机数
...   会话票据 / PSK 材料（长度前缀字段，未解密）
```

客户端 hello 的剩余部分可见清晰的长度前缀结构：

```
00 00 00 6f   111 字节子消息
01 00 00 00 6a ...
00 0f ...
01 00 00 00 63 ...
01 00 09 ...
3a 80 00 00 00 00 00 48 00 0c <12B> 00 48 <72B> ...
```

> 该构建使用 **PSK/会话恢复** 快速握手（对应二进制中的 `mmtls_psk.cpp`），
> 握手消息很短（46/55 字节），不携带完整 ECDHE 交换。

## 4. 服务器与端口

抓包实测端口 80/443/8080 均承载 mmtls，实际 IP 段（腾讯）：
`43.137.221.x, 175.27.x, 222.79.113.x, 27.155.118.x`。

## 5. 抓包方法（mihomo TUN 下）

流量经 mihomo TUN：应用 -> 198.18.0.1 -> 真实网卡(enp2s0) -> 服务器。

```bash
# 下行（服务器->应用）在 lo 上可见
sudo tcpdump -i lo -nn -w tun_in.pcap 'port 80 or port 443 or port 8080'
# 上行（应用->服务器）在真实网卡上可见 (NAT 后源地址为局域网 IP)
sudo tcpdump -i enp2s0 -nn -w nic_out.pcap 'tcp and (port 80 or port 443 or port 8080)'
# 或一次性抓全部
sudo tcpdump -i any -nn 'host <微信服务器IP>'
```

> 注意：长连接可能使用 8080 端口，抓包过滤器务必包含 `port 8080`。

## 6. 工具用法

```bash
python3 pcap_mmtls.py <file.pcap> [过滤IP]   # 重组成流并按 HTTP/裸TCP 解析记录
python3 mmtls_parser.py http < body.bin     # 解析一个 HTTP 报文(含头部)
python3 mmtls_parser.py raw  < body.bin     # 解析一段裸 mmtls 记录流
```

另有被动内存扫描器 `tools/scan_key.py`：

```bash
# 多进程扫描微信堆内存中的会话密钥（ChaCha20/AES-128/AES-256）
# 用 AEAD tag 验证候选密钥（假阳性率 2^-128）
MAXSEQ=512 PHASE=12 SCAN16=1 python3 -u scan_key.py <pid> <pcap> <微信服务器IP>
#   PHASE=1 快速(seq 0..15) / PHASE=2 全量(seq 0..MAXSEQ)
#   SCAN16=1 额外扫 16 字节密钥(AES-128) / ISOLATE=0 关闭媒体隔离过滤
```

## 7. 解密应用数据的尝试与结论

### 7.1 frida 挂钩 —— 不可行 ⛔

多次尝试 hook mmtls 编解码函数均导致微信崩溃（共 5 次，minidump 显示
`SIGSEGV at addr=0`，即空指针跳转）。根因是该微信构建与 frida 内联补丁不兼容：

- 异常终止 frida 会残留函数入口的 `e9` 跳转补丁，指向已释放的 trampoline；
- Backtracer 在热路径上会因栈损坏崩溃；
- 即使通过管道 `quit` 干净卸载，恢复补丁过程同样触发崩溃；
- 最小化单钩子（seal / Encrypt 调用点）在发消息瞬间同样崩溃。

结论：**不要在该微信进程上用 frida Interceptor 挂钩**。只读 frida 操作
（读模块基址/内存）是安全的。

### 7.2 被动内存扫描 —— 已评估，未采用 ⛔

曾实现多进程内存扫描器（`tools/scan_key.py`）：
- 遍历全部可写内存段（堆优先，含文件映射 .bss/.data），8 字节步长；
- 熵预过滤 + 相邻密钥对 + 媒体/压缩数据隔离过滤；
- 支持 ChaCha20-Poly1305 / AES-256-GCM（32B）与 AES-128-GCM（16B）；
- nonce 假设：`seq12` / `seq8` / `iv XOR seq`（多种 IV 偏移），aad = 记录头或空；
- 两阶段 seq：phase1 (0..15) 快速 / phase2 (0..MAXSEQ) 全量；
- AEAD tag 验证假阳性率 2^-128，自测通过（三种加密算法均能正确命中）。

**未命中的原因（后经 gdb 验证确认）**：
1. **AEAD nonce/aad 精确构造未知** —— mmtls_lib 闭源，纯猜测组合无法通过 tag 验证。
2. cipher_state 用 relative-vtable + 封装指针，Key/IV 以动态状态机存储，
   且被媒体/压缩缓存干扰，纯被动扫描假阳性高。

> 该方法被 §7.3 的 **gdb 硬件断点直接提取**方案取代（不再需要猜测参数）。

### 7.3 提取结果：AES-128-GCM 会话密钥 + 完整解密（✅ 全链路攻破）

**完整解密参数（经线上抓包验证，双向 580+ 记录连续解密成功）：**

```
Cipher:  AES-128-GCM
Key1 (客户端→服务器):  <16B，gdb 提取>
IV1                    <12B>
Key2 (服务器→客户端):  <16B>
IV2                    <12B>
Nonce:   IV XOR record_seq(12B 大端)     ← 每记录递增
AAD:     record_seq(8B 大端) + 5B记录头(17 f1 04 len)
```

key1/key2 位于 cipher 对象 `[cobj+0x50]`/`[cobj+0xc0]`（第二对象基址 `cobj+0x70`，
同布局 rel+0x50/+0x30），IV 在 `[cobj+0x30]`/`[cobj+0xa0]`。

**离线解密工具**（`tools/mmtls_analysis/`）：
```bash
python3 mmtls_decrypt.py <pcap> <服务器IP> <key_hex> <iv_hex>
```

**实时抓包解包输出**（`tools/mmtls_analysis/`）：
```bash
MMTLS_KEYS="key1 iv1 key2 iv2" sudo python3 -u mmtls_live.py [服务器IP]
# 密钥由 gdb 硬件断点提取（tools/gdb_extract_key.sh）
# 连接重连后 key 变化，会提示 DECRYPT-FAIL，需重新提取
```

解密出的 mars 明文结构（含设备号、URI、自增计数器）：
```
00 00 01 72 | 00 10 00 01 | 00 00 00 79 | 00 00 02 xx | <8B 会话/设备数据> ...
<device/account id>   ← 设备/账号标识（解密明文）
/cgi-bin/micromsg-bin/statusnotify, newsync ...
```

**提取路径**（gdb 硬件断点，全程微信零崩溃，脚本见 `tools/`）：
- key：`cipher_state(LongConnResult)` → `[+8]` cipher obj → `+0x50`（key_len=0x10 证实 AES-128）
- IV：cipher obj → `+0x30`（nonce_len=0x0c 证实 12 字节）
- AAD：`0x6fa9a0b` 调用点 `[8B seq][5B 记录头]`（13 字节）
- nonce：`IV XOR seq`（BoringSSL setiv 经 `0x6fa99c0`→`0x711d270`，rsi=9 模式, rdx=0x0c 长度）

**key 生命周期**：同连接内固定（仅 nonce 每记录变）；跨连接/重连后重新协商（需重提取）。

**明文捕获命令**（无需 key，直接读加密前数据）：
```bash
sudo bash tools/mmtls_analysis/tools/gdb_capture_plaintext.sh
```
