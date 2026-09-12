# 微信 CDN storeid / filekey 生成结构逆向

分析对象：微信安卓版 8.0.77（versionCode 3160，包 com.tencent.mm）
数据来源：
- 手机实时捕获的 2 条 C2C 图片 `stodownload` URL（libwechatmm 内明文 HTTP 写出）
- base.apk 18 个 dex 中硬编码的 28 条历史样本 URL（含 storeid/filekey/fileparam）
- libwechatmm.so / libcdnadapter.so 静态反汇编（`mars::cdn` 模块）

---

## 1. 总体流程

```
       客户端(Java 层拼 URL)              服务器(CDN 控制服务)
  ─────────────────────────────────────────────────────────────
  filekey = DER{appid, region, md5}  ──►  控制请求(经 mmtls)  ──┐
  aekey   = CreateAeskey() 随机16字节        │                   │
        │                                  │                   │
        │◄── ctrlinfo: url/bakurl/pcdnurl   │                   │
        │     + storeid(服务端签名，含时间戳)  ◄──────────────────┘
        ▼
  GET https://vweixinf.tc.qq.com/<appid>/<scene>/stodownload
      ?m=<md5>&filekey=<DER hex>&hy=SH&storeid=<token>&ef=1|2&bizid=...
      （携带 X-Reserve 反爬头）
        ▼
  返回 AES 加密的图片数据（密钥 = aekey）
```

- **filekey**：客户端生成，确定性强（由 md5 派生），可离线构造。
- **storeid**：**服务器动态签发**，绑定"时间戳 + 文件 + 账号/区域"，不可客户端构造。
- **aekey**：客户端 `mars::cdn::CreateAeskey()` 生成 16 随机字节 → 32 位 hex。

---

## 2. filekey 生成结构（完整）

URL 中 `filekey=` 是一个 **DER 编码的 ASN.1 结构**，hex 传输。通用骨架：

```
SEQUENCE
 ├─ INTEGER 1                          # 版本号
 ├─ OCTET STRING                       # 内层信息（内容依业务而定）
 │    └─ SEQUENCE
 │         ├─ INTEGER <appid>          # 业务场景号
 │         ├─ OCTET STRING "SH"        # 区域（hy 参数）
 │         ├─ OCTET STRING <md5>       # 16B 二进制 或 32B ASCII hex
 │         └─ [INTEGER <附加>]          # 可选附加整数
 └─ OCTET STRING                       # 尾部扩展（btfs 标记）
      ├─ 00000004 "btfs" 00000001 <0x31|0x32>
      └─ [可选 appstore 扩展]
```

### 2.1 各业务变体（实测样本）

| 业务 | appid | 路径 | md5 编码 | 附加 INTEGER | 尾部 |
|---|---|---|---|---|---|
| C2C 图片（当前版，现场捕获） | **110** (`0x6e`) | `/110/2040X/stodownload` | **32B ASCII hex** | 无 | `btfs…0x32` |
| C2C 图片（dex 历史样本） | 258 (`0x0102`) | — | 16B 二进制 | 有 | `btfs…0x31` |
| SNS 视频缩略图 | 109 (`0x6d`) | `/109/20204/snsvideodownload` | 16B 二进制 | 有 | `btfs…0x31` |
| SNS 视频（原画） | 105 (`0x69`) | `/105/20210/snsdyvideodownload` | 16B 二进制 | 有 | 无 btfs，改带 `fileparam` |
| 模板/占位 | 269 (`0x010d`) | — | 空 OCTET STRING | 有 | `btfs…0x32` |

### 2.2 现场捕获的 C2C 图片 filekey（当前版）

```
filekey = 3044 020101 0430 [48B] 040d [13B]

0430 内层:
  30 2e 02 01 6e 04 02 53 48 04 20 <32B=md5的ASCII hex>

040d 尾部:
  00000004 "btfs" 00000001 32
```

### 2.3 fileparam（SNS 视频专用，与 filekey 并列）

```
fileparam = 302c 020101 0425 [37B] 0400
  内层: 3023 0204 <u32=0x6ffd9302?> 0204 <u32> 0202 <u16> 0203 <u24> 0203 <u24> 0204 <u32> 0201 00 0400
```
主要承载视频转码/码率参数（多组 INTEGER），结构固定。

### 2.4 生成函数

- `mars::cdn::CreateFileKey()`（libwechatmm.so @0x23fac0）：返回 `std::string`，
  内容 = 全局串 + `.` + **16 随机字节的 hex**（非 DER；用于上传侧 aekey/filekey 会话材料）。
- `mars::cdn::CreateAeskey()`（@0x23fa10）：16 随机字节 → 32 位 hex。
- DER 装配在 Java 层 URL 构造处完成（现场捕获到 Java 拼 URL 的字节流）。

---

## 3. storeid 生成结构

storeid 由 **CDN 服务器**在控制信息(ctrlinfo)里下发。不同版本存在 3 种编码：

### 3.1 Format A —— 历史版（ASCII hex，46B，可直接肉眼解）

```
storeid = hex_ascii("YYYYMMDDHHMMSS" + 字段)
例: <hex("YYYYMMDDHHMMSS" + 文件/签名/版本字段)>

字段分解:
  YYYYMMDDHHMMSS   签发时间（UTC+8，服务器签发时刻）→ 会过期
  00               分隔
  <文件相关 ID>     同时间不同文件时变化
  <签名/会话材料>   同时间戳的文件相同
  <版本/校验>       版本与校验字节
```

实测：同一签发时间戳的两个文件，仅「文件相关 ID」段变化，其余全部相同
→ **时间戳绑定、服务器签名**。

另一组（C2C 图片）结尾版本/校验段固定，仅中部文件段变化。

### 3.2 Format B —— 当前 8.0.77（31B 二进制，现场捕获 + dex 样本）

```
字节 偏移  字段               说明
 0-1   XX XX                服务器/会话前缀（同一会话固定）
 2-3   XX XX                "
 4-5   00 00                "
 6-8   XX XX XX             文件相关（不同文件变化，非 md5 直接哈希，含随机/密钥派生）
 8-15  XX ...               签发时间/会话组件（同会话固定）
 16    6e                   appid（=110，与 filekey/URL 路径一致）
 17    02                   ef（1=缩略图 / 2=原图）
 18    00                   保留
 19    4f                   'O' 区域前缀标记
 20    XX                   每文件随机/扰乱字节
 21-22 53 48                "SH" 区域明文
 23    XX                   签名标记
 24-31 XX ...               8B 签名/校验（每文件变化，尾部随 ef 略变）
```

历史版本区域标记为 `4f 50 53 48`("OPSH") / `4f 4f 53 48`("OOSH") 等，`4f` 起头 + 区域码。

### 3.3 结论

- storeid **不可客户端构造**：内含服务器签发时间戳（Format A 明文可见，Format B 为
  会话组件）+ 服务器签名尾部，伪造签名需服务器私钥。
- storeid **有过期时间**：时间戳在签发时刻写死，过期后 CDN 返回 400。
  实测同一 storeid 在 10 分钟内可重复下载且返回一致数据。
- 对"补全缺失图片"的正确做法：**保持 URL 捕获器实时运行**，在微信浏览时抓取
  `m=<md5> + filekey + storeid` 三元组，趁有效期内下载。

---

## 5. 发送消息路径与模拟可行性

### 5.1 发送链路（代码实证）

```
文本消息：
  Java 组装 protobuf ──► MMProtocalJni.pack() (libMMProtocalJni.so)
      ──► mars 长连接 (mmtls, AES-128-GCM, PSK 会话) ──► newsendmsg (reqid 237)

图片/视频/文件：
  ① cdnuploadimgprepare / cdnuploadimgcommit（短连接控制 CGI）
  ② StartC2CUpload (mars CDN, scene="default")
       CreateAeskey()=16B随机密钥 ─► AES加密原始数据
       CreateFileKey()=随机密钥串
       ──► 数据上传 CDN，得到 filekey/aeskey
  ③ sendmsg_from_cdn：经长连接发消息引用（filekey+aeskey+缩略图）
       （libwechatmm.so 存在 "sendmsg_from_cdn" / "sendmsg_via_cdn" 路径）
  ④ 对方用 filekey 派生 stodownload 下载 URL（§2 已逆向）

语音：uploadvoice CGI；文件：uploadappattach CGI
```

- 长连接为 mmtls（`libwechatnetwork.so` 含 `BeginHandShake`/`ClearAllMMtlsPsk`，
  与 PC 版同构 → PC 的 AES-128-GCM 密钥提取方案可复用）
- 文本发送的序列化经 `Java_com_tencent_mm_protocal_MMProtocalJni_pack`（导出符号）

### 5.2 模拟可行性评估

| 方案 | 做法 | 难点 / 风险 |
|---|---|---|
| **① frida 调用 App 自身发送链路**（最现实） | hook Java 发送方法或 `MMProtocalJni.pack`，复用真实会话/mmtls 密钥/设备认证 | 需 frida Java bridge（frida 17 需 npm 打包 `frida-java-bridge`）；需逆向正确调用参数(toUser/content/msgType/seq) |
| **② 独立协议实现** | gdb/内存扫描提取手机上 mmtls 会话密钥（PC 方案移植）；自建 newsendmsg protobuf + mmtls 加密 | 需完整 protobuf schema（ClientMsg 等）、双端 seq 同步、设备状态；seq 失步即被断开；风控（频率/内容）易触发封号 |
| **③ 改包** | hook `pack()` 序列化处替换 content 放行 | 仅能"修改消息"，非自主发送 |

关键瓶颈（按难度）：
1. 手机上提取 mmtls 会话密钥（frida 被反调试杀，需 gdbserver 或 `/proc/pid/mem` 扫描，
   复用 PC 的 AES-128-GCM + IV XOR seq + AAD=seq||记录头 方案）
2. newsendmsg / UploadMsg 的 protobuf schema
3. seq/session 状态管理与服务器风控

### 5.3 实测定位到的发送调用链（8.0.77）

```
UI 发送按钮
 └─ ChatFooter.a(String, int)          # 文本发送入口（插件 SDK UI 层）
     └─ plugin.messenger.foundation.*   # 消息服务层（a0.M/U0/b0 等，参数为 storage.y3 消息对象）
         └─ modelbase.r2.E2(...)       # 网络发送层（7 参: reqid/key/seq/iv/...）
             └─ modelbase.v2.N8(...)   # mars 发送层（18 参: key/host=szlong.weixin.qq.com/port/hash/...）
                 └─ MMProtocalJni.pack # 序列化为 mars protobuf（libMMProtocalJni.so 导出）
                     └─ mars 长连接 (mmtls) ──► newsendmsg (reqid 237)
```

实测：N8 的第 3 参为长连接主机 `szlong.weixin.qq.com` / `szextshort.weixin.qq.com`；
E2/N8 对**所有** mars 网络请求都触发（含后台同步/心跳），非文本专属。

### 5.4 关键坑：frida Java bridge 在微信上必崩 ⛔

反复 attach + `Java.use(...).overloads[...].implementation` 后微信崩溃。tombstone 证实：

```
signal 11 (SIGSEGV) fault addr 0x049a5468
  #00 [anon:dalvik-main space]
  #00 /memfd:frida-agent-64.so (deleted)          ← frida agent 内崩溃
  #02 libart.so art::OptimizingCompiler::JitCompile  ← ART JIT 编译线程
```

**根因**：`frida-java-bridge` 的 ART 方法 hook（patch JIT 代码）与微信大量 JIT 编译
竞争，在编译/绑定线程上竞态 SIGSEGV。纯 native hook（socket 层 `send`/`SSL_write`）
则稳定不崩。

**稳定 hook 正路**：本机已装 **LSPosed（zygisk_lsposed）+ Miko 框架**（含
AutoRedPacket/AntiRevoke 等微信模块），LSPosed 用与 ART 共存的 hook 机制，
是 hook 微信 Java 发送方法的可靠路径；或走纯 native（socket/mmttls）层。

### 5.5 模拟发送可行路线（按稳定性排序）

| 路线 | 做法 | 状态 |
|---|---|---|
| **① LSPosed 模块**（推荐） | 写 Xposed 模块 hook/调用 `ChatFooter.a(String,int)` 或 foundation 发送 API，复用真实会话 | 设备已装框架，最稳；需写模块+重启生效 |
| **② 纯 native frida** | hook mars 发送 native 函数观察请求；构造 protobuf 调 native 发送（不经 Java） | socket 层已证明稳定，但需定位 native 发送函数 + 构造 protobuf |
| **③ mmtls 密钥注入** | 提取手机 mmtls 会话密钥（gdbserver/内存扫描），独立实现 newsendmsg | 难度最高；PC 方案可移植 |

---

## 6. 工具清单（frida_cdn/）

| 脚本 | 作用 |
|---|---|
| `capture_cdn.py` | 实时捕获 CDN 下载 URL（stodownload/sns/头像），存完整请求头 |
| `capture_all.py` | 综合：URL + ctrlinfo 日志 + CreateFileKey/CreateAeskey |
| `hook_ctrlinfo.py` | hook ctrlinfo 日志调用点，dump url/bakurl/pcdnurl |
| `xref.py` / `disasm.py` | 离线字符串 xref 定位 + 反汇编 |

关键 hook 点（libwechatmm.so 偏移）：
- `0x1f476c`：CDN task ctrlinfo 处理/日志函数（x0=task，含 url/storeid/aeskey）
- `0x1f4f38`：ctrlinfo 日志调用点（x1=format, x2=args 数组）
- `0x23fa10` / `0x23fac0`：`CreateAeskey` / `CreateFileKey` 导出符号
- `0x1cdc18`：`CdnManager::StartC2CDownload(C2CDownloadRequest)`（下载任务入口）
- `0x1b50d8`：`JniStartC2CDownload`（Java→native JNI 入口）
