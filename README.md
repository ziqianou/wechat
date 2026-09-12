# 微信聊天记录导出与智能分析

基于微信 PC 4.0 数据的聊天记录导出工具，支持：

- **按昵称自动定位会话**，导出可读聊天记录
- **图片 OCR**：自动提取截图/聊天记录/试卷等图片中的文字
- **图片视觉描述**（VLM）：对照片、图表生成中文描述
- **语音转文字**：SILK 语音自动转写为文本（Whisper）
- **增量更新**：只处理新消息，媒体结果缓存复用
- **数据库直接解密**：本地密钥配置（`wx_secrets.py`），本地快照后解密真实微信数据目录
- **缺失图片补全**：从消息 XML 提取 CDN URL 下载表情包，转 V2 dat 落盘
- **朋友圈图片导出**：解密 SNS 缓存图片，按 原图/缩略图 分类整理

---

## 功能特性

| 功能 | 说明 | 默认 |
|---|---|---|
| 聊天记录导出 | 按联系人昵称/备注定位会话，输出带时间戳的对话文本 | ✅ |
| 图片 OCR | RapidOCR 提取图片内文字 | ✅ 开 |
| 图片视觉描述 | Qwen2.5-VL 生成照片/图表中文描述 | ⏸ 关（需显式开启） |
| 语音转文字 | SILK → MP3 → Whisper 中文转写 | ✅ 开 |
| 增量更新 | 记录每个会话进度，只处理新增消息 | ✅ |
| H265 原图保留 | 微信 4.0 的 wxgf(HEVC) 图片可转 JPEG 或保留 `.h265` | ✅ |
| 数据库直接解密 | 本地密钥配置，本地快照 + SQLCipher 解密真实目录 | ✅ |
| 缺失图片补全 | 下载消息 XML 自带 URL 的表情包，转 V2 dat 落盘 | ✅ |
| 朋友圈图片导出 | 解密 SNS 缓存，按原图/缩略图分类 | ✅ |

---

## 快速开始

### 1. 配置本地密钥（必需，不入库）

账号路径与数据库密钥不写入源码，统一放在被 `.gitignore` 屏蔽的本地文件中：

```bash
# Python：复制模板后填入真实 WX_BASE / SELF_WXID / DB_KEYS
cp wx_secrets.example.py wx_secrets.py
# Shell：run.sh 读取的真实微信目录
echo 'WECHAT_BASE=/path/to/xwechat_files/<wxid>_<pid>' > wx_secrets.env
```

> 密钥获取方式见下文「派生密钥格式与内存提取」。
> `wx_secrets.py` 与 `wx_secrets.env` 已被忽略，不会随仓库提交。

### 2. 运行

```bash
# 导出指定联系人会话（自动直解真实微信目录）
./run.sh 联系人A
./run.sh 联系人B
./run.sh wxid_xxxxxxxxxxxx

# 开启图片视觉描述（照片/图表无文字时生成描述）
WECHAT_VLM=1 ./run.sh 联系人A
```

> **数据来源**：一律从真实微信数据目录
> `xwechat_files/<wxid>_<pid>/db_storage/` 本地快照后按本地密钥配置解密

> **🔒 需要 root 权限**（部分功能）：
> - 常规导出（`main.py` / `run.sh` / `export_sns.py` / 图片补全）普通用户即可运行
> - **mmtls 抓包/解密**（`mmtls_analysis/` 下 tcpdump、gdb 断点提取密钥、
>   捕获明文等）**必须 root**：`sudo bash <脚本>` 或 `sudo python3 -u <脚本>`
> - 脚本内置 root 校验，非 root 运行会直接报错退出
> - 微信数据目录需对运行用户可读（默认 `xwechat_files` 目录属主可读）

### 补全缺失图片

```bash
# 下载消息 XML 自带 URL 的表情包/emoji，转 V2 dat 落盘（会话 hash = Msg_ 表名后缀）
python3 tempfile/decrypt_v4/image_downloader.py <会话 hash>

# 微信浏览有新图片的会话时，扫描进程内存捕获 CDN 下载 URL
python3 tempfile/decrypt_v4/url_capture.py
```

### 环境变量开关

| 变量 | 说明 | 默认 |
|---|---|---|
| `WECHAT_CONTACT` | 默认联系人昵称（未设时须在命令行指定） | 无 |
| `WECHAT_OCR` | 图片 OCR | `1` |
| `WECHAT_VLM` | 图片视觉描述（较慢） | `0` |
| `WECHAT_ASR` | 语音转文字 | `1` |

---

## 输出示例

```text
[2026-05-30 15:39:23] 我: [图片](文字: 15:39:19 | 哆 | 100% | 联系人A m26.16的红包 | ...)
[2026-07-01 11:55:32] 我: [图片](描述: 图中是一条河流，河岸上有一座建筑，前面有一个小桥...)
[2026-07-30 17:25:31] 联系人B: [语音→文字](反方还提了一个很有意思的例子...)
```

- `[图片](文字: ...)`：OCR 提取的图片文字
- `[图片](描述: ...)`：VLM 生成的图片描述
- `[语音→文字](...)`：语音转写结果
- `[合并消息]{...}`：合并转发的嵌套消息

---

## 输出文件

| 文件 | 说明 |
|---|---|
| `chat_history_<显示名>.txt` | 主聊天记录（含图片 OCR/描述、语音转文字） |
| `moments_export.txt` | 朋友圈导出（动态 + 点赞/评论，含时间） |
| `tempfile/decrypt_v4/out/<月份>/Img/*.jpg` | 解密后的全尺寸图片（JPEG） |
| `tempfile/decrypt_v4/out/<月份>/Img/*.h265` | wxgf 图片的 H265 原始编码 |
| `tempfile/decrypt_v4/out_rec/` | Rec 转发记录中的图片 |
| `tempfile/decrypt_v4/fan_voice/` | 语音文件（`.silk` + `.mp3` + `transcript.txt`） |
| `tempfile/decrypt_v4/cache/` | 增量状态与媒体结果缓存（`state.json`/`images/`/`voices/`） |

---

## 朋友圈导出

解密 `sns.db`（SQLCipher，密钥见 `wx_secrets.py`）并导出为可读文本：

```bash
# 导出全部朋友圈
python3 export_sns.py

# 只导出某人的动态（昵称/备注/wxid 均支持）
python3 export_sns.py 联系人A
python3 export_sns.py wxid_xxxxxxxxxxxx
python3 export_sns.py -w wxid_xxxxxxxxxxxx   # 同上，-w 显式指定 wxid

# 限制条数
python3 export_sns.py --limit 100
```

### 昵称匹配（鲁棒性）

与 `main.py` 的会话定位一致，支持：

1. **精确 wxid**：`wxid_xxxxxxxxxxxx`
2. **精确显示名**（备注 > 昵称，不区分大小写）：`联系人A`
3. **wxid 前缀**（部分 wxid）：`-w wxid_xxxx`
4. **显示名模糊子串**：`联系人A` 可匹配 `联系人A p23.5 m26.10`

匹配时自动排除群聊（`@chatroom`）、服务号（`@openim`）和陌生人（`@stranger`/`v3_`）；
多候选时优先真实 `wxid_` 联系人并取最短命中。未匹配到任何用户会输出警告并导出全部。

### 输出格式

```text
【联系人A m26.8 | 2026-08-21 00:33:02】
我已经一个暑假没有动过笔了（为数不多用笔的是在快递盒上写地址）...
  [图] 1920x2560
  👍 联系人B p23.3 m26.8 2026-08-21 00:33:47, 联系人C m26.8 2026-08-21 00:39:13
  💬 联系人D m26.4 (2026-08-21 00:15:28) : 今天早上看的...
```

- 点赞（👍）与评论（💬）均有**具体时间**，来源为 XML `user_comment.create_time` 与 `SnsMessage_tmp3.create_time`
- **已删除标记**：评论/点赞在 `SnsMessage_tmp3` 中有记录、但当前动态 XML 中已不存在时标注
  `(已删除)`（可发现被撤回/编辑过的评论）；点赞去重与已删判断以 `username` 为准
- 评论支持**引用/回复**：`[引用 @昵称: 被引用的评论内容]`，来源为
  `SnsMessage_tmp3.serialized_ref_buf`（protobuf：f1/f3=被引用者、f8=被引用内容），
  以及 XML `ref_username`（仅回复对象）；无内容时只标注 `[引用 @昵称]`
- 昵称统一经 `_build_nickname_resolver()` 解释：`wxid → 备注/昵称`（来源真实 `contact.db` 本地快照解密）

### 朋友圈可见性

微信把可见性（"不让他看"/"不看 TA"/"仅 N 天可见"）放在**服务端过滤**，本地 `sns.db`
只缓存"我可见"的动态，没有黑白名单表：

- 被屏蔽用户的动态不会落库（本地仅 276 个用户，通讯录 1782 个）
- "仅 N 天可见"体现在时间跨度：如某用户 10 条动态跨度 6 天 → 疑似仅一周可见
- 单条动态 XML 有 `<private>`/`<showFlag>` 标志，但无 blackList/whiteList 名单
- 权限名单存服务端，本地仅加密 MMKV（未落明文）

---

## 工作原理

### 会话定位

1. 输入昵称 → 在真实 `contact.db` 的 `Contact` 表按 `remark`/`nick_name` 匹配（支持子串模糊匹配，自动排除群聊和服务号）
2. 会话表名 = `Msg_` + `md5(username)`，例如：
   - `wxid_aaaaaaaaaaaa` → `Msg_<md5(username)>`

### 图片解密（WeChat 4.0 V2 格式）

微信 4.0 图片文件头为 `07 08 56 32`（"V2"），结构：

```
[6字节签名 0708 5632 0807] [aes_len 4字节] [xor_len 4字节] [1字节填充]
[前 aes_len 字节：AES-ECB 加密]
[中间段：明文]
[后 xor_len 字节：与 0xAC 逐字节异或]
```

微信实际生成的 V2 dat 恒为 `aes_len = 1024`（前 1024 字节 AES-ECB 加密，密钥见
`wx_secrets.py` 的 `IMAGE_AES_KEY`），剩余全部 XOR `0xAC`，无中间明文段。

解密后可能是：
- **JPEG/PNG/GIF**：直接可用
- **wxgf（H265 单帧）**：HEVC 编码的图片，可经 ffmpeg 抽帧为 JPEG，或保留 `.h265` 原始数据

### 数据库直接解密（本地快照）

微信 PC 4.0 的真实数据库（`message_0.db`、`hardlink.db`、`sns.db` 等）为 SQLCipher 加密。
本工具从 `wx_secrets.py` 读取**每个数据库的派生密钥**，解密真实目录
`xwechat_files/<wxid>_<pid>/db_storage/`。

- 密钥来源：`key_info.db` 中按账号派生的 18 个数据库密钥，填入本地 `wx_secrets.py` 的 `DB_KEYS`
- 自动识别：明文库直接打开，加密库自动 `PRAGMA key`

#### 派生密钥格式与内存提取

每个派生密钥为 96 位十六进制串，结构为 `key(32 字节) || salt(16 字节)`：

- 后 32 位 hex = **salt**，恒等于该加密库文件**前 16 字节**（可用于定位密钥对应的库）
- 前 64 位 hex = **SQLCipher 密钥本体**（`PRAGMA key = "x'<96hex>'"` 直接用整串）

**从微信进程内存提取**：微信运行时会以 `x'<96 hex 字符>'` 形式驻留全部派生密钥，
扫描进程可读内存即可批量抓取（对应 `cloudbak-we-sync` 的 `scan_db_keys_from_memory`）：

```python
# Linux: 扫描 /proc/<pid>/mem，匹配 x'<96 hex>' 模式
# 得到 96hex 后按 后32位=salt 与各库文件头匹配，即锁定每个库的密钥
```

```bash
# macOS（cloudbak-we-sync/find_image_key.c）
sudo ./find_image_key --deep
```

#### hardlink.db 派生密钥修复记录

`hardlink.db` 此前配置的派生密钥为**错误值**（salt 与实际文件头不符），导致 hardlink 库
打开/解密失败、图片与文件磁盘映射（`file_hardlink_info_v4` / `image_hardlink_info_v4`）失效。
2026-08-26 已从微信进程内存重新提取并修正 `wx_secrets.py` 中的对应 `DB_KEYS` 条目。

修正后密钥的 salt 段与 `hardlink.db` 文件头前 16 字节一致，已实测解密成功
（`dir2id`、`image_hardlink_info_v4`、`file_hardlink_info_v4` 均可正常读取）。
其余各库密钥也已与内存提取结果逐一核对，均正确。

#### 本地快照，不污染微信运行目录

所有脚本在访问微信真实数据库前，先经 `tempfile/decrypt_v4/local_db.py` 的
`local_copy()` 把目标库（连同 `-wal`/`-shm`）**复制到本地快照目录**
`tempfile/decrypt_v4/db_local/`，再在本地副本上打开/解密。

- 保证微信运行目录不被创建/修改 `-shm`、`-wal` 等文件
- 已复制过且源文件未变化时直接复用，避免重复拷贝大库（`message_0.db` ~115MB）
- 解密连接统一由 `local_db.open_local()` 处理（自动匹配密钥）
- 如需释放磁盘空间：删除 `tempfile/decrypt_v4/db_local/` 即可

### 缺失图片补全（V2 dat 生成 + CDN 下载）

`tempfile/decrypt_v4/image_downloader.py` 可补全聊天记录中缺失的图片：

1. **表情包/emoji**：消息 XML 自带 `cdnurl`（`wxapp.tc.qq.com/.../stodownload?m=<md5>&filekey=<DER>`），
   直接 HTTP 下载明文 PNG/GIF
2. **转 V2 dat**：`img_to_v2dat()` 将明文图片转为微信原生 V2 dat 格式
   （`07 08 56 32` 头 + AES-ECB 前 1024B + 剩余 XOR），与微信客户端生成的完全一致
3. **落盘**：写入真实 `msg/attach/<会话>/<月份>/Img/<md5>.dat`，并更新 `hardlink.db` 记录，
   使导出脚本/OCR 能直接识别

普通 C2C 聊天图片（`<img>` 消息）的 CDN URL 需微信运行时动态签发 `storeid`，
无法静态构造（测试返回 400）。仅当微信浏览到有新图片的会话时可配合
`url_capture.py` 扫描进程内存捕获 URL 补全。

### 朋友圈图片导出（SNS 缓存）

`tempfile/decrypt_v4/sns_export.py` 将微信朋友圈(SNS)缓存图片导出为可读文件：

1. **扫描缓存**：微信把朋友圈图片加密缓存在 `cache/<月份>/Sns/Img/`（V2 dat 格式）
2. **解密**：用 `media_tools.convert_v4` 还原为 JPEG
3. **分类**：按图片尺寸 `max(宽,高) >= 500px` 判断 原图/缩略图
4. **输出结构**：
   ```
   tempfile/sns_images/<月份>/Sns/Img/原图/<文件名>.jpg
   tempfile/sns_images/<月份>/Sns/Img/缩略图/<文件名>.jpg
   tempfile/sns_images/<月份>/Sns/Video/<hash>/...   # 视频原样保留
   ```

```bash
python3 tempfile/decrypt_v4/sns_export.py
```

> 说明：仅解密图片内容，文件名保持微信原始形式；Video/Temp 目录保留原 hash 结构。

### OCR / VLM / ASR

- **OCR**：RapidOCR（onnxruntime），内存处理，中文识别效果好
- **VLM**：Qwen2.5-VL-3B（4bit 量化），GPU 推理，为无文字图片生成中文描述
- **ASR**：SILK → PCM → MP3 → OpenAI Whisper（base）中文转写

### 增量更新

- `cache/state.json` 记录每个会话已处理到的 `max_local_id`
- 媒体结果缓存到 `cache/images/<md5>.{ocr,desc}`、`cache/voices/<id>.txt`
- 二次运行只处理新增消息，已缓存结果秒级复用

---

## 依赖安装

```bash
pip install --break-system-packages -r requirements.txt
```

依赖清单见 [`requirements.txt`](requirements.txt)，含导出/OCR/VLM/ASR 核心依赖及
mmtls 工具所需的可选依赖。

系统依赖：`ffmpeg`（wxgf 转 JPEG、语音转 MP3）、`sqlite3`

> VLM 模型 `Qwen/Qwen2.5-VL-3B-Instruct` 首次运行需下载约 7GB 到
> `~/.cache/huggingface`。之后以离线模式加载（`local_files_only`）。
> GTX 1650 4GB 显存需用 4bit 量化加载。

---

## 目录结构

```
.
├── run.sh                      # 一键导出脚本
├── main.py                     # 主程序（会话定位、消息解析、OCR/VLM/ASR、增量、数据库直解）
├── export_all.py               # 批量导出所有会话
├── export_sns.py               # 朋友圈(sns.db)解密导出（动态/点赞/评论 + 时间）
├── requirements.txt            # Python 依赖清单
├── wx_secrets.example.py       # 密钥配置模板（复制为 wx_secrets.py 并填写）
├── wx_secrets.py               # 🔒 本地密钥/账号配置（已 gitignore，不入库）
├── wx_secrets.env              # 🔒 run.sh 读取的 WECHAT_BASE（已 gitignore，不入库）
├── .gitignore                  # 隐私数据/密钥/缓存屏蔽列表
├── tempfile/decrypt_v4/
│   ├── media_tools.py          # 解密 + OCR + VLM + 会话定位工具库
│   ├── local_db.py             # 微信数据库本地快照（不污染微信运行目录）
│   ├── db_local/               # 本地数据库副本（可随时删除释放空间）
│   ├── image_downloader.py     # 缺失图片补全（表情包下载 + V2 dat 生成 + 落盘）
│   ├── url_capture.py          # 扫描微信进程内存捕获 CDN storeid URL
│   ├── sns_export.py           # 朋友圈缓存图片导出（解密+原图/缩略图分类）
│   ├── logging_config.py       # 标准化日志配置
│   ├── decrypt_v4.py           # 批量图片解密脚本
│   ├── cache/                  # 增量状态与媒体缓存
│   ├── out/                    # 解密后的图片（按月份组织）
│   ├── out_rec/                # 转发记录图片
│   └── fan_voice/              # 语音文件与转写结果
├── tempfile/sns_images/        # 朋友圈图片导出（<月份>/Sns/Img/{原图,缩略图}/）
├── mmtls_analysis/             # 🔒 mmtls 协议逆向工具集（须 root 运行）
│   ├── mmtls_decrypt.py        #   离线解密 pcap 中的 mmtls 应用数据
│   ├── mmtls_parser.py         #   mmtls 记录流解析（HTTP/裸TCP）
│   ├── pcap_mmtls.py           #   pcap 流重组 + 记录解析
│   └── tools/                  #   gdb 断点提取密钥/捕获明文（sudo 运行）
└── chat_history_*.txt          # 导出的聊天记录
```

---

## 常见问题

**Q: 为什么有些图片没有 OCR/描述？**
A: 这些图片本地没有下载文件（微信 PC 端只缓存部分图片）。只有本地存在 `.dat` 文件才能处理。

**Q: 怎么补全缺失的图片？**
A: 消息 XML 自带 URL 的表情包/emoji 可自动补全：
```bash
python3 tempfile/decrypt_v4/image_downloader.py <会话 hash>
```
普通 C2C 聊天图片（`<img>` 消息）的下载 URL 需微信运行时签发 `storeid`，
无法静态构造。可在微信浏览到有新图片的会话时用 `url_capture.py` 捕获：
```bash
python3 tempfile/decrypt_v4/url_capture.py
```

**Q: 为什么有些普通图片即使补全也无法下载？**
A: 普通聊天图片的 CDN 下载需要 `storeid`（微信用账号会话动态签发的临时鉴权参数），
它无法从消息 XML 静态构造或复用（测试返回 400）。只有微信自身浏览触发下载时，
配合 URL 捕获才能补全。已过期的旧图片（`media_expire_at`）微信自身也无法重新下载。

**Q: 数据库解密失败？**
A: 确认 `key_info.db` 中的派生密钥与当前账号匹配。若微信重新登录，密钥可能变化，
需重新从 `login/wxid_*/key_info.db` 提取密钥更新到 `wx_secrets.py` 的 `DB_KEYS`。
也可直接从微信进程内存扫描 `x'<96 hex>'` 模式批量抓取当前派生密钥（见上文
"派生密钥格式与内存提取"），并按 salt 与库文件头匹配后更新。
历史坑：`hardlink.db` 曾因密钥 salt 与文件头不符而解密失败，2026-08-26 已修正。

**Q: 运行 mmtls 工具报权限错误？**
A: `mmtls_analysis/` 下的抓包（tcpdump）、gdb 断点提取密钥/捕获明文**必须用 root**：
```bash
sudo bash mmtls_analysis/tools/gdb_extract_key.sh
sudo bash mmtls_analysis/tools/gdb_capture_plaintext.sh
sudo python3 -u mmtls_analysis/tools/fresh_start.py
```
脚本内置 `id -u`/`geteuid` 校验，非 root 会直接报错退出。其余导出/解密脚本普通用户即可运行。

**Q: 为什么纯照片没有描述？**
A: 纯照片无文字，OCR 提取不到。需要开启视觉描述：`WECHAT_VLM=1 ./run.sh`。

**Q: 运行报 CUDA OOM？**
A: GTX 1650 显存仅 4GB，需确保没有残留的 python 进程占用显存（`nvidia-smi` 检查），且 VLM 用 4bit 量化加载。

**Q: 增量更新是什么意思？**
A: 记录每个会话已处理到的消息位置，二次运行只处理新增消息；已生成的 OCR/描述/转写结果缓存复用，秒级完成。
