# 微信安卓版 CDN 下载链接动态研究（frida + root）

目标机：Android 16 / 微信 8.0.77 (versionCode 3160)
手段：frida 只读 hook libc `send/sendto/write/writev` + libssl `SSL_write`，
扫描出站 HTTP 请求行，捕获微信运行时生成的 CDN 下载 URL。

**storeid / filekey 生成结构的完整逆向见 [storeid_filekey_analysis.md](storeid_filekey_analysis.md)**。

## 1. 结论摘要

- 微信安卓 8.0.77 的 **C2C 聊天图片下载** 走 CDN 的 `stodownload` 接口，
  host 为 `vweixinf.tc.qq.com`，且**明文 HTTP（端口 80）**（`sendto` 直发，
  未走 TLS）。
- 下载 URL 由 **Java 层拼接**（捕获到 `http://vweixinf.tc.qq.com/...` 的构造
  现场），核心鉴权参数 `storeid` 由服务器动态签发，**无法静态构造**。
- 头像/视频号（`wx.qlogo.cn` /finderhead）、资源更新（`dldir1.qq.com`）
  走 HTTPS（`SSL_write`）；短视频先经本地代理 `127.0.0.1:12658`
  `/proxy/<play_id>/1/vod.mp4?token=...` 再转发。

## 2. C2C 图片 stodownload URL 结构

实测抓到的完整请求（原图，鉴权值已脱敏）：

```
GET /110/20402/stodownload?m=<32-hex md5>
    &filekey=<DER hex，含内嵌 md5>
    &hy=<region>
    &storeid=<服务器动态签发 token>
    &ef=2
    &bizid=1022
    &picformat=60.png
    &ftype=2 HTTP/1.1
Accept: */*
Connection: Keep-Alive
Content-Type: application/octet-stream
Host: vweixinf.tc.qq.com
User-Agent: MicroMessenger Client
X-Client-Os: android-36
X-Client-Version: 28004D30
X-Reserve: <反爬签名>
```

缩略图版本（Java 层构造现场，`ef=1`、`/110/20401/`，无 `picformat`）：

```
http://vweixinf.tc.qq.com/110/20401/stodownload?m=<32-hex md5>
    &filekey=<DER hex>
    &hy=<region>
    &storeid=<服务器动态签发 token>
    &ef=1&bizid=1022&ftype=2
```

### 参数含义

| 参数 | 含义 | 备注 |
|---|---|---|
| `m` | 图片 md5（32 hex） | 用于定位文件 |
| `filekey` | DER 编码结构（hex） | 见下 |
| `hy` | 分区域标记 | 如 `SH` |
| `storeid` | 服务器动态签发签名 | **有效期内可复用下载**，过期返回 400 |
| `ef` | 1=缩略图 / 2=原图 | 对应 `/110/20401/` 与 `/110/20402/` |
| `bizid` | 业务号 | C2C 图片为 1022 |
| `picformat` | 目标尺寸描述 | 如 `60.png`（60×60 缩略图），原图请求不带 |
| `ftype` | 文件类型 | 2 |

### filekey DER 结构（内嵌 md5 证明）

```
SEQUENCE (68B)
 ├─ INTEGER 1                          # 版本
 ├─ OCTET STRING (48B)                 # 内嵌 DER
 │   └─ SEQUENCE (46B)
 │       ├─ INTEGER 110                # appid
 │       ├─ OCTET STRING "SH"          # region
 │       └─ OCTET STRING (32B)         # 图片 md5 的 ASCII（与 m= 一致）
 └─ OCTET STRING (13B)                 # 00 00 00 04 "btfs" 00 00 00 01 32
```

`filekey` 不含 AES 密钥，仅是"持有该文件 md5"的凭证；下载返回的
payload 为 **AES 加密**（熵 7.97），解密密钥（aekey）在 CDN 控制信息
（ctrlinfo / 消息 XML）中，需另行提取（见 §5）。

## 3. 捕获的其它 CDN 类 URL

```
GET /finderhead/ver_1/<long-base64-urlsafe>/132 HTTP/1.1      Host: wx.qlogo.cn
GET /weixin/checkresupdate/<hash>.png                          Host: dldir1.qq.com
GET /proxy/<play_id>/1/vod.mp4?play_id=..&clip_id=1&force_online=0&token=<uuid>  Host: 127.0.0.1:12658
```

- `/finderhead/ver_1/...`：视频号/头像，参数结尾 `132` 是图片尺寸档位。
- `/proxy/.../vod.mp4?token=`：短视频经本地代理端口 12658，token 为一次性 UUID。

## 4. 复现步骤

```bash
# 手机端：启动 frida-server（root）
adb shell su -c 'nohup /data/local/tmp/frida-server &'

# 电脑端：运行捕获器（默认按包名 attach，可传 pid）
python3 capture_cdn.py 120 captured.json

# 手机端：打开微信，进入含图片的聊天 → 上下滑动/点开大图/刷朋友圈
# 结束自动保存 captured.json（含完整请求头）
```

注意：微信有反调试，frida-server 可能被杀；被杀后重启 frida-server 重跑，
一次捕获内不要在手机做无关操作。若仍不稳定，可给 `Interceptor.attach`
加 `onEnter` 异常保护或改用 spawn（`frida.get_usb_device().spawn`）注入。

## 5. 下一步（可选）

1. **解密 payload**：抓 `stodownload` 返回的密文 + 提取 aekey
   （hook `SSL_read`/内存扫描 `aekey` 字段，或解析消息 XML/ctrlinfo）
   → 完整实现"URL 捕获 + 下载 + 解密补全缺失图片"。
2. **storeid 有效期测试**：重复下载已捕获 URL，确认 TTL（观察 400 出现时间）。
3. **原生 CDN 函数定位**：`libwechatmm.so` 中已定位 4 处关键 xref
   （`0x1f4f0c` ctrlinfo、`0x39e300` cdnurl 加 query、`0x250efc` POST 拼装），
   可 hook 这些函数直接从参数读 URL/aekey，不依赖 socket 扫描。
