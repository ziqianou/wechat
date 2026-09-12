# WeChat mmtls 逆向工具集

本目录包含整个逆向会话的脚本。核心解密参数见 `../README.md` §7.5。

## 解密 / 解析（主交付物）

| 工具 | 用途 |
|------|------|
| `../mmtls_decrypt.py` | **离线解密** pcap：`python3 mmtls_decrypt.py <pcap> <IP> [key] [iv]` |
| `../mmtls_parser.py` | 解析 mmtls 记录流（HTTP/裸TCP） |
| `../pcap_mmtls.py` | pcap 流重组 + 记录解析 |

## gdb 动态工具（安全，零代码修改）

frida 内联挂钩在本构建上崩溃（5 次 SIGSEGV@0）；gdb 硬件断点（DR 寄存器）全程微信零崩溃。

| 工具 | 用途 |
|------|------|
| `gdb_capture_plaintext.sh` | 捕获 mmtls 应用数据**明文**（断 0x6fc5960, rdx==0x17） |
| `gdb_extract_key.sh` | 提取 **key + IV**（断 0x6fa9010, cobj+0x50/+0x30） |
| `fresh_start.py` | 一键：启动抓包→等微信→识别握手会话→扫密钥 |
| `fresh_extract.py` | 从 pcap 提取含握手的新鲜会话记录 |

## 静态 RE 辅助

| 工具 | 用途 |
|------|------|
| `disasm.py` | capstone 反汇编窗口（`python3 disasm.py <va>:<窗口>`） |
| `find_xrefs.py` | 定位字符串的代码交叉引用（RIP-relative） |
| `find_encrypt.py` | 扫描堆解算 cipher_state 相对虚表（vtable[2]=Encrypt） |
| `find_cipher.py` | 扫描带 vtable+密钥材料的 cipher_state 候选 |
| `mdparse.py` | 解析微信崩溃 minidump（异常地址/线程） |

## 被动内存扫描（早期方案，已弃用于解密）

| 工具 | 说明 |
|------|------|
| `scan_key.py` | 多进程堆扫描 ChaCha20/AES-GCM 密钥（AEAD tag 验证） |
| `memscan.py` | process_vm_readv 基础内存读取 |

> 被动扫描最终失败原因：微信对 cipher_state 用 relative-vtable + 封装指针，
> Key/IV 动态存储且被媒体/压缩缓存干扰，假阳性高。改用 gdb 硬件断点直接提取。

## 关键地址（模块内 RVA，版本 4.1.8）

```
mmtls Encrypt (vtable[2])     0x6f4bbd0
pack 记录                     0x6fc41b0   (esi=0x17 应用数据)
记录封装                       0x6fc5960   (r8=明文, rdx=type)
记录写入                       0x6fc6000   (aad 构造点)
cipher op (key/IV 读取)        0x6fa9010   (cobj+0x50=key, +0x30=IV)
AAD 构造                       0x6fa9a0b   ([8B seq][5B 记录头])
setiv (nonce)                  0x6fa99c0   (0x711d270)
BoringSSL AES-GCM              0x711dxxx
```
