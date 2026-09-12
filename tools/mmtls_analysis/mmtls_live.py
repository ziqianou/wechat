#!/usr/bin/env python3
"""
微信 mmtls 实时抓包 + 动态解包输出
- 自动识别微信服务器 IP（指定或自动）
- 解密失败时自动用 gdb 硬件断点提取新会话 key（无需手动提供）
- 解析并打印明文结构 / 可读字符串 / URI

用法:
  sudo python3 -u mmtls_live.py                # 自动识别 IP + 自动提取 key
  sudo python3 -u mmtls_live.py <服务器IP>      # 指定 IP

依赖: python3-cryptography, tcpdump, gdb（自动提取 key 时）
"""
import subprocess, struct, time, os, sys, re, json

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PCAP = "/tmp/opencode/live_decrypt.pcap"
FILTER_PORTS = "tcp port 80 or tcp port 443 or tcp port 8080"
GDB_SCRIPT = "/tmp/opencode/live_extract.gdb"

class LiveDecoder:
    def __init__(self):
        self.k1 = self.i1 = self.k2 = self.i2 = None
        self.seq = {}
        self.buffers = {}
        self.fail_count = 0
        self._last = set()

    def set_keys(self, k1, i1, k2, i2):
        self.k1 = bytes.fromhex(k1); self.i1 = bytes.fromhex(i1)
        self.k2 = bytes.fromhex(k2); self.i2 = bytes.fromhex(i2)
        self.seq.clear()
        print(f"[+] key1(C->S)={k1[:16]}... key2(S->C)={k2[:16]}...", flush=True)

    def decrypt(self, rec, seq, dirC):
        key = self.k1 if dirC else self.k2
        iv = self.i1 if dirC else self.i2
        hdr, body = rec[:5], rec[5:]
        aad = seq.to_bytes(8, "big") + hdr
        nonce = bytes([iv[j] ^ (seq.to_bytes(12, "big")[j]) for j in range(12)])
        return AESGCM(key).decrypt(nonce, body, aad)

    def parse_link(self, data, lt):
        if lt == 276:  # SLL2
            if len(data) < 30: return None
            ip = data[20:]
            if ip[0] >> 4 != 4 or ip[9] != 6: return None
            tcp = ip[(ip[0] & 0x0f) * 4:]
            src, dst = ip[12:16], ip[16:20]
        elif lt == 1:  # EN10MB
            eth = data[14:]
            if len(eth) < 20 or eth[0] >> 4 != 4 or eth[9] != 6: return None
            tcp = eth[(eth[0] & 0x0f) * 4:]
            src, dst = eth[12:16], eth[16:20]
        else:
            return None
        if len(tcp) < 20: return None
        sport, dport = struct.unpack(">HH", tcp[0:4])
        off = (tcp[12] >> 4) * 4
        s = ".".join(map(str, src)); d = ".".join(map(str, dst))
        return (s, sport, d, dport, sport > dport), tcp[off:]

    def show_plain(self, pt, dirC, dedup_key):
        # 只输出"有意义"内容：URI 或真实文本；长连接 mars 二进制一律静默
        uri = re.search(rb"/cgi-bin/[a-z0-9/_.-]+", pt)
        # 真实文本：>=8 字符且字母占比高
        real = []
        for g in re.finditer(rb"[a-zA-Z][a-zA-Z0-9._/-]{7,}", pt):
            s = g.group().decode('latin1')
            if sum(c.isalpha() for c in s)/len(s) > 0.7:
                real.append(s)
        if not uri and not real:
            return
        if uri:
            print(f"[HTTP] {uri.group().decode()}  ({len(pt)}B)")
            try:
                print(f"   {pt[:160].decode('latin1','replace')}")
            except Exception: pass
        else:
            print(f"[TEXT] {' | '.join(real[:5])}")

    def feed(self, conn, payload, target_ip):
        buf = self.buffers.setdefault(conn, bytearray())
        buf.extend(payload)
        while len(buf) >= 5:
            typ, ver, ln = buf[0], bytes(buf[1:3]), struct.unpack(">H", bytes(buf[3:5]))[0]
            if ver != b"\xf1\x04":
                buf.clear(); break
            if len(buf) < 5 + ln:
                break
            rec = bytes(buf[:5 + ln]); del buf[:5 + ln]
            if typ != 0x17:
                continue
            dirC = conn[4]
            if self.k1 is None:
                continue
            st = self.seq.get(conn, [0, 0])
            s = st[0] if dirC else st[1]
            pt = None
            for cand in range(s, s + 8):
                try:
                    pt = self.decrypt(rec, cand, dirC)
                    st[0 if dirC else 1] = cand + 1
                    self.seq[conn] = st
                    break
                except Exception:
                    pass
            if pt is None:
                for cand in range(0, 200000):
                    try:
                        pt = self.decrypt(rec, cand, dirC)
                        st[0 if dirC else 1] = cand + 1
                        self.seq[conn] = st
                        break
                    except Exception:
                        pass
            if pt is None:
                self.fail_count += 1
                if self.fail_count >= 2 and target_ip in conn:
                    print(f"\n[!] 会话 key 已变化（DECRYPT-FAIL）—— 正在自动提取新 key...", flush=True)
                    self.fail_count = 0
                    raise KeyError("session changed")
                continue
            self.show_plain(pt, dirC, (dirC, conn[0], len(pt)))

def extract_keys_via_gdb(pid, base):
    """Run gdb to extract both keys from the cipher object. Returns dict or None."""
    target = hex(int(base, 16) + 0x6fa9010)
    script = f"""set pagination off
set confirm off
set auto-solib-add off
hbreak *{target}
continue
set $cobj = *(void**)($rdi+8)
set $k1 = *(void**)($cobj+0x50)
set $n1 = *(void**)($cobj+0x30)
set $k2 = *(void**)($cobj+0xc0)
set $n2 = *(void**)($cobj+0xa0)
dump binary memory /tmp/opencode/lk1.bin $k1 $k1+0x10
dump binary memory /tmp/opencode/ln1.bin $n1 $n1+0x0c
dump binary memory /tmp/opencode/lk2.bin $k2 $k2+0x10
dump binary memory /tmp/opencode/ln2.bin $n2 $n2+0x0c
detach
quit
"""
    open(GDB_SCRIPT, "w").write(script)
    print("[*] 请发送一条消息以触发 key 提取...", flush=True)
    subprocess.run(f"gdb -q -p {pid} -nx -x {GDB_SCRIPT} >/dev/null 2>&1", shell=True, timeout=60)
    try:
        k1 = open("/tmp/opencode/lk1.bin", "rb").read().hex()
        n1 = open("/tmp/opencode/ln1.bin", "rb").read().hex()
        k2 = open("/tmp/opencode/lk2.bin", "rb").read().hex()
        n2 = open("/tmp/opencode/ln2.bin", "rb").read().hex()
        return dict(k1=k1, i1=n1, k2=k2, i2=n2)
    except Exception:
        return None

def start_tcpdump():
    subprocess.run("pkill -f 'tcpdump.*live_decrypt' 2>/dev/null", shell=True)
    try: os.remove(PCAP)
    except Exception: pass
    subprocess.Popen(f"tcpdump -i any -nn -w {PCAP} {FILTER_PORTS} >/dev/null 2>&1",
                     shell=True, start_new_session=True)
    time.sleep(2)

def get_wechat():
    pid = None
    for p in os.popen("pgrep -x wechat").read().split():
        try:
            if open(f"/proc/{p}/comm").read().strip() == "wechat":
                pid = int(p); break
        except Exception: pass
    base = None
    if pid:
        for line in open(f"/proc/{pid}/maps"):
            pp = line.split()
            if len(pp) >= 5 and pp[2] == "00000000" and pp[3] == "08:13":
                base = pp[0].split("-")[0]
                break
    return pid, base

def main():
    args = sys.argv[1:]
    target_ip = args[0] if args else None
    dec = LiveDecoder()
    # 自动提取 key（gdb 硬件断点）
    pid, base = get_wechat()
    if pid is None:
        print("[!] 未检测到微信进程", flush=True); return
    dec.set_keys(
        "181a2fc86c40946b33690cfa922dbbd0", "15b41b09b48cd8cd0e7a3777",
        "fefede1671d05af581500a2387e35cbb", "685cd30d7fe27f0bda700127")
    start_tcpdump()
    print(f"[*] tcpdump -> {PCAP}  监听{'服务器'+target_ip if target_ip else '所有mmtls'} 流量", flush=True)
    print("[*] Ctrl+C 退出", flush=True)

    for _ in range(30):
        try:
            f = open(PCAP, "rb"); hdr = f.read(24)
            if len(hdr) >= 24: break
        except Exception: pass
        time.sleep(0.5)
    if not hdr or len(hdr) < 24:
        print("[!] pcap init fail"); return
    lt = struct.unpack("<I", hdr[20:24])[0]
    while True:
        pos = os.path.getsize(PCAP)
        f.seek(24)
        while True:
            rh = f.read(16)
            if len(rh) < 16:
                f.seek(pos); break
            cap = struct.unpack("<I", rh[8:12])[0]
            data = f.read(cap)
            if len(data) < cap:
                f.seek(pos); break
            r = dec.parse_link(data, lt)
            if r:
                conn, payload = r
                if payload:

                    try:
                        dec.feed(conn, payload, target_ip or conn[0])
                    except KeyError:
                        # 重新提取 key
                        pid, base = get_wechat()
                        if pid:
                            keys = extract_keys_via_gdb(pid, base)
                            if keys:
                                dec.set_keys(**keys)
                        dec.fail_count = 0
        time.sleep(0.3)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        subprocess.run("pkill -f 'tcpdump.*live_decrypt' 2>/dev/null", shell=True)
        print("\n[*] 已停止")
