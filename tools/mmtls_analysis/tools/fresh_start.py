#!/usr/bin/env python3
"""
微信 mmtls 全流程一键分析脚本。

用法:  sudo python3 -u fresh_start.py
流程:
  1. 停止旧抓包/扫描, 清空旧 pcap
  2. 启动 tcpdump 抓取全部 TCP 流量 (-i any)
  3. 提示你启动微信 (从零启动)
  4. 自动检测微信进程 PID
  5. 捕获"带握手的全新会话" (握手 0x19/0x16 后紧跟应用数据 0x17,
     seq 从 0 开始), 立即跑 phase-1 内存密钥扫描 (seq 0..15, 密钥仍在内存)
  6. 周期重扫, 直到找到密钥或超时
"""
import subprocess, time, os, sys, struct, glob

# root 权限检查（tcpdump / 读微信进程内存 / gdb attach 均需 root）
if os.geteuid() != 0:
    print("[错误] 需要 root 权限运行：sudo python3 -u fresh_start.py", file=sys.stderr)
    sys.exit(1)

PCAP = "/tmp/opencode/captures/start_all.pcap"
OUT = "/tmp/opencode/start_all.log"
MIN_RECS = 2          # 找到几条含握手会话的应用数据后开始扫描
SCAN_SECS = 150       # 每次扫描窗口时长
TOTAL = 900           # 总监控时长
CAPS = "/tmp/opencode"

def log(msg):
    line = f"[{time.strftime('%H:%M:%S')}] {msg}"
    print(line, flush=True)
    with open(OUT, "a") as f:
        f.write(line + "\n")

def sh(cmd, **kw):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=20, **kw)

def stop_old():
    # stop tcpdump units + scans
    for unit in sh("systemctl list-units --type=service --no-legend 2>/dev/null | grep -oE 'capture[0-9]|scan[A-Za-z0-9]+' | sort -u").stdout.split():
        sh(f"systemctl stop {unit}.service 2>/dev/null")
    for pat in ("tcpdump -i", "scan_key.py", "reconnect_watch"):
        for pid in sh(f"pgrep -f '{pat}'").stdout.split():
            try: os.kill(int(pid), 15)
            except Exception: pass
    time.sleep(1)
    for f in glob.glob(CAPS + "/captures/start_*.pcap"):
        try: os.remove(f)
        except Exception: pass

def get_pid():
    for p in sh("pgrep -f '/opt/wechat/wechat'").stdout.split():
        # ensure it's the main binary process
        try:
            with open(f"/proc/{p}/comm") as f:
                if f.read().strip() == "wechat":
                    return int(p)
        except Exception: pass
    return None

def parse_pcap():
    """Return {conn_key: bytearray} of mmtls records per connection."""
    import scan_key
    try:
        hdr = open(PCAP, "rb").read(24)
    except Exception:
        return {}
    if len(hdr) < 24: return {}
    lt = struct.unpack("<I", hdr[20:24])[0]
    conns = {}
    with open(PCAP, "rb") as f:
        f.seek(24)
        while True:
            rh = f.read(16)
            if len(rh) < 16: break
            cap = struct.unpack("<I", rh[8:12])[0]
            data = f.read(cap)
            if len(data) < cap: break
            r = scan_key.parse_packet(data, lt)
            if not r: continue
            (s, sp, d, dp), payload = r
            if not payload: continue
            key = (s, sp, d, dp)
            conns.setdefault(key, bytearray()).extend(payload)
    return conns

def fresh_records():
    """Find connections WITH a handshake (0x19/0x16) and return their appdata records."""
    import scan_key
    conns = parse_pcap()
    out = []
    for (s, sp, d, dp), payload in conns.items():
        off = 0; has_hs = False; appdata = []
        while off + 5 <= len(payload):
            typ, ver, ln = payload[off], payload[off+1:off+3], struct.unpack(">H", payload[off+3:off+5])[0]
            if ver != b"\xf1\x04": break
            if off + 5 + ln > len(payload): break
            if typ in (0x16, 0x19): has_hs = True
            if typ == 0x17: appdata.append(payload[off:off+5+ln])
            off += 5 + ln
        if has_hs and appdata:
            log(f"  fresh session {s}:{sp}<->{d}:{dp} appdata={len(appdata)}")
            out.extend((True, r) for r in appdata)
    return out

def run_scan(pid, records):
    import scan_key
    if not records: return
    log(f"[scan] phase1 seq0..15 ciphers=all regions=all, {len(records)} records")
    # snapshot records for the worker
    os.environ["PHASE"] = "1"
    os.environ["MAXSEQ"] = "512"
    os.environ["SCAN16"] = "1"
    scan_key.CUR_MAXSEQ = 16
    t0 = time.time()
    found = None
    # run via a small driver so multiprocessing works cleanly
    import multiprocessing as mp
    from multiprocessing import Pool
    regions = scan_key.get_regions(pid)
    tasks = [(pid, s, e, records[-60:]) for s, e, _ in regions]
    nproc = min(os.cpu_count() or 4, 12)
    with Pool(nproc) as pool:
        for res in pool.imap_unordered(scan_key.scan_region, tasks, chunksize=1):
            if res:
                addr, key, hits, n_cand = res
                k, isc, seq, aad_ok, mode, cname, pt = hits[0]
                log(f"[FOUND] addr={addr:#x} cipher={cname} seq={seq} aad_header={aad_ok} mode={mode}")
                log(f"   key={key.hex()}")
                log(f"   pt ={pt[:64].hex()} [{''.join(chr(c) if 32<=c<127 else '.' for c in pt[:64])}]")
                pool.terminate()
                return True
            if pool._processes and False:
                pass
    log(f"[scan] done, no key, {time.time()-t0:.0f}s")
    return False

def main():
    log("===== 微信 mmtls 一键分析 =====")
    stop_old()
    log("[1/5] 启动抓包 (全部 TCP, -i any)...")
    sh(f"rm -f {PCAP}")
    sh(f"setsid tcpdump -i any -nn -w {PCAP} 'tcp' >/dev/null 2>&1 &")
    time.sleep(2)
    log("[2/5] 请现在【启动微信】(从零开始). 等待进程出现...")
    pid = None
    for _ in range(60):
        pid = get_pid()
        if pid: break
        time.sleep(2)
    if not pid:
        log("[!] 未检测到微信进程, 继续等待流量...")
    else:
        log(f"[3/5] 微信进程 PID={pid}")
    t_end = time.time() + TOTAL
    last_scanned_n = 0
    last_n = -1
    while time.time() < t_end:
        recs = fresh_records()
        pid = pid or get_pid()
        n = len(recs)
        if n != last_n:
            last_n = n
            log(f"[wait] fresh-session appdata records: {n} (pid={pid})")
        # re-scan when fresh records grow (more chances to hit live session key)
        if recs and pid and n > last_scanned_n + 2:
            last_scanned_n = n
            try:
                ok = run_scan(pid, recs)
                if ok:
                    log("[DONE] 找到密钥!")
                    break
            except Exception as e:
                log(f"[!] scan error: {e}")
            time.sleep(90)  # cooldown between scans
        time.sleep(6)
    sh("pkill -f 'tcpdump -i any -nn -w /tmp/opencode/captures/start_all' 2>/dev/null")
    log("===== 结束 =====")

if __name__ == "__main__":
    main()
