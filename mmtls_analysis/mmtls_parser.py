#!/usr/bin/env python3
"""
WeChat mmtls protocol parser.

Decoded record framing (WeChat 4.1.8 Linux, mars framework):
    +------+-----------+----------+------------------------+
    | type |  version  | length   | body                   |
    | 1B   |  2B f1 04 | 2B BE    | length bytes           |
    +------+-----------+----------+------------------------+

    type: 0x16 = handshake, 0x17 = application data,
          0x15 = session/notify, 0x14 = change cipher spec (TLS-like)

The version bytes on the wire are always `f1 04`.
Records appear either raw on TCP (long connection, port 80) or as the
body of HTTP/1.1 responses / the HTTP request (shortlink, mmtls-over-http).
"""
import sys, struct

MMTLS_VERSION = bytes.fromhex("f104")

def hexdump(data, base=0):
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        h = " ".join(f"{b:02x}" for b in chunk[:8]) + "  " + " ".join(f"{b:02x}" for b in chunk[8:])
        a = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"{base+i:08x}  {h:<46s}  {a}")

def parse_records(buf, name=""):
    """Split a buffer into mmtls records using the f1 04 framing."""
    off = 0
    recs = []
    while off < len(buf):
        if off + 5 > len(buf):
            print(f"  [truncated header at {off}]")
            break
        typ, ver, ln = buf[off], buf[off+1:off+3], struct.unpack(">H", buf[off+3:off+5])[0]
        if ver != MMTLS_VERSION:
            # not a record boundary; try to resync
            print(f"  [!!] bad version {ver.hex()} at {off}, resyncing...")
            idx = buf.find(MMTLS_VERSION, off)
            if idx == -1:
                break
            off = idx - 1
            continue
        if off + 5 + ln > len(buf):
            print(f"  [truncated body at {off} len={ln}]")
            break
        body = buf[off+5:off+5+ln]
        tname = {0x16: "handshake", 0x17: "appdata", 0x15: "session/notify",
                 0x14: "ccs", 0x18: "heartbeat"}.get(typ, "unknown")
        recs.append((typ, ln, body))
        print(f"  {name} @{off:5d}  type=0x{typ:02x} ({tname})  len={ln}")
        off += 5 + ln
    return recs

def parse_handshake(body):
    """Parse a handshake record body (best effort)."""
    if len(body) >= 4:
        n = struct.unpack(">I", body[:4])[0]
        print(f"      handshake: length={n}")
    if len(body) >= 5:
        print(f"      handshake: type=0x{body[4]:02x}")
    rest = body[5:]
    if len(rest) >= 32:
        print(f"      random: {rest[:32].hex()}")
    if len(rest) > 32:
        print(f"      extra ({len(rest)-32} bytes): {rest[32:].hex()}")

def parse_http(data):
    """Split an HTTP response/request and print headers + mmtls body records."""
    try:
        head, _, body = data.partition(b"\r\n\r\n")
    except Exception:
        head, body = data, b""
    cl = 0
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            cl = int(line.split(b":")[1].strip())
    print("    HTTP head:")
    for line in head.split(b"\r\n"):
        print(f"      {line.decode('latin1')}")
    print(f"    HTTP body ({len(body)} bytes, content-length={cl}):")
    parse_records(body, "body")
    return body

def main():
    import binascii
    mode = sys.argv[1] if len(sys.argv) > 1 else "http"
    data = sys.stdin.buffer.read()
    if mode == "http":
        parse_http(data)
    else:
        parse_records(data, "raw")

if __name__ == "__main__":
    main()
