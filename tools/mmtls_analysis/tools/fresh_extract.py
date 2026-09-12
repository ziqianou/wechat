import sys, struct, scan_key
pcap=sys.argv[1]
hdr=open(pcap,'rb').read(24)
if len(hdr)<24: print("empty"); sys.exit()
lt=struct.unpack('<I',hdr[20:24])[0]
conns={}
with open(pcap,'rb') as f:
    f.seek(24)
    while True:
        rh=f.read(16)
        if len(rh)<16: break
        cap=struct.unpack('<I',rh[8:12])[0]
        data=f.read(cap)
        if len(data)<cap: break
        r=scan_key.parse_packet(data,lt)
        if not r: continue
        (s,sp,d,dp),payload=r
        if not payload: continue
        key=(s,sp,d,dp)
        conns.setdefault(key,bytearray()).extend(payload)
found=0
for (s,sp,d,dp),payload in conns.items():
    if sp>dp: server=(d,dp)
    else: server=(s,sp)
    # parse records, track handshake + first appdata
    off=0; has_hs=False; appdata=[]
    while off+5<=len(payload):
        typ,ver,ln=payload[off],payload[off+1:off+3],struct.unpack('>H',payload[off+3:off+5])[0]
        if ver!=b'\xf1\x04': break
        if off+5+ln>len(payload): break
        if typ in (0x16,0x19): has_hs=True
        if typ==0x17: appdata.append(payload[off:off+5+ln])
        off+=5+ln
    if has_hs and appdata:
        found+=1
        print(f"--- fresh session {s}:{sp}->{d}:{dp} handshake=True appdata_records={len(appdata)}")
        for a in appdata[:4]:
            print(f"    appdata hdr={a[:5].hex()} len={len(a)}")
if not found:
    print("no fresh sessions with handshake yet")
