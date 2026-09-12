"""综合捕获：stodownload URL + ctrlinfo（storeid 来源）+ CreateFileKey/CreateAeskey。

用法：python3 capture_all.py <pid> <秒数> <输出json>
"""
import frida
import sys
import time
import json

JS = r"""
const MM = Process.getModuleByName('libwechatmm.so');

function readStdString(ptr) {
    if (ptr.isNull()) return '<null>';
    try {
        var hdr = ptr.readU8();
        var isHeap = (hdr & 1) === 1;
        var len = hdr >> 1, dataPtr;
        if (isHeap) { len = ptr.add(8).readU64().toNumber(); dataPtr = ptr.add(16).readPointer(); }
        else dataPtr = ptr.add(1);
        if (len > 2048) return '<big:%d>' % len;
        return dataPtr.readUtf8String(len);
    } catch (e) { return '<err>'; }
}
function readCString(ptr, n) { try { return ptr.readUtf8String(n || 256); } catch (e) { return '<err>'; } }
function readAscii(ptr, n) {
    try {
        var arr = new Uint8Array(ptr.readByteArray(n));
        var s = '';
        for (var i = 0; i < arr.length; i++) {
            var b = arr[i]; if (b === 0) break;
            s += (b >= 0x20 && b < 0x7f) ? String.fromCharCode(b) : '.';
        }
        return s;
    } catch (e) { return null; }
}
function moduleOf(a) { var m = Process.findModuleByAddress(a); return m ? m.name : '?'; }

// ---------- 1. socket stodownload 捕获 ----------
const CDN_RE = /(stodownload|storeid|filekey=)/i;
const HTTP_LINE_RE = /(?:GET|POST)\s+(\S+)\s+HTTP\/1\.[01]/;
function onSend(which, fd, buf, len) {
    if (len <= 0 || len > 65536) return;
    var s = readAscii(buf, Math.min(len, 3000));
    if (!s || !CDN_RE.test(s)) return;
    var m = HTTP_LINE_RE.exec(s);
    if (!m) return;
    send({t: 'url', ts: Date.now(), host: (s.match(/[Hh]ost:\s*(\S+)/) || [,'?'])[1], path: m[1], raw: s.slice(0, 1500)});
}
function hookSend(mod, sym, which) {
    var p = Process.findModuleByName(mod).getExportByName(sym);
    Interceptor.attach(p, {
        onEnter: function (a) {
            var buf, len, fd = -1;
            if (which === 'ssl') { buf = a[1]; len = a[2].toInt32(); }
            else { fd = a[0].toInt32(); buf = a[1]; len = a[2].toInt32(); }
            onSend.call(this, which, fd, buf, len);
        }
    });
    send({t: 'ok', s: 'socket ' + sym});
}

// ---------- 2. ctrlinfo 日志调用点 ----------
Interceptor.attach(MM.base.add(0x1f4f38), {
    onEnter: function (a) {
        var fmt = readCString(a[1]);
        if (fmt.indexOf('ctrlinfo') === -1) return;
        var arr = a[2], items = [];
        for (var i = 0; i < 14; i++) items.push(readStdString(arr.add(i * 8).readPointer()));
        send({t: 'ctrlinfo', ts: Date.now(), items: items});
    }
});

// ---------- 3. 密钥生成 ----------
function hookRet(addr, name) {
    Interceptor.attach(addr, {
        onEnter: function () { this.slot = this.context.x8; },
        onLeave: function () { send({t: 'gen', name: name, v: readStdString(this.slot)}); }
    });
}
setTimeout(function () {
    MM.enumerateExports().forEach(function (e) {
        if (e.name.indexOf('CreateFileKey') !== -1 || e.name.indexOf('CreateAeskey') !== -1) {
            hookRet(e.address, e.name);
            send({t: 'ok', s: 'keygen ' + e.name});
        }
    });
    hookSend('libc.so', 'sendto', 'sendto');
    hookSend('libc.so', 'send', 'send');
    hookSend('libssl.so', 'SSL_write', 'ssl');
    send({t: 'ready'});
}, 100);
"""


def main():
    pid = int(sys.argv[1])
    duration = int(sys.argv[2]) if len(sys.argv) > 2 else 120
    outfile = sys.argv[3] if len(sys.argv) > 3 else 'capture_all.json'
    out = []

    def on_message(msg, data):
        if msg['type'] != 'send':
            print(msg); return
        p = msg['payload']
        if not isinstance(p, dict): print(p); return
        t = p.get('t')
        if t == 'ready':
            print('[*] ready, browse FRESH images now (open not-recently-viewed pics)')
        elif t == 'ok':
            print('[+]', p['s'])
        elif t == 'url':
            out.append(p)
            print('[*] stodownload %s %s' % (p['host'], p['path'][:160]))
        elif t == 'ctrlinfo':
            out.append(p)
            print('\n===== CTRLINFO =====')
            names = ['filekey', 'url', 'bakurl', 'quic', 'pcdnurl', 'net', 'timestamp',
                     'useugc', 'usepcdn', 'beginpcdn', 'exitpcdn', 'preloadpcdn', 'pcdn_timeout_count', 'extra']
            for i, v in enumerate(p['items']):
                print('  %-18s = %s' % (names[i], (v or '')[:260]))
        elif t == 'gen':
            out.append(p)
            print('[gen] %s = %s' % (p['name'].split(' ').pop(), (p['v'] or '')[:64]))

    device = frida.get_usb_device()
    session = device.attach(pid)
    script = session.create_script(JS)
    script.on('message', on_message)
    script.load()
    try:
        time.sleep(duration)
    except KeyboardInterrupt:
        pass
    if out:
        with open(outfile, 'w') as f:
            json.dump(out, f, ensure_ascii=False, indent=2)
        print('\n[*] %d records -> %s' % (len(out), outfile))
    try:
        script.unload(); session.detach()
    except Exception:
        pass


if __name__ == '__main__':
    main()
