"""Frida 脚本：捕获微信进程内所有出站 HTTP/TLS 写数据中的 CDN URL。

Hook 层：
  - libc.so:  send / sendto / write / writev
  - libssl.so: SSL_write

对所有出站字节做 ASCII 扫描，命中 URL 模式（http(s)://... 或
GET/POST ... HTTP/1.x）且域名含 CDN 关键字时上报完整 URL。
用法：
  python3 capture_cdn_url.py [持续时间秒] [输出json]
"""
import frida
import sys
import time
import json
import threading

JS_TEMPLATE = r"""
const TARGET_HOSTS = /(^|[.@/-])(qq\.com|weixin\.qq\.com|wechat\.com|qpic\.cn|weixin\.cn|qq\.com\/|snsvideo|wxapp|vweixinf|storeid|stodownload)/i;
const URL_RE = /((?:https?:\/\/|(?:GET|POST|PUT|HEAD)\s)[^\s"']{8,500})/i;
const HTTP_RE = /(?:GET|POST|PUT|HEAD|OPTIONS|CONNECT)\s+(\S+)\s+HTTP\/1\.[01]/;
const VERBOSE = false;

var modules = {};

function readStr(ptr, max) {
    try {
        return ptr.readUtf8String(max);
    } catch (e) {
        try {
            var bytes = ptr.readByteArray(max);
            var arr = new Uint8Array(bytes);
            var s = '';
            for (var i = 0; i < arr.length; i++) {
                var b = arr[i];
                if (b === 0) break;
                if (b >= 0x20 && b < 0x7f) s += String.fromCharCode(b);
                else s += '.';
            }
            return s;
        } catch (e2) { return null; }
    }
}

function moduleOf(addr) {
    var m = Process.findModuleByAddress(addr);
    return m ? m.name : '?';
}

function onWrite(which, bufPtr, len, fdHint) {
    if (len <= 0 || len > 65536) return;
    var s = readStr(bufPtr, Math.min(len, 4096));
    if (!s) return;
    if (VERBOSE) {
        send({t: 'raw', which: which, len: len, data: s.slice(0, 120), from: 'v', fd: fdHint});
        return;
    }
    if (!HTTP_RE.test(s) && s.indexOf('http') === -1 && s.indexOf('qq.com') === -1 && s.indexOf('qpic.cn') === -1) return;
    var caller = Thread.backtrace(this.context, Backtracer.FUZZY).slice(0, 5).map(moduleOf).join(',');
    send({t: 'raw', which: which, len: len, data: s.slice(0, 2000), from: caller, fd: fdHint});
}

function hook(mod, sym, which) {
    var m = Process.findModuleByName(mod);
    if (!m) return;
    var p = m.getExportByName(sym);
    if (!p) return;
    try {
        Interceptor.attach(p, {
            onEnter: function (args) {
                var buf, len, fd = -1;
                if (which === 'ssl_write') {
                    buf = args[1]; len = args[2].toInt32();
                } else if (which === 'send' || which === 'write') {
                    fd = args[0].toInt32(); buf = args[1]; len = args[2].toInt32();
                } else if (which === 'sendto') {
                    fd = args[0].toInt32(); buf = args[1]; len = args[2].toInt32();
                } else if (which === 'writev') {
                    // iovec array
                    var iov = args[1]; var cnt = args[2].toInt32();
                    var total = 0; var buf0 = null;
                    for (var i = 0; i < cnt && i < 16; i++) {
                        var base = iov.add(i * 16);
                        var p2 = base.readPointer();
                        var l2 = base.add(8).readU64().toNumber();
                        if (buf0 === null) buf0 = p2;
                        total += l2;
                    }
                    if (total > 65536) return;
                    buf = buf0; len = total;
                }
                this.buf = buf; this.len = len; this.which = which; this.fd = fd;
                onWrite.call(this, which, buf, len, fd);
            }
        });
        send({t: 'hooked', mod: mod, sym: sym, at: p.toString()});
    } catch (e) {
        send({t: 'hookfail', mod: mod, sym: sym, err: String(e)});
    }
}

// main
setTimeout(function () {
    hook('libc.so', 'send', 'send');
    hook('libc.so', 'sendto', 'sendto');
    hook('libc.so', 'write', 'write');
    hook('libc.so', 'writev', 'writev');
    hook('libssl.so', 'SSL_write', 'ssl_write');
    send({t: 'ready'});
}, 100);
"""

def main():
    duration = int(sys.argv[1]) if len(sys.argv) > 1 else 120
    outfile = sys.argv[2] if len(sys.argv) > 2 else 'captured_cdn_urls.json'
    pid = int(sys.argv[3]) if len(sys.argv) > 3 else None

    results = []

    def on_message(msg, data):
        if msg['type'] != 'send':
            print(msg)
            return
        payload = msg['payload']
        if isinstance(payload, dict):
            if payload.get('t') == 'ready':
                print('[*] hooks installed, capturing %ds...' % duration)
            elif payload.get('t') == 'hooked':
                print('[+] hooked %s!%s at %s' % (payload['mod'], payload['sym'], payload['at']))
            elif payload.get('t') == 'raw':
                results.append(payload)
                data_s = payload['data']
                # extract URL-ish substring
                import re
                m = re.search(r'(?:GET|POST|PUT|HEAD|OPTIONS|CONNECT)\s+(\S+)\s+HTTP', data_s)
                url = m.group(1) if m else (data_s[:120] if 'http' in data_s.lower() else '')
                print('[url] %s len=%d caller=[%s]' % (url[:160], payload['len'], payload['from'][:80]))
            elif payload.get('t') == 'hookfail':
                print('[-] hookfail', payload)
        else:
            print(payload)

    device = frida.get_usb_device()
    if pid:
        session = device.attach(pid)
        print('[*] attached to pid', pid)
    else:
        session = device.attach('com.tencent.mm')
    script = session.create_script(JS_TEMPLATE)
    script.on('message', on_message)
    script.load()

    try:
        time.sleep(duration)
    except KeyboardInterrupt:
        pass

    if results:
        with open(outfile, 'w') as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        print('[*] saved %d records -> %s' % (len(results), outfile))
    else:
        print('[*] no records captured')
    try:
        session.detach()
    except Exception:
        pass

if __name__ == '__main__':
    main()
