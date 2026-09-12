"""微信安卓版 CDN 下载 URL 实时捕获器（frida + root）。

原理：
  微信安卓 8.0.x 的 C2C 图片/视频走 CDN，下载请求在进程内以明文 HTTP 写出
  （libc send/sendto/write/writev）或 TLS 写出（libssl.so SSL_write）。
  本工具 hook 上述入口，扫描出站字节中的 HTTP 请求行并解析 CDN URL。

捕获到的 URL 形如：
  https://vweixinf.tc.qq.com/110/2040X/stodownload?m=<md5>&filekey=<DER hex>
       &hy=SH&storeid=<签名>&ef=<1缩略图|2原图>&bizid=1022&picformat=..&ftype=2

用法：
  1) 手机 root，启动 frida-server： adb shell su -c 'nohup /data/local/tmp/frida-server &'
  2) 打开微信并停在会触发下载的页面（聊天列表/图片大图/朋友圈/视频号）
  3) 本机运行： python3 capture_cdn.py <秒数> [输出json] [pid]
     不传 pid 时按包名 com.tencent.mm 查找。
  4) 在微信里上下滑动 / 点开图片 / 播放视频触发 CDN 下载
  5) 输出 JSON 里保留完整请求头（含 X-Reserve 反爬 token 等）

注意：
  - 只读 hook，不修改行为；卸载即恢复。
  - 微信对 frida 有反调试，若 frida-server 被杀死，重启并重试；
    一次捕获期间不要在手机上做多余操作。
"""
import frida
import sys
import time
import json
import re

JS = r"""
const CDN_RE = /(stodownload|\.qpic\.cn|qlogo|\.tc\.qq\.com|cdn\.weixin|vweixinf|finderhead|wxapp)/i;
const HTTP_LINE_RE = /(?:GET|POST|PUT|HEAD|OPTIONS|CONNECT)\s+(\S+)\s+HTTP\/1\.[01]/;
const HOST_RE = /(?:\r?\n|^)[Hh]ost:\s*(\S+)/;

function readAscii(ptr, n) {
    try {
        var bytes = ptr.readByteArray(n);
        var arr = new Uint8Array(bytes);
        var s = '';
        for (var i = 0; i < arr.length; i++) {
            var b = arr[i];
            if (b === 0) break;
            s += (b >= 0x20 && b < 0x7f) ? String.fromCharCode(b) : '.';
        }
        return s;
    } catch (e) { return null; }
}

function moduleName(addr) {
    var m = Process.findModuleByAddress(addr);
    return m ? m.name : '?';
}

function handle(which, fd, buf, len) {
    if (len <= 0 || len > 65536) return;
    var s = readAscii(buf, Math.min(len, 3000));
    if (!s) return;
    if (!CDN_RE.test(s)) return;
    var path = null;
    var m = HTTP_LINE_RE.exec(s);
    if (m) path = m[1];
    if (!path) return;
    var hm = HOST_RE.exec(s);
    var host = hm ? hm[1] : '';
    // 完整 URL（host 为空时补 https 前缀占位，后续可凭 Host 关联）
    var url = (host ? '' : '') + path;
    var back = Thread.backtrace(this.context, Backtracer.FUZZY).slice(0, 4).map(moduleName).join(',');
    send({kind: 'url', t: Date.now(), which: which, fd: fd, host: host, path: path,
          url: url, len: len, from: back, headers: s.slice(0, 1500)});
}

function hook(mod, sym, which) {
    var m = Process.findModuleByName(mod);
    if (!m) return;
    var p = m.getExportByName(sym);
    if (!p) return;
    Interceptor.attach(p, {
        onEnter: function (args) {
            var buf, len, fd = -1;
            if (which === 'ssl_write') {
                buf = args[1]; len = args[2].toInt32();
            } else if (which === 'send' || which === 'write' || which === 'sendto') {
                fd = args[0].toInt32(); buf = args[1]; len = args[2].toInt32();
            } else if (which === 'writev') {
                var iov = args[1], cnt = args[2].toInt32(), buf0 = null, total = 0;
                for (var i = 0; i < cnt && i < 32; i++) {
                    var base = iov.add(i * 16);
                    var p2 = base.readPointer(), l2 = base.add(8).readU64().toNumber();
                    if (buf0 === null) buf0 = p2;
                    total += l2;
                }
                if (total > 65536) return;
                buf = buf0; len = total;
            } else return;
            handle.call(this, which, fd, buf, len);
        }
    });
    send({kind: 'hooked', mod: mod, sym: sym, at: p.toString()});
}

setTimeout(function () {
    hook('libc.so', 'send', 'send');
    hook('libc.so', 'sendto', 'sendto');
    hook('libc.so', 'write', 'write');
    hook('libc.so', 'writev', 'writev');
    hook('libssl.so', 'SSL_write', 'ssl_write');
    send({kind: 'ready'});
}, 100);
"""


def main():
    duration = int(sys.argv[1]) if len(sys.argv) > 1 else 120
    outfile = sys.argv[2] if len(sys.argv) > 2 else 'captured_cdn_urls.json'
    pid = int(sys.argv[3]) if len(sys.argv) > 3 else None

    captured = []

    def on_message(msg, data):
        if msg['type'] != 'send':
            print(msg)
            return
        p = msg['payload']
        if not isinstance(p, dict):
            print(p)
            return
        if p.get('kind') == 'ready':
            print('[*] hooks ready, capturing %ds (slide/open images/videos in WeChat now)' % duration)
        elif p.get('kind') == 'hooked':
            print('[+] hooked %s!%s @ %s' % (p['mod'], p['sym'], p['at']))
        elif p.get('kind') == 'url':
            captured.append(p)
            host = p.get('host') or '?'
            print('[*] CDN URL host=%s\n    %s' % (host, p['path'][:180]))
            print('    headers(first 200): %s' % p['headers'][:200].replace('\n', ' | '))

    device = frida.get_usb_device()
    if pid:
        session = device.attach(pid)
    else:
        session = device.attach('com.tencent.mm')
    script = session.create_script(JS)
    script.on('message', on_message)
    script.load()
    try:
        time.sleep(duration)
    except KeyboardInterrupt:
        pass
    if captured:
        with open(outfile, 'w') as f:
            json.dump(captured, f, ensure_ascii=False, indent=2)
        print('[*] %d CDN URL(s) -> %s' % (len(captured), outfile))
    else:
        print('[*] none captured')
    try:
        script.unload()
        session.detach()
    except Exception:
        pass


if __name__ == '__main__':
    main()
