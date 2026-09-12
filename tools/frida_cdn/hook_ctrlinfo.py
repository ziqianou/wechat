"""Hook 微信 CDN task ctrlinfo 日志 + CreateFileKey/CreateAeskey，还原 storeid/filekey/aeskey 来源。

目标函数（libwechatmm.so，通过偏移定位）：
  - off+0x1f4f38：ctrlinfo 日志调用点，x1=format串, x2=args数组(全为 std::string*)
  - CreateFileKey / CreateAeskey：导出符号，返回随机密钥串

用法：python3 hook_ctrlinfo.py <pid> [秒数]
"""
import frida
import sys
import time
import re

JS = r"""
const MM = Process.getModuleByName('libwechatmm.so');
const CTRLINFO_LOG = MM.base.add(0x1f4f38);

function readStdString(ptr) {
    if (ptr.isNull()) return '<null>';
    try {
        var hdr = ptr.readU8();
        var isHeap = (hdr & 1) === 1;
        var len = hdr >> 1;
        var dataPtr;
        if (isHeap) {
            len = ptr.add(8).readU64().toNumber();
            dataPtr = ptr.add(16).readPointer();
        } else {
            dataPtr = ptr.add(1);
        }
        if (len > 1024) return '<big:%d>' % len;
        return dataPtr.readUtf8String(len);
    } catch (e) { return '<err>'; }
}

function readCString(ptr) {
    try { return ptr.readUtf8String(256); } catch (e) { return '<err>'; }
}

// ---------- hook ctrlinfo logger call site ----------
Interceptor.attach(CTRLINFO_LOG, {
    onEnter: function (args) {
        var fmt = readCString(args[1]);
        if (!fmt || fmt.indexOf('ctrlinfo') === -1) return;
        var argArr = args[2];
        var items = [];
        // 该 format 全部为 %_ (std::string)，逐个读取
        for (var i = 0; i < 14; i++) {
            var p = argArr.add(i * 8).readPointer();
            items.push(readStdString(p));
        }
        send({t: 'ctrlinfo', fmt: fmt, items: items});
    }
});

// ---------- hook CreateFileKey / CreateAeskey ----------
function hookRet(addr, name) {
    Interceptor.attach(addr, {
        onEnter: function () { this.retSlot = this.context.x8; },
        onLeave: function (retval) {
            // 返回 std::string（通过 x8 返回指针写入）
            var str = readStdString(this.retSlot);
            send({t: 'gen', name: name, value: str});
        }
    });
    send({t: 'hooked', name: name, at: addr.toString()});
}

setTimeout(function () {
    var exps = MM.enumerateExports();
    exps.forEach(function (e) {
        if (e.name.indexOf('mars3cdn') !== -1 && (e.name.indexOf('CreateFileKey') !== -1 || e.name.indexOf('CreateAeskey') !== -1)) {
            hookRet(e.address, e.name.split(' ').pop());
        }
    });
    send({t: 'ready'});
}, 100);
"""


def main():
    pid = int(sys.argv[1]) if len(sys.argv) > 1 else None
    duration = int(sys.argv[2]) if len(sys.argv) > 2 else 120

    def on_message(msg, data):
        if msg['type'] != 'send':
            print(msg)
            return
        p = msg['payload']
        if isinstance(p, dict) and p.get('t') == 'ctrlinfo':
            print('\n===== CTRLINFO =====')
            print('fmt:', p['fmt'])
            names = ['filekey', 'url', 'bakurl', 'quic', 'pcdnurl', 'net', 'timestamp',
                     'useugc', 'usepcdn', 'beginpcdn', 'exitpcdn', 'preloadpcdn', 'pcdn_timeout_count', 'extra']
            for i, v in enumerate(p['items']):
                if i < len(names):
                    print('  %-20s = %s' % (names[i], v[:300]))
                else:
                    print('  arg%d = %s' % (i, v[:300]))
        elif isinstance(p, dict) and p.get('t') == 'gen':
            print('[gen] %-16s = %s' % (p['name'], p['value'][:80]))
        elif isinstance(p, dict) and p.get('t') == 'hooked':
            print('[+] hooked %s @ %s' % (p['name'], p['at']))
        elif isinstance(p, dict) and p.get('t') == 'ready':
            print('[*] ready, browse image chats now...')

    device = frida.get_usb_device()
    session = device.attach(pid if pid else 'com.tencent.mm')
    script = session.create_script(JS)
    script.on('message', on_message)
    script.load()
    try:
        time.sleep(duration)
    except KeyboardInterrupt:
        pass
    try:
        script.unload()
        session.detach()
    except Exception:
        pass


if __name__ == '__main__':
    main()
