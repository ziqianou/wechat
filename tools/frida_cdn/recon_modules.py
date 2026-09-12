import frida, sys, json

js = r"""
var mods = Process.enumerateModules();
var interesting = [];
for (var i = 0; i < mods.length; i++) {
    var m = mods[i];
    if (m.path.indexOf('tencent') !== -1 || m.path.indexOf('/data/app') !== -1) {
        interesting.push({name: m.name, base: m.base.toString(), size: m.size, path: m.path});
    }
}
send(JSON.stringify(interesting, null, 1));
"""

def on_message(msg, data):
    if msg['type'] == 'send':
        print(msg['payload'])
    else:
        print(msg)

session = frida.get_usb_device().attach('com.tencent.mm')
script = session.create_script(js)
script.on('message', on_message)
script.load()
session.detach()
