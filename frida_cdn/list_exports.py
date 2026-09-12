import frida, sys

js = r"""
function listExports(modName, filter) {
    var m = Process.findModuleByName(modName);
    if (!m) { send(modName + ': NOT LOADED'); return; }
    var found = [];
    try {
        m.enumerateExports().forEach(function (e) {
            if (e.name.indexOf(filter) !== -1) found.push(e.name + ' @ ' + e.address);
        });
    } catch (e) { send('err ' + e); }
    send(modName + ': ' + JSON.stringify(found, null, 1));
}
listExports('libssl.so', 'SSL_write');
listExports('libc.so', 'send');
listExports('libc.so', 'write');
"""

def on_message(msg, data):
    if msg['type'] == 'send':
        print(msg['payload'])
    else:
        print(msg)

device = frida.get_usb_device()
session = device.attach('com.tencent.mm')
script = session.create_script(js)
script.on('message', on_message)
script.load()
session.detach()
