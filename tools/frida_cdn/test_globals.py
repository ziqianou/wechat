import frida, sys

js = r"""
var names = [];
for (var k in globalThis) {
    names.push(k);
}
send('globals: ' + names.join(', '));
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
