import frida, sys

js = r"""
const Java = require('frida-java-bridge');
Java.perform(function () {
    var results = [];
    var classes = Java.enumerateLoadedClassesSync();
    var count = 0;
    for (var i = 0; i < classes.length; i++) {
        var c = classes[i];
        if (c.indexOf('cdn') !== -1 && c.indexOf('com.tencent') !== -1) {
            results.push(c);
            count++;
        }
    }
    send('CDN classes: ' + count);
    send(JSON.stringify(results, null, 1));
});
"""

def on_message(msg, data):
    if msg['type'] == 'send':
        print(msg['payload'])
    else:
        print(msg)

device = frida.get_usb_device()
session = device.attach('com.tencent.mm')
script = session.create_script(js, runtime='v8')
script.on('message', on_message)
script.load()
import time; time.sleep(2)
session.detach()
