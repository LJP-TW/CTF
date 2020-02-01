#!/usr/bin/python -u
# encoding: utf-8

import random, string, subprocess, os, sys
from hashlib import sha256

os.chdir(os.path.dirname(os.path.realpath(__file__)))

def proof_of_work():
    chal = ''.join(random.choice(string.letters+string.digits) for _ in xrange(16))
    print(chal)
    sol = sys.stdin.read(14)
    print(sha256(chal + sol).hexdigest())
    if len(sol) != 14 or not sha256(chal + sol).hexdigest().startswith('dadada'):
        print("pow error")
        exit()


if __name__ == '__main__':
    os.system("./EasyROP")
