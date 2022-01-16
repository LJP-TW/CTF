#!/usr/bin/env python3

from Crypto.Cipher import AES
from base64 import b64decode

def encrypt(content, key, IV):
    cipher = AES.new(key, AES.MODE_CBC, iv=IV)
    result = cipher.encrypt(content)
    return result

def decrypt(content, key, IV):
    cipher = AES.new(key, AES.MODE_CBC, iv=IV)
    result = cipher.decrypt(content)
    return result

def to_bytes(number):
    return bytes.fromhex(hex(number)[2:])[::-1]

key = 0x11f121df288a3fef766d35309b9a67f78b5f4bad60b96763f6a9de8aa60d92d1 
iv  = 0xFB5093BD521C93F9282AA1237A0A923B 

# content = b'Successfully=_= '
# 
# data = encrypt(content, key, iv)
# 
# print([hex(x) for x in data])
# 
# content = decrypt(data, key, iv)
# 
# print(content)

# key = 0x11f121df288a3fef766d35309b9a67f78b5f4bad60b96763f6a9de8aa60d92d1
# iv  = 0xFB5093BD521C93F9282AA1237A0A9237
# data = b64decode('gi6ZYb0jcGQZtdvn95bKUPEMCQNFRnZHCERN6GK+MLY=')
# content = decrypt(data, to_bytes(key), to_bytes(iv))
# print(content)

# key = 0x11f121df288a3fef766d35309b9a67f78b5f4bad60b96763f6a9de8aa60d92d1 
# iv  = 0xFB5093BD521C93F9282AA1237A0A923B 
# data = b64decode('ej11h3gdBqW5R+tNHW5xsOz1iLlYAJpCGdo3YOClzaYOpCvBhF6wFNC/YlCzDbtdiYq8+sfGBbhkEXL8FmJV5uBBXJ0OR4OstnCg6gjkQYI=')
# content = decrypt(data, to_bytes(key), to_bytes(iv))
# print(content)
# # I cannot find flag on this computer, they dont save flag on computer!genius!=_=
# 
# key = 0x11f121df288a3fef766d35309b9a67f78b5f4bad60b96763f6a9de8aa60d92d0
# iv  = 0xFB5093BD521C93F9282AA1237A0A923a
# data = b64decode('bRvh/P2mhVRKOjx+3yPxqcFYKk6W3x7kO28IY5ckcf4C3YMbBuN941wrmtNfLOz9xXO65th7ZAeVad+Z8HPRxTJeuRIKTaqv6cAN28UFbOJJA2uefQLFzp+Fl3B8T4Kk')
# content = decrypt(data, to_bytes(key), to_bytes(iv))
# print(content)
# # Sources say they write down flags on a black cover notebook with a white cat on its front=_=
# 
# key = 0x11f121df288a3fef766d35309b9a67f78b5f4bad60b96763f6a9de8aa60d92d4
# iv  = 0xFB5093BD521C93F9282AA1237A0A923e
# data = b64decode('z7EP7CgNyYCtNb4fia2LO2dTA+Xtcwm4AL5tXmJmO9k=')
# content = decrypt(data, to_bytes(key), to_bytes(iv))
# print(content)
# # Good Job!Mission Complete!=_=
# 
# i = -7
# key = 0x11f121df288a3fef766d35309b9a67f78b5f4bad60b96763f6a9de8aa60d92d4-i
# iv  = 0xFB5093BD521C93F9282AA1237A0A923e-i-4
# data = b64decode('n8sWY0lKjZGmL6uzGoQKReCk2fNsaoQEPuCJJpT1twA=')
# content = decrypt(data, to_bytes(key), to_bytes(iv))
# print(content)
# # 7ood Job!Mission Complete!=_=

# i = -3
# key = 0x11f121df288a3fef766d35309b9a67f78b5f4bad60b96763f6a9de8aa60d92d4-i
# iv  = 0xFB5093BD521C93F9282AA1237A0A923e-i-4
# data = b64decode('FgbDTDkDqxnRbtahXsXdekET4/zpL/JNIK22VSnUJcmi10yDH4vrqjKFRn5Ub7ns6lusReLGDBJ24ypdlTI1r3yIUxCQGGXM4SlXUsHtl24hF44n49C/igkpLYoB0A1/pkCE/pkoBo6uKAJDwT3kQDzZDJRWgTBuw6wj8TpQ2VNdYucjdugbbQjmyxQrb0kk2O4ZBxYst1AOJh7kfTOutsPGSAtQ9Gn16PKMEeTw6XEhttR1l/X5j0jEpnKI2gAY5cxsOsB7dPsuampYXtZ7HQ==')
# content = decrypt(data, to_bytes(key), to_bytes(iv))
# print(content)
# # Successfully=_= I cannot find flag on this computer, they dont save flag on computer!genius!=_= Sources say they write down flags on a black cover notebook with a white cat on its front=_=    ok,I_found_it!


# i = -2
# key = 0x11f121df288a3fef766d35309b9a67f78b5f4bad60b96763f6a9de8aa60d92d4-i
# iv  = 0xFB5093BD521C93F9282AA1237A0A923e-i-4
# data = b64decode('zdeuKXamubFEU24lGKBlaBR/RX2Xr71Ww7j2PxWzKbGXxP8RXOct7OyeqLo32C0tIxYWM53JpmatzOnY8fNJ+xc4P+RAd7vx34oWFrDQ69zWjSDFwaczbav/bndVj4jKEkHXnxaffFsi4VHyIcM/2OZZVLDNcsMPzkeJQNoy5DHaIVy3NfER1MdQA20O9Y4ff2nWBcdxWJd9SGt0T3F/ZS6NOSAXagSUe6XF8Lz7e7LlYlBt2UkKw+FZSVlxr3XUZj7VDYYM61iOSNqXpozD1FbkC9iQihkDZ8as91SBQRk=')
# content = decrypt(data, to_bytes(key), to_bytes(iv))
# print(content)
# # Successfully=_= I cannot find flag on this computer, they dont save flag on computer!genius!=_= Sources say they write down flags on a black cover notebook with a white cat on its front=_=    ok,I_found_it!the_flag_is_


i = -1
key = 0x11f121df288a3fef766d35309b9a67f78b5f4bad60b96763f6a9de8aa60d92d4-i
iv  = 0xFB5093BD521C93F9282AA1237A0A923e-i-4
data = b64decode('Lf9qPeoKXgzno0hTiuAr+57MFeOSp69vgcqawBGckN9rHdMnJyaoVTPgaV6lqwvuz4zQPGLNbnBs1Vvt741zBwWuWHqMVJEwZsQOt3TZHM4aCDuhqNLAh1YzA9JCFPZc7U3rQZmRBqkS7/3m1qLHhlrWYs+DUv0qp7WRAxvQERajujTSYA4mh4iFqrZH6UrXnHx1QKNWd749iDfU7J8AAcSzPnjl9cod9W1iq1x5lKiNAvbmJ5lhlmvN6tCI0pI3wEF7r94gCZF4YwT70FOzjsyU3f6ipFUifPUXgVJhIkN5G/xqk96nhO2Kz+6/1KkGJamXlwykSdhUzMWmGuESJ4GTliI9NJ4fAGMJx5cl0FY=')
content = decrypt(data, to_bytes(key), to_bytes(iv))
print(content)
# Wuccessfully=_= I cannot find flag on this computer, they dont save flag on computer!genius!=_= Sources say they write down flags on a black cover notebook with a white cat on its front=_=    ok,I_found_it!the_flag_is_BALSN{niconjconi_this_is_an_onL1N3_G4ME!!=_=}
