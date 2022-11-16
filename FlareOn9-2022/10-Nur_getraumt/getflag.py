#!/usr/bin/env python3
import struct
import string

def u16(b):
    return struct.unpack('>H', b)[0]

def repeat_until(b, l):
    result = []
    for i in range(l):
        result.append(b[i % len(b)])
    return bytes(result)

encflag = b''.join([
    b'\x2D\x0C\x00\x1D\x1A\x7F\x17\x1C\x4E\x02\x11\x28\x08\x10\x48\x05',
    b'\x00\x00\x1A\x7F\x2A\xF6\x17\x44\x32\x0F\xFC\x1A\x60\x2C\x08\x10',
    b'\x1C\x60\x02\x19\x41\x17\x11\x5A\x0E\x1D\x0E\x39\x0A\x04\x27\x18'])

encflag_len = encflag[0]
encflag_tmp = encflag[1:1+encflag_len]
ans_crc_val = u16(encflag[1+encflag_len:])
encflag     = encflag_tmp

print(encflag_len)
print(encflag)
print(hex(ans_crc_val))

guess_password = b'abcde'
guess_password = repeat_until(guess_password, encflag_len)

decflag = bytes([x ^ y for x, y in zip(encflag, guess_password)])

print(decflag)

guess_flag = b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@flare-on.com'
known_flag = b'================================@flare-on.com' # = means unknown
known_flag = b'Dann_singe_ich_ein_Lied_f=r_dich@flare-on.com' # = means unknown
known_flag = b'Dann_singe_ich_ein_Lied_fur_dich@flare-on.com' # = means unknown
# password = b'Hast du etwas Zeit fur mich Hast du etwas Zei'
assert(len(guess_flag) == encflag_len)

cand = string.printable

known_password = bytes([0 if k == ord('=') else k ^ e for k, e in zip(known_flag, encflag)])

print(known_password)

known_password = b'Hast du etwas Zeit f=r mi=h?Hast du etwas Zei'
guess_password = b'Hast du etwas Zeit fur mich?Hast du etwas Zei'

decflag = bytes([x ^ y for x, y in zip(encflag, guess_password)])

print(decflag)


