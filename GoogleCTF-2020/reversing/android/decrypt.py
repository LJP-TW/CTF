#!/usr/bin/env python3

g_class = [0x271986b,
           0xa64239c9,
           0x271ded4b,
           0x1186143,
           0xc0fa229f,
           0x690e10bf,
           0x28dca257,
           0x16c699d1,
           0x55a56ffd,
           0x7eb870a1,
           0xc5c9799f,
           0x2f838e65]

g_arr   = [0 for _ in range(0xc)]
g_int   = 0

nani = [0x41, 0x70, 0x70, 0x61, 0x72, 0x65, 0x6e, 0x74, 
        0x6c, 0x79, 0x20, 0x74, 0x68, 0x69, 0x73, 0x20, 
        0x69, 0x73, 0x20, 0x6e, 0x6f, 0x74, 0x20, 0x74,
        0x68, 0x65, 0x20, 0x66, 0x6c, 0x61, 0x67, 0x2e,
        0x20, 0x57, 0x68, 0x61, 0x74, 0x27, 0x73, 0x20,
        0x67, 0x6f, 0x69, 0x6e, 0x67, 0x20, 0x6f, 0x6e,
        0x3f]
key = ''.join(chr(x) for x in nani)
keyString = ''.join(chr(x) for x in nani)
print(keyString)

def R_func(a, b):
    if a == 0:
        return [0, 1]
    r = R_func(b % a, a)
    return [r[1] - b // a * r[0], r[0]]

flagString = 'CTF{y0u_c4n_k3ep_y0u?_m4gic_1_h4Ue_laser_b3ams!}' # user input, len must be 0x30
i = 0
print('{}: {}'.format(len(flagString), flagString))
while True:
    # goto_4
    if i >= len(flagString) // 4:
        break # goto cond_3
    g_arr
    idx = i * 4 + 3
    g_arr[i]  = ord(flagString[idx]) << 0x18
    idx = i * 4 + 2
    g_arr[i] |= ord(flagString[idx]) << 0x10
    idx = i * 4 + 1
    g_arr[i] |= ord(flagString[idx]) << 0x8
    idx = i * 4
    g_arr[i] |= ord(flagString[idx])
    i += 1

# cond_3
while g_int < 0xc:
    m = 0x100000000
    g = R_func(g_arr[g_int], m)
    inv = (((g[0] % m) + m) % m)

    print('{} round'.format(g_int))
    print('\tinv: {:#x}'.format(inv))
    print('\tggg: {:#x}'.format(g_class[g_int]))
    if inv == g_class[g_int]:
        g_int += 1
    else:
        print(':(')
        exit()
