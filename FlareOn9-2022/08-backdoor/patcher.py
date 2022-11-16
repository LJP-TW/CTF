#!/usr/bin/env python3
import sys
import re
import pefile
import struct

if len(sys.argv) < 3 or len(sys.argv) > 4:
    print('Usage: python3 patcher.py TARGET_EXE PATCH_FILE <OUTPUT_EXE>')
    exit(1)

target_fn = sys.argv[1]
patchs_fn = sys.argv[2]

if len(sys.argv) == 4:
    output_fn = sys.argv[3]
else:
    output_fn = 'output.exe_'

FLARE15_wl_m = [[3,167772389],[11,167772323],[16,167772324],[21,167772390],[28,100663475],[35,100663481],[42,16777263],[48,67109184],[53,167772306],[59,100663424],[70,100663477]]
FLARE15_gh_m = [[2,33554460],[7,167772268],[12,167772339],[22,1879048209],[28,1879048209],[37,167772340],[42,16777324],[49,167772341],[55,167772325],[61,167772342],[71,16777327],[76,167772228],[81,167772317],[88,167772325],[94,167772343],[99,167772228],[104,167772317],[111,167772325],[117,167772344],[127,16777328],[132,167772228],[137,167772317],[146,167772345],[170,167772346],[182,167772228],[187,167772200],[209,167772325],[215,167772347],[224,167772219],[229,167772317],[237,167772348],[244,167772349],[253,167772350],[258,167772351],[269,167772352],[280,167772353],[292,167772228],[297,167772200],[306,167772354],[321,167772230],[328,167772325],[334,167772317],[341,167772325],[348,167772317],[355,167772289],[360,167772290],[371,167772326],[381,167772326],[391,167772326],[401,167772326],[411,167772326],[421,167772326],[431,167772326],[439,167772303],[452,167772355],[470,16777263],[475,1879060560],[480,167772356],[485,167772357],[513,167772228]]
FLARE15_gs_m = [[2,167772387],[7,167772267],[13,100663397],[20,100663385],[31,167772263],[40,100663395],[56,33554458],[67,67109087],[72,167772183],[77,167772388],[91,67109088],[96,16777263],[105,67109091],[112,167772246],[123,67109088],[128,167772247],[158,167772230]]
FLARE15_pe_m = [[5,167772263],[13,167772264],[20,721420295],[25,67108951],[31,67108951],[36,67108986],[43,167772246],[50,167772265],[57,721420296],[62,67108952],[68,721420297],[73,67108953],[78,67108952],[83,67109081],[88,33554458],[93,67108955],[103,67108955],[110,721420298],[115,33554458],[126,67108955],[148,167772230]]

config = {}
config['flared_35'] = FLARE15_pe_m
config['flared_66'] = FLARE15_gh_m
config['flared_69'] = FLARE15_gs_m
config['flared_70'] = FLARE15_wl_m

with open(patchs_fn, 'r') as f:
    lines = f.read().split('\n')
    patchs = {}
    i = 0
    while i < len(lines):
        # Parse log
        print(lines[i])
        re_result = re.findall(r'([^ ]*) \(rva: ([^\)]*)\) \(size: ([^\)]*)\) \(token: ([^\)]*)\):', lines[i])
        if len(re_result) == 0:
            break
        func, rva, size, token = re_result[0]
        rva = int(rva, 16)
        size = int(size, 16)
        code = []
        for ci in range(size):
            if ci % 8 == 0:
                i += 1                
                codeline = lines[i].split(', ')
            code.append(int(codeline[ci % 8][2:], 16))

        # Try to patch DynamicMethod IL to Module IL
        if func in config:
            patchlist = config[func]
            for pl in patchlist:
                key, value = pl[0], pl[1]
                code[key]   = (value >> 0) & 0xff
                code[key+1] = (value >> 8) & 0xff
                code[key+2] = (value >> 0x10) & 0xff
                code[key+3] = (value >> 0x18) & 0xff

            patchs[rva] = bytes(code)
        i += 1

# Patch PE
pe = pefile.PE(target_fn)

for rva, code in patchs.items():
    fb = pe.get_data(rva, 1)

    # Patch method body

    # tiny or fat format
    isfathdr = fb[0] & 1

    if isfathdr == 1:
        rva += 12
    else:
        rva += 1
    
    pe.set_bytes_at_rva(rva, code)

pe.write(output_fn)
