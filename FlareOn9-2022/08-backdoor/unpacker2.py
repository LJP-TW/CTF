#!/usr/bin/env python3
import sys
import re
import pefile
import struct
from flared_67 import *

if len(sys.argv) < 2 or len(sys.argv) > 3:
    print('Usage: python3 unpacker.py TARGET_EXE <OUTPUT_EXE>')
    exit(1)

target_fn = sys.argv[1]

if len(sys.argv) == 3:
    output_fn = sys.argv[2]
else:
    output_fn = 'output.exe_'

def u32(b):
    return struct.unpack('<I', bytes(b[:4]))[0]

hashmap = {}
hashmap[0x06000001] = b"89b957e3cbcc1acc0649a02914815042749ef4bf809987ac3b24a303f31a37f8"
hashmap[0x06000003] = b"689d7525fedc82ecb6ae5046342b45e3bccb57e9f9209f658b3f240d1a74069c"
hashmap[0x06000006] = b"30752c497d0229b3fecf3e058c2c8d39a9a46a5f27b02da69c0c5a997e97a80e"
hashmap[0x06000008] = b"7c5ccd915cbf3032739fa1df6b8578099f01baa6b94aebc638f0dc285ffcc915"
hashmap[0x0600000a] = b"5ca8a51747ebd16b041721bf56a30cd5f39f1829df27e51eadfba77003a38393"
hashmap[0x0600000c] = b"96c576e472cc6ff877cb1db64b2dbd0494f518d3550b213fe753319665721b6b"
hashmap[0x06000012] = b"305a002f193b2c1ed9295410535693b9f52c47aaf4f685bccd787b2145af07de"
hashmap[0x06000014] = b"b1c8119c5c717d00c46b7a6c43cf3eda111059ac6b4c6cb4a440575dde65e014"
hashmap[0x06000016] = b"538fcc692564863f834626beee91b70f1f100389e96a91b9b836d7c65acb0dc5"
hashmap[0x06000018] = b"326aa956a45a5b48c14bd56e606a978d80263a80db167f6e604ff770d65f2f1a"
hashmap[0x0600001A] = b"becb82d3c6bb7eed0697117dec50c26813eb9d9710b85c50842b9b4648d45aef"
hashmap[0x0600001C] = b"7135726c5225c7883449ffdd33bb30f26d4e32cfeb3600d9fcdac23baa43833b"
hashmap[0x0600001E] = b"4a0fb13652122a0f14c212c36437a5d23d53a19cadf059d11b6bbab3907022e2"
hashmap[0x06000020] = b"794ac8464ceed27c1b1afcf98241435748dae7fe6b4952524b631bf81a1e7c0b"
hashmap[0x06000022] = b"94957fff987e7e015868fab12fa7d5b0ee1e7545bacb8c8fa4f07ccdc59b8c3d"
hashmap[0x06000024] = b"0e5cf5d9e4e7fd4b8398ef26d20c04a1308cae65181d584d7acf3f48d88c8e50"
hashmap[0x06000026] = b"270860100f1937f49306a3325e8523e80b941ec3124e30704e2f154e0f899c83"
hashmap[0x0600002a] = b"ee6d9a21346018078a87ea4079959b4ed9cf153ae077c93273ea38c718b00b51"
hashmap[0x0600002c] = b"c4493ff5f1dc3be5ca9fa51900dbfb69dce66febae5e025cecb68051d27eefef"
hashmap[0x0600002F] = b"cc80b00c4bb40917278fde45c00e4e4df426ba455513c251a650878d40bc2d83"
hashmap[0x06000031] = b"30b905e5d66a3ad24630f11a9f05c361251881c82487d5aec3614474cfebbaf0"
hashmap[0x06000033] = b"11d539d6204eadbccd1d370ee6bc6225a8c710d5d2e34e923d7a24876b376ed7"
hashmap[0x06000035] = b"8de5507bdedfad2f1bd4b340eb476abab4442cead1b922e8e18521f7d0cd7f7d"
hashmap[0x06000037] = b"4f0f2ca37f08cf119f3185e28118947d704968babe1557b56db844a614098cd7"
hashmap[0x06000039] = b"85b3a7dd78eb9d17c2832a9c0bf0db35aa018f34dde74bcf4a47d98409e1ec52"
hashmap[0x0600003b] = b"520c23900a8cc6b701184426230786fc29f82f39b50c6a75b5f7418e34d1c39b"
hashmap[0x0600003d] = b"f965be7303dbadaee57d174da473ba7b9297feb886fb008c1f89e0a125c44519"
hashmap[0x0600003F] = b"0651f80b2cb667ae922cbf418343ac73f73956788d9f8a729bab11e1cf35a85e"
hashmap[0x06000041] = b"846fcbb2e5f6c174ad51ca99b9f088effefc36c8e67a37df6019289da27fe09b"
hashmap[0x06000043] = b"edd1976b2b2ba673e1e95247a54238a9b27fb7965bbb117e306524d93e3f99f1"
hashmap[0x06000045] = b"9181748dca8875decbf8e9ded90515da514028154a2396682a4ffc705e43c4c7"
hashmap[0x06000047] = b"3460378b704cb824bf52d41dedc68d99a1afedee8d70267a29841721775572de"
hashmap[0x06000049] = b"e530c0106f2f9e2498ef8cc04c59d7e721caa3dc018c4c8450e4d395e6e92176"
hashmap[0x0600004b] = b"f9a758d38e2e4e3641c0fafbac22ffa3314edbaba50e6e5538e3a99a193def7f"
hashmap[0x0600004d] = b"f8a2493f82ee664325c6407b5cf8465ee02cfea3a24f6a8037add8e4ba5bb648"
hashmap[0x06000058] = b"d787bb6bb380aebfdd031a4da2153b0985d25090529fca1214416cd43d9ccc2e"
hashmap[0x0600005a] = b"1aa22d6334aa58ad2077d2f1f4199167ef9912756bbc0389770327b587441730"
hashmap[0x0600005c] = b"892fac736928f224083e373766972ba02aa77c0b44a1f35033c08cd7da79b25f"
hashmap[0x06000068] = b"ffc58f783ea75c62c4afa6527e902ce857152317cf4dbcbe5947e4dd23705f4e"
hashmap[0x0600006A] = b"977deaeda5fff073045620bfdd21f0eaf0fa910ae9fdc86b8cfa6f7c5721fdfb"
hashmap[0x0600006C] = b"977deaeda5fff073045620bfdd21f0eaf0fa910ae9fdc86b8cfa6f7c5721fdfb"
hashmap[0x06000071] = b"c61192c7c844195b942eb02b0b64f71f00dad46f11f99b5419bc6d78a72fefb7"
hashmap[0x06000074] = b"0686a47bcd1172713a20e72108b885853e737a949afdc1cd296f4197944db1e2"
hashmap[0x06000076] = b"74fbaf68c82f81c33b3f74468e96439ac6abe8c24f405b2dc0d97cfaebcdc91b"
hashmap[0x06000078] = b"719ee568522cdb7a4519108d0a34b9531404122d12775ae8daedafc6f068a016"
hashmap[0x0600007A] = b"77c01ab26f569d1a8fb3571757e6a1beed94d3ae2a168fba2fc01c07216c6f8b"
hashmap[0x0600007C] = b"2fad6d86f3573b7ceedcb1e688397139901dfc97f1784917d345a22251121627"
hashmap[0x0600007f] = b"82b8dfa1f5e9dbf88357ea5c516d4377dc1066eb2ed87590f1bc2529b721ab71"
hashmap[0x06000084] = b"b3650258065ed1ee9f35521593eefae670c594c85c3e121f7b5588a0a6de198b"
hashmap[0x06000086] = b"a4691056b72cb7feda735954953e6ea4b347d8e3735ace8612661d63e1785761"
hashmap[0x06000088] = b"7cddb7c1f3d440dea183054eb4576dc8e1d1a4f7ca1fabb5f33fcb1a2a551e29"
hashmap[0x0600008e] = b"db08afea48362227ed638d9657ac36f30eec90853f33fe4c68898b122260f989"
hashmap[0x06000091] = b"81e1a476823fefa6bcb79f32d479c6c07298cd32991be20324e6259e49f7d045"
hashmap[0x06000093] = b"ede0bad0a05130663ac46fbc858f0376a5a753edd6a7111831e8951f0f537409"
hashmap[0x06000095] = b"699fdcf2eb7d280a3bfaaf7e81a2eb138804737ab5f90ff369ecf8550b59da95"
hashmap[0x06000097] = b"33d51cd2fbaef784d7acbc6d5e5cfcce1be1771d3524511a09712c9f541bd36d"
hashmap[0x06000099] = b"4ea4cf8de819a44de373cd43d1dd3eedd2d85b497d2dc620e85aa350f264f787"
hashmap[0x0600009a] = b"310d4de08e81de33d5601d3d7912008f20b2b7749f06566e52db6a77e1f4bdc5"
hashmap[0x060000A2] = b"8d3a199fa17ab158db9c7b072881ce611fae801896acb5b18b8836147222feef"
hashmap[0x060000A4] = b"1b8e223862dbfda65e539a98367650c1f80080f5470117c4cf5d77548d90debc"
hashmap[0x060000A6] = b"e712183aad38b4e510347e6968c89b0915acd954e66847b84cd34d687ac021cb"
hashmap[0x060000A8] = b"e712183aad38b4e510347e6968c89b0915acd954e66847b84cd34d687ac021cb"
hashmap[0x060000AA] = b"69991a3e95c5119fa78d5cffeff4bd913768663e601fcf7fd028ec252aab1571"
hashmap[0x060000AC] = b"710b11bc609c76eddf0b9d50f342e8ba89479aff881fa83407a6262515f7f9f2"
hashmap[0x060000AE] = b"807617625d41107bf8992c570a8669c792bf094237b2fdbbf2b63a0258fd77e2"
hashmap[0x060000B0] = b"4951e5478e0781cc7c74837c1b3897c6beaefcf41f1f92686ee50f627f2ca36b"
hashmap[0x060000B2] = b"37875be24378a8f648fac988941910ee9af9a5926e6ffbe1f5420bce034e00fb"
hashmap[0x060000B4] = b"8a966e195c4e8117f070d085b2dc6b9ab62eec402bab94a1e317802e2676cf72"
hashmap[0x060000B6] = b"a537f738601625b8ae6a20e79b0c92c55738cc5d3f94e50b6c29bdfd698e9263"
hashmap[0x060000B8] = b"344f2938932f8a3dee33c33357b422ef5d1d8f9607104350f320534ae937e0f7"
hashmap[0x060000BA] = b"31d823800a33883a8529585dce3128d12fe50c05dca4e9df3cdb5c792d50777c"

configs = {}

def add_config(name, rva, tk):
    config = {}
    config['rva'] = rva
    config['tk'] = tk
    configs[name] = config

add_config('flared_00', 0x2194, 0x06000001)
add_config('flared_01', 0x22e0, 0x06000003)
add_config('flared_02', 0x236c, 0x06000006)
add_config('flared_03', 0x23dc, 0x06000008)
add_config('flared_04', 0x2444, 0x0600000a)
add_config('flared_05', 0x2500, 0x0600000c)
add_config('flared_06', 0x26d0, 0x06000012)
add_config('flared_07', 0x2089, 0x06000014)
add_config('flared_08', 0x2788, 0x06000016)
add_config('flared_09', 0x27fc, 0x06000018)
add_config('flared_10', 0x2850, 0x0600001a)
add_config('flared_11', 0x28a4, 0x0600001c)
add_config('flared_12', 0x2964, 0x0600001E)
add_config('flared_13', 0x2a28, 0x06000020)
add_config('flared_14', 0x2a90, 0x06000022)
add_config('flared_15', 0x2b4c, 0x06000024)
add_config('flared_16', 0x2bd8, 0x06000026)
add_config('flared_17', 0x2d84, 0x0600002a)
add_config('flared_18', 0x2e80, 0x0600002c)
add_config('flared_19', 0x2fa0, 0x0600002f)
add_config('flared_20', 0x303c, 0x06000031)
add_config('flared_21', 0x30e0, 0x06000033)
add_config('flared_22', 0x3190, 0x06000035)
add_config('flared_23', 0x3240, 0x06000037)
add_config('flared_24', 0x32f4, 0x06000039)
add_config('flared_25', 0x3484, 0x0600003b)
add_config('flared_26', 0x35b8, 0x0600003d)
add_config('flared_27', 0x3654, 0x0600003f)
add_config('flared_28', 0x209d, 0x06000041)
add_config('flared_29', 0x3708, 0x06000043)
add_config('flared_30', 0x3820, 0x06000045)
add_config('flared_31', 0x3900, 0x06000047)
add_config('flared_32', 0x39ac, 0x06000049)
add_config('flared_33', 0x3aa0, 0x0600004b)
add_config('flared_34', 0x3b40, 0x0600004d)
add_config('flared_35', 0x3be0, 0x06000058)
add_config('flared_36', 0x3ce4, 0x0600005a)
add_config('flared_37', 0x3d4c, 0x0600005c)
add_config('flared_38', 0x3f0c, 0x06000068)
add_config('flared_39', 0x4094, 0x0600006a)
add_config('flared_40', 0x40ec, 0x0600006c)
add_config('flared_41', 0x4144, 0x06000071)
add_config('flared_42', 0x41c8, 0x06000074)
add_config('flared_43', 0x4308, 0x06000076)
add_config('flared_44', 0x43d0, 0x06000078)
add_config('flared_45', 0x4498, 0x0600007a)
add_config('flared_46', 0x4514, 0x0600007C)
add_config('flared_47', 0x4574, 0x0600007f)
add_config('flared_48', 0x46d0, 0x06000084)
add_config('flared_49', 0x4828, 0x06000086)
add_config('flared_50', 0x48dc, 0x06000088)
add_config('flared_51', 0x49c4, 0x0600008e)
add_config('flared_52', 0x4aa4, 0x06000091)
add_config('flared_53', 0x4b28, 0x06000093)
add_config('flared_54', 0x4b94, 0x06000095)
add_config('flared_55', 0x4c6c, 0x06000097)
add_config('flared_56', 0x4d1c, 0x06000099)
# add_config('flared_57', 0x4fdc, 0x0600009a)
add_config('flared_58', 0x12708, 0x060000a2)
add_config('flared_59', 0x127d0, 0x060000a4)
add_config('flared_60', 0x12870, 0x060000a6)
add_config('flared_61', 0x128d8, 0x060000a8)
add_config('flared_62', 0x12940, 0x060000aa)
add_config('flared_63', 0x129a4, 0x060000ac)
add_config('flared_64', 0x12a40, 0x060000ae)
add_config('flared_65', 0x12acc, 0x060000b0)
add_config('flared_66', 0x12b84, 0x060000b2)
# add_config('flared_67', 0x12e00, 0x060000b4)
add_config('flared_68', 0x13c50, 0x060000b6)
add_config('flared_69', 0x13cec, 0x060000b8)
# add_config('flared_70', 0x13e04, 0x060000ba)

def flared_66_hash(t):
    if t in hashmap:
        return hashmap[t]
    return None

def flared_69_readsec(s, sec_names):
    target = None
    
    for section in pe.sections:
        if s[:8] == section.Name:
            target = section
            if section.Name in sec_names:
                print('[*] Remove {}'.format(section.Name))
                sec_names.remove(section.Name)
            break
    
    if target == None:
        print('Section not found')
        exit()

    return target.get_data(length=target.Misc_VirtualSize)

def flared_46_decrypt(d, p=bytes([18, 120, 171, 223])):
    # int[] array = new int[256];
    # int[] array2 = new int[256];
    # byte[] array3 = new byte[d.Length];
    array = [0 for _ in range(256)]
    array2 = [0 for _ in range(256)]
    array3 = [0 for _ in range(len(d))]

    # int i;
    # for (i = 0; i < 256; i++)
    # {
    #     array[i] = (int)p[i % p.Length];
    #     array2[i] = i;
    # }
    for i in range(256):
        array[i] = p[i % len(p)]
        array2[i] = i

    # int num;
    # for (i = (num = 0); i < 256; i++)
    # {
    #     num = (num + array2[i] + array[i]) % 256;
    #     int num2 = array2[i];
    #     array2[i] = array2[num];
    #     array2[num] = num2;
    # }
    num = 0
    for i in range(256):
        num = (num + array2[i] + array[i]) % 256
        num2 = array2[i]
        array2[i] = array2[num]
        array2[num] = num2

    # int num3;
    # num = (num3 = (i = 0));
    # while (i < d.Length)
    # {
    #     num3++;
    #     num3 %= 256;
    #     num += array2[num3];
    #     num %= 256;
    #     int num2 = array2[num3];
    #     array2[num3] = array2[num];
    #     array2[num] = num2;
    #     int num4 = array2[(array2[num3] + array2[num]) % 256];
    #     array3[i] = (byte)((int)d[i] ^ num4);
    #     i++;
    # }
    num = 0
    num3 = 0
    for i in range(len(d)):
        num3 = (num3 + 1) % 256
        num = (num + array2[num3]) % 256
        num2 = array2[num3]
        array2[num3] = array2[num]
        array2[num] = num2
        num4 = array2[(array2[num3] + array2[num]) % 256]
        array3[i] = (d[i] ^ num4) % 256

    # return array3;
    return array3

def flared_67_patchPE(b, rva):
    j = 0
    while j < len(b):
        if b[j] == 0xfe:
            key = 0xfe00 + b[j+1]
            j += 1
        else:
            key = b[j]
        
        ot = dictionary[key]
        j += 1

        if ot == 'B':
            # xor 2727913149 (0xa298a6bd)
            b[j+0] ^= 0xbd
            b[j+1] ^= 0xa6
            b[j+2] ^= 0x98
            b[j+3] ^= 0xa2
            j += 4
        elif ot == 'C':
            j += 1
        elif ot == 'E':
            j += 1
        elif ot == 'D':
            j += 4
        elif ot == 'G':
            j += 4
        elif ot == 'F':
            j += 2
        elif ot == 'H':
            j += 8
        elif ot == 'I':
            j += 4 + u32(b[j:]) * 4

    code = bytes(b)

    fb = pe.get_data(rva, 1)

    # Patch method body

    # tiny or fat format
    isfathdr = fb[0] & 1

    if isfathdr == 1:
        rva += 12
    else:
        rva += 1
    
    pe.set_bytes_at_rva(rva, code)

pe = pefile.PE(target_fn)

# Check sections
sec_names = []
for section in pe.sections:
    sec_names.append(section.Name)

for func, config in configs.items():
    rva = config['rva']
    tk = config['tk']
    
    s = flared_66_hash(tk)
    d = flared_69_readsec(s, sec_names)
    b = flared_46_decrypt(d)
    flared_67_patchPE(b, rva)

pe.write(output_fn)

print('Not used section:')
for sec_name in sec_names:
    print('  [*] {}'.format(sec_name))
