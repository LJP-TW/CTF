#!/usr/bin/env python3

import struct

# with open('07_anode/anode.exe', 'rb') as f:
#     anode = f.read()
#
# with open('anode.nojs.exe', 'wb') as f:
#     f.write(anode[:0x35dfa00])
# 
# anode_js = anode[0x35dfa00:]
# 
# idx = anode_js.find(b'<nexe~~sentinel>')
# 
# contentSize = int(struct.unpack('<d', anode_js[idx+16:idx+24])[0])
# resourceSize = int(struct.unpack('<d', anode_js[idx+24:idx+32])[0])
# 
# with open('anode_content.js', 'wb') as f:
#     f.write(anode_js[:contentSize])
# 
# with open('anode_resource.js', 'wb') as f:
#     f.write(anode_js[contentSize:contentSize+resourceSize])

# with open('anode.nojs.exe', 'rb') as f:
#     anode_nojs = f.read()
# 
# with open('anode_patch.js', 'rb') as f:
#     patch_js = f.read()
# 
# with open('anode_patch.exe', 'wb') as f:
#     f.write(anode_nojs)
#     f.write(patch_js)

# with open('anode.nojs.exe', 'rb') as f:
#     anode_nojs = f.read()
# 
# with open('anode_content.js', 'rb') as f:
#     content_js = f.read()
# 
# with open('anode_resource_patch.js', 'rb') as f:
#     resource_js = f.read()
# 
# footer  = b'<nexe~~sentinel>'
# footer += struct.pack('<d', len(content_js))
# footer += struct.pack('<d', len(resource_js))
# 
# with open('anode_patch.exe', 'wb') as f:
#     f.write(anode_nojs)
#     f.write(content_js)
#     f.write(resource_js)
#     f.write(footer)

with open('anode.nojs.exe', 'rb') as f:
    anode_nojs = f.read()

with open('anode_content.js', 'rb') as f:
    content_js = f.read()

with open('anode_resource_test.js', 'rb') as f:
    resource_js = f.read()

footer  = b'<nexe~~sentinel>'
footer += struct.pack('<d', len(content_js))
footer += struct.pack('<d', len(resource_js))

with open('anode_patch.exe', 'wb') as f:
    f.write(anode_nojs)
    f.write(content_js)
    f.write(resource_js)
    f.write(footer)

# with open('anode_patch.exe', 'rb') as f:
#     anode = f.read()
# 
# with open('anode.nojs.exe', 'wb') as f:
#     f.write(anode[:0x35dfa00])
# 
# anode_js = anode[0x35dfa00:]
# 
# idx = anode_js.find(b'<nexe~~sentinel>')
# 
# contentSize = int(struct.unpack('<d', anode_js[idx+16:idx+24])[0])
# resourceSize = int(struct.unpack('<d', anode_js[idx+24:idx+32])[0])
# 
# with open('anode_content_2.js', 'wb') as f:
#     f.write(anode_js[:contentSize])
# 
# with open('anode_resource_2.js', 'wb') as f:
#     f.write(anode_js[contentSize:contentSize+resourceSize])