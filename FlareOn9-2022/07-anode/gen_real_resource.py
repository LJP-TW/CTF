#!/usr/bin/env python3
import re

with open('test_js_log', 'r') as f:
    test_log = f.read().split('\n')
    test_map = {}
    for l in test_log:
        line = l.split(' : ')
        if len(line) != 2:
            continue
        test_map[line[0]] = line[1]
    print(test_map)
    
with open('anode_resource.js', 'r') as f:
    anode_resource = f.read()

test_nums = re.findall(r'if \(([0-9]*n?)\)', anode_resource)

for test_num in test_nums:
    if test_num not in test_map:
        continue
    anode_resource = anode_resource.replace(test_num, test_map[test_num])
    print('replace {} to {}'.format(test_num, test_map[test_num]))

with open('anode_resource_real.js', 'wb') as f:
    f.write(anode_resource.encode())
