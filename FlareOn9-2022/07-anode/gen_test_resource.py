#!/usr/bin/env python3
import re

with open('anode_resource.js', 'rb') as f:
    anode_resource = f.read()

test_nums = re.findall(r'if \(([0-9]*n?)\)', anode_resource.decode())

content = b''

content += '''
const readline = require('readline').createInterface({
  input: process.stdin,
  output: process.stdout,
});

readline.question(`Enter flag: `, flag => {
  readline.close();
'''.encode()

for test_num in test_nums:
    content += '''
    if ({test_num}) {{
        console.log('{test_num} : 1');
    }} else {{
        console.log('{test_num} : 0');
    }}
    '''.format(test_num = test_num).encode()

content += '''
});

//'''.encode()

with open('anode_resource_test.js', 'wb') as f:
    f.write(content)
