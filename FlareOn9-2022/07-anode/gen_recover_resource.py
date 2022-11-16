#!/usr/bin/env python3
import re

# https://stackoverflow.com/a/2556252
def rreplace(s, old, new, occurrence):
    li = s.rsplit(old, occurrence)
    return new.join(li)

def replace(s, old, new, occurrence):
    li = s.split(old, occurrence)
    return new.join(li)

with open('state_js_log', 'r') as f:
    logs = f.read().split('state: ')[1:-1][::-1] # ignore last state
    log_list = []
    for l in logs:
        state = l.split('\n')[:-1]
        log_list.append([1, state[0]])    # 1: state
        for mr in state[1:-1]:            # skip last Math.random()
            assert('[*]' in mr)
            log_list.append([0, mr[19:]]) # 0: Math.random

with open('real_case.js', 'r') as f:
    real_cases = f.read().split('case ')[1:]
    real_case_map = {}
    for real_case in real_cases:
        temp = real_case.split('\n', 1)
        state, codeblock = temp[0].split(':')[0], temp[1]

        pattern = r'if \(([01])\) {([^}]*)} else {([^}]*)}([\S\n\t ]*)continue;'
        result = re.findall(pattern, codeblock)

        if len(result) == 0:
            codeblock = codeblock.replace('continue;', '')
            real_case_map[state] = codeblock
            continue

        result = result[0]

        new_codeblock = ''
        if result[0] == '1':
            new_codeblock += result[1]
        else:
            new_codeblock += result[2]
        new_codeblock += result[3]
        real_case_map[state] = new_codeblock

content = b''

content += '''
var state = 0;
var b = [106, 196, 106, 178, 174, 102, 31, 91, 66, 255, 86, 196, 74, 139, 219, 166, 106, 4, 211, 68, 227, 72, 156, 38, 239, 153, 223, 225, 73, 171, 51, 4, 234, 50, 207, 82, 18, 111, 180, 212, 81, 189, 73, 76];
'''.encode()

i = 0
while i < len(log_list):
    t, state = log_list[i][0], log_list[i][1]

    assert(t == 1)
    assert(state in real_case_map)
    
    content += '// state {}\n'.format(state).encode()
    
    codeblock = real_case_map[state] 
    
    codeblock = codeblock.replace('+=', 'PLUSEQUAL')\
                         .replace('-=', '+=')\
                         .replace('PLUSEQUAL', '-=')

    cnt = 0
    while True:
        if 'Math.random()' not in codeblock:
            break
        
        if cnt == 2:
            i -= 1

        i += 1

        if i >= len(log_list):
            break

        t, randomnum = log_list[i][0], log_list[i][1]
        
        if t != 0:
            i -= 1
            break

        codeblock = replace(codeblock, 'Math.random()', randomnum, 1)
        cnt += 1
        
    content += codeblock.encode()
    
    i += 1

#    assert(t == 1)
#
#    casepattern = 'case {}:\n(.*)continue;'.format(num)
#    caseblock = re.findall(casepattern, anode_resource)
#
#    assert(len(caseblock) == 1)
#
#    caseblock = caseblock[0]
#
#    while True:
#        idx = caseblock.rfind('Math.random()')
#        if idx == -1:
#            break
#        
#        i += 1        
#        t, num = log_list[i]
#        assert(t == 0)
#
#        caseblock = rreplace(caseblock, 'Math.random()', num, 1)
#
#
#
#
#    content += '''
#    if ({test_num}) {{
#        console.log('{test_num} : 1');
#    }} else {{
#        console.log('{test_num} : 0');
#    }}
#    '''.format(test_num = test_num).encode()

content += '''
console.log(b);
bs = String.fromCharCode.apply(null, b);
'''.encode()

with open('anode_resource_recover.js', 'wb') as f:
    f.write(content)
