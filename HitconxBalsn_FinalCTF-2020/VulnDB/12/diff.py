#!/usr/bin/env python3

with open('./106-round-137-team-4-ad-2-55b82bc770c73925a6397e4117bc81f0', 'rb') as f1:
    C1 = f1.read()

with open('./vulndb', 'rb') as f2:
    C2 = f2.read()

count = 0
idx = 0
for c1, c2 in zip(C1, C2):
    if c1 != c2:
        print(hex(idx))
        count += 1
    idx += 1

print(count)



