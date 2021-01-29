#!/usr/bin/env python3

with open('./105-round-134-team-1-ad-2-6814398e040bb9664bcfa20296627f1e', 'rb') as f1:
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



