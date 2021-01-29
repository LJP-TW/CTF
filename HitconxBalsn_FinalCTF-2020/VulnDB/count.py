#!/usr/bin/env python3

with open('./release/vulndb', 'rb') as f1:
    C1 = f1.read()

with open('./7/vulndb_patched3_NX', 'rb') as f2:
    C2 = f2.read()

count = 0
for c1, c2 in zip(C1, C2):
    if c1 != c2:
        count += 1
print(count)

