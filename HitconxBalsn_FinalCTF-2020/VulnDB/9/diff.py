#!/usr/bin/env python3
with open('./vulndb_patch_NX_Nmallocsize', 'rb') as f1:
    C1 = f1.read()

with open('./vulndb_patch_NX_Nmallocsize_2', 'rb') as f2:
    C2 = f2.read()

idx = 0
for c1, c2 in zip(C1, C2):
    if c1 != c2:
        print(hex(idx))
    idx += 1



