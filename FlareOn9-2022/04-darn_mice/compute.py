#!/usr/bin/env pyton3

'''
mov     byte ptr [ebp-28], 50 ; 'P'
mov     byte ptr [ebp-27], 5E ; '^'
mov     byte ptr [ebp-26], 5E ; '^'
mov     byte ptr [ebp-25], 0A3
mov     byte ptr [ebp-24], 4F ; 'O'
mov     byte ptr [ebp-23], 5B ; '['
mov     byte ptr [ebp-22], 51 ; 'Q'
mov     byte ptr [ebp-21], 5E ; '^'
mov     byte ptr [ebp-20], 5E ; '^'
mov     byte ptr [ebp-1F], 97
mov     byte ptr [ebp-1E], 0A3
mov     byte ptr [ebp-1D], 80
mov     byte ptr [ebp-1C], 90
mov     byte ptr [ebp-1B], 0A3
mov     byte ptr [ebp-1A], 80
mov     byte ptr [ebp-19], 90
mov     byte ptr [ebp-18], 0A3
mov     byte ptr [ebp-17], 80
mov     byte ptr [ebp-16], 90
mov     byte ptr [ebp-15], 0A3
mov     byte ptr [ebp-14], 80
mov     byte ptr [ebp-13], 90
mov     byte ptr [ebp-12], 0A3
mov     byte ptr [ebp-11], 80
mov     byte ptr [ebp-10], 90
mov     byte ptr [ebp-0F], 0A3
mov     byte ptr [ebp-0E], 80
mov     byte ptr [ebp-0D], 90
mov     byte ptr [ebp-0C], 0A3
mov     byte ptr [ebp-0B], 80
mov     byte ptr [ebp-0A], 90
mov     byte ptr [ebp-9], 0A2
mov     byte ptr [ebp-8], 0A3
mov     byte ptr [ebp-7], 6B ; 'k'
mov     byte ptr [ebp-6], 7F
mov     byte ptr [ebp-5], 0
'''

v5 = [
    0x50, 0x5E, 0x5E, 0xA3, 0x4F, 0x5B, 0x51, 0x5E,
    0x5E, 0x97, 0xA3, 0x80, 0x90, 0xA3, 0x80, 0x90,
    0xA3, 0x80, 0x90, 0xA3, 0x80, 0x90, 0xA3, 0x80,
    0x90, 0xA3, 0x80, 0x90, 0xA3, 0x80, 0x90, 0xA2,
    0xA3, 0x6B, 0x7F,
]

result = []

for i in v5:
    if i <= 0xc3:
        result.append(0xc3 - i)
    else:
        print('skip')
        exit(1)

print(result)
print(bytes(result))

