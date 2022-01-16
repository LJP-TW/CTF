# Reverse / 407 - cheater

> As a CTF player, how do I sovle challenges and get the flags ?
> NO, I don't ! I infiltrate spies into the CTF origanizers' family. 
> Their girlfriend, boyfriend, wife, husband, adopted son and even their pet cat !
> Spies will try to borrow their computer for playing a tiny tiny pixel-art video game... 
> That's a trap! The game is actually a interface to contact headquarter for futher commands!
> But a double secret agent stole my flag!
> Haha, that's a bait, help me to found out which flag was leak so I can target the perpetrator.
> 
> **The story, names,  and incidents portrayed in this description are fictitious.**

* 題目含有以下檔案
    * flag-online.exe
    * SDL2.dll
    * SUS.pcapng
    * assets/
* flag-online.exe 執行起來是一個遊戲

![](https://raw.githubusercontent.com/LJP-TW/CTF/master/BalsnCTF-2021/rev/cheater/img1.png)

![](https://raw.githubusercontent.com/LJP-TW/CTF/master/BalsnCTF-2021/rev/cheater/img2.png)

## Solution
By @LJP 

* 首先看一下 SUS.pcapng
    * 疑似為 victim 與 c2 web server 溝通的過程
    * 發現不少疑似 base64 編碼過的部分, 解碼後是 raw bytes, 懷疑是加密過的資料
    * 共有三種 API
* /antibalsn/regist
```
GET /antibalsn/regist HTTP/1.1
Connection: Keep-Alive
Accept: */*
User-Agent: Mozilla/4.0 (compatible; Win32; WinHttp.WinHttpRequest.5)
Host: flag-online.balsn.tw:7414

HTTP/1.0 200 OK
Server: BaseHTTP/0.6 Python/3.8.12
Date: Sat, 16 Oct 2021 03:36:05 GMT
Content-type: text/html

05INporeqfZjZ7lgrUtfi/dnmpswNW127z+KKN8h8RE=
OZIKeiOhKij5kxxSvZNQ+29XPzP5Q61kNGFyb+bMn8A=
AGHrWuOtb5rQ+OC7CbmDPQ==
```

* /antibalsn/gameState
```
GET /antibalsn/gameState HTTP/1.1
Connection: Keep-Alive
Accept: */*
User-Agent: Mozilla/4.0 (compatible; Win32; WinHttp.WinHttpRequest.5)
Host: flag-online.balsn.tw:7414

HTTP/1.0 200 OK
Server: BaseHTTP/0.6 Python/3.8.12
Date: Sat, 16 Oct 2021 03:36:12 GMT
Content-type: text/html

ej11h3gdBqW5R+tNHW5xsOz1iLlYAJpCGdo3YOClzaYOpCvBhF6wFNC/YlCzDbtdiYq8+sfGBbhkEXL8FmJV5uBBXJ0OR4OstnCg6gjkQYI=
```

* /antibalsn/gameOver/
```
GET /antibalsn/gameOver/FgbDTDkDqxnRbtahXsXdekET4/zpL/JNIK22VSnUJcmi10yDH4vrqjKFRn5Ub7ns6lusReLGDBJ24ypdlTI1r3yIUxCQGGXM4SlXUsHtl24hF44n49C/igkpLYoB0A1/pkCE/pkoBo6uKAJDwT3kQDzZDJRWgTBuw6wj8TpQ2VNdYucjdugbbQjmyxQrb0kk2O4ZBxYst1AOJh7kfTOutsPGSAtQ9Gn16PKMEeTw6XEhttR1l/X5j0jEpnKI2gAY5cxsOsB7dPsuampYXtZ7HQ== HTTP/1.1
Connection: Keep-Alive
Accept: */*
User-Agent: Mozilla/4.0 (compatible; Win32; WinHttp.WinHttpRequest.5)
Host: flag-online.balsn.tw:7414

HTTP/1.0 200 OK
Server: BaseHTTP/0.6 Python/3.8.12
Date: Sat, 16 Oct 2021 03:36:52 GMT
Content-type: text/html
```

* 懷疑 flag-online.exe 有連線行為後, 再來就是驗證看看
* 借助 AdateDNS, 將所有 DNS query 都回傳 127.0.0.1, 執行 flag-online.exe 後可以看到有 `flag-online.balsn.tw` 的 query
    * ![](https://raw.githubusercontent.com/LJP-TW/CTF/master/BalsnCTF-2021/rev/cheater/img3.png)
* 再來是找 flag-online.exe 哪邊的程式碼做了連線的事情, 想法是在 socket 函數下斷點, 再從 call stack 往回追溯
    * 可以發現程式一開始並沒有加載 ws2_32.dll (提供 socket 函數的 dll)
    * 具體方法改成先在 LoadLibraryA 設斷點, 直到加載 ws2_32.dll  後再設定 socket 中斷點, 後來發現設定一次後, 之後會自動在加載完 ws2_32.dll 後加上 socket 中斷點
    * 自己寫一個 c2, 照著 pcap 裡的封包送 payload
* 總之追到了 offset 0x73089 身上

```
.text:000000014007305F                 mov     [rsp+200h+var_1E0], 0
.text:0000000140073068                 mov     [rbp+var_1B0], 0
.text:0000000140073073                 mov     [rbp+var_180], 0
.text:000000014007307E                 mov     [rbp+var_178], 0
.text:0000000140073089                 call    invoke__9c6Y89ad8seBcyEinNcDbxHw
.text:000000014007308E                 lea     rax, [rbp+var_170]
.text:0000000140073095                 mov     rcx, r12
.text:0000000140073098                 mov     [rsp+200h+var_1D0], 0
.text:00000001400730A1                 mov     [rsp+200h+var_1D8], rax
.text:00000001400730A6                 lea     r9, [rbp+var_1A8]
.text:00000001400730AD                 mov     r8d, 3
.text:00000001400730B3                 lea     rdx, TM__kCjcUih9bJAaBH0Qh5DC0Tw_17
.text:00000001400730BA                 mov     [rsp+200h+var_1E0], 0
.text:00000001400730C3                 mov     [rbp+var_1A8], 0
.text:00000001400730CE                 mov     [rbp+var_170], 0
.text:00000001400730D9                 mov     [rbp+var_168], 0
.text:00000001400730E4                 call    invoke__9c6Y89ad8seBcyEinNcDbxHw
```

* 也追到了 flag-online.exe 是用 WinHTTP 系列的 API 在與 c2 web server 溝通
    * 並在 WinHTTP API 設斷點後, 發現程式還沒進遊戲邏輯前就會往 `/antibalsn/regist` 打 request
* 順著 offset 0x73089 往後看做了什麼, 發現解碼解密的程式碼
```
.text:0000000140073160 loc_140073160:                          ; CODE XREF: init__1eM9auCeT70xrbC2fzp7DfQ+311↓j
.text:0000000140073160                 mov     rcx, [r12+rbx*8+10h]
.text:0000000140073165                 call    b64decode
.text:000000014007316A                 mov     r15, rax
.text:000000014007316D                 test    rax, rax
.text:0000000140073170                 jz      short loc_140073177
.text:0000000140073172                 add     qword ptr [rax-10h], 8

...

.text:0000000140073320 loc_140073320:                          ; CODE XREF: init__1eM9auCeT70xrbC2fzp7DfQ+35C↑j
.text:0000000140073320                 mov     rdx, rsi
.text:0000000140073323                 mov     rcx, rdi
.text:0000000140073326                 add     rdx, 20h ; ' '
.text:000000014007332A                 call    decrypt__yTNT7OFdw4VeC8mj9be88kA_part_0
.text:000000014007332F                 jmp     loc_140073202
```
* 解題的當下沒有細看 decrypt, 只知道一開始封包中, 此 API 返回的 payload 解完後是 `Successfully=_= `
* 且到這個時候才發現原來 function name 有跡可循, 搜尋了一下 decode/encode/decrypt/encrypt 找到幾個看起來有用的函數, 接下來的動態分析看情況在裡面設斷點
* 在遊戲中都不會再送 request, 因此懷疑是不是 money 要到一定數量才會開始搞事, 為了驗證這個想法, 於是開始往改 money 跟看哪邊用到 money 的去逆
* Cheat Engine 弄一下得到了 money 的位址, 並找到哪邊使用到 money
* 0x72DCD 應該是設定 money 的部分, 比較沒用
```
.text:0000000140072DCD                 mov     rcx, [rbx+18h]
.text:0000000140072DD1                 call    nimIntToStr
```
* 0x75178 判定 money 是否大於 3690h
```
.text:000000014007516F                 mov     rcx, [rbp+20h]
.text:0000000140075173                 call    update__zDr9byk6pUTEohhdzGFqH5A_2
.text:0000000140075178                 cmp     qword ptr [rbp+18h], 3690h ; cmp money
.text:0000000140075180                 jle     short loc_14007519C
```
* 從這邊順下, 可以找到在符合一定條件後會將一個叫做 currentState 的變數設為 2
```
.text:00000001400752A0                 mov     qword ptr [rbp+8], 1Eh
.text:00000001400752A8                 mov     cs:currentState__Wc09cKuZYDia4B4v9cw7TNVA, 2
.text:00000001400752AF                 jmp     loc_14007519C
```
* 如果直接改 money, 改成大於 3690h, 並將 currentState 改成 2, 則會進到可以打字的狀態

![](https://raw.githubusercontent.com/LJP-TW/CTF/master/BalsnCTF-2021/rev/cheater/img4.png)

* 亂按一下就發現, awsd 可以移動框框, z 可以輸入字, x 可以將上面的文字打 request 給 c2
* 按下 x 後, 進到 0x73340 的 encrypt 函數
* xrefs 看一下, 找到哪邊呼叫到 0x73340 encrypt

```
.text:0000000140073B81                 mov     rcx, [rbp+arg_0]
.text:0000000140073B85                 lea     rdx, [rbp+var_2C0]
.text:0000000140073B8C                 call    encrypt__l7V4zu461RHdTkKYdKDbtw
.text:0000000140073B91                 xor     edx, edx
.text:0000000140073B93                 mov     rcx, rax
.text:0000000140073B96                 call    b64encode
```

* 可以合理猜測流量中的密文就是這樣來的, 要解開就要開逆 0x73340 encrypt 函數
* 0x73340 encrypt code 簡單來講如下

```c
__int64 __usercall encrypt__l7V4zu461RHdTkKYdKDbtw@<rax>(_BYTE *a1@<rcx>, __int64 **a2@<rdx>, __m128 *a3@<xmm7>)
{
    // 將明文 padding 成 0x10 倍數, 用空格 padding
    
    ...
    
    // 類似 python AES.new()
    init__vm3AATzsuQUkWc17a2NCRQ(IV, (v31 + 0x39), 0x20i64, (v31 + 0x59));
    
    ...
    
    // 明文每 0x10 個字處理
    for ( i = 16i64; ; i += 16i64 )
    {
        // 與 IV xor
        result = _mm_xor_si128(_mm_loadu_si128(&plain_str[i / 8]), _mm_loadu_si128(&IV[968]));
        // 加密 block
        encrypt__py6wg79aBw8iTzUm11Z7JOA_2(result.m128i_i8, IV, &result, a3);
        // 更新 IV
        X5BX5Deq___wCxLFNoF2DOiuJpFEiBO9cQ(&IV[968], &v27, &result, 16i64);
    }
}
```
* 這邊先猜測幾個點
    * 應該是 CBC Mode
    * 從 xor 那邊可以取得 IV, IV 大小是 0x10
    * 此加密演算法一個 block 大小是 0x10
* 先這樣, 再來繼續看 init 在幹嘛
```c
__int64 __fastcall init__vm3AATzsuQUkWc17a2NCRQ(__int64 a1, __int64 a2, __int64 a3, __int64 a4)
{
  ...
  keySchedule__atoyT3nOrMuAmdOTI4mO5g(a1, a2);
  ...
  return X5BX5Deq___wCxLFNoF2DOiuJpFEiBO9cQ(v5 + 968, &v7, v4, 16i64);
}
```
* 看一下 keySchedule 發現裡面很醜, 但有呼叫到 `ortho` 開頭的函數
* 假設作者不是完全自己寫這些函數, 或許 google 能 google 到相似的東西, 拿一些函數裡的常數搜尋, 解題當下搜尋的關鍵字是 `ortho 0x5555555555555555 0xAAAAAAAAAAAAAAAA`
* 找到了這份 code: https://gitlab.com/yawning/bsaes/blob/0a714cd429ec/ct64/aes_ct64.go
* 看起來跟 flag-online.exe 裡面的很像, 就先假設真的是 AES
* google 來的 code 裡面的 Keyscheds, 第二個參數是 key, 那來觀察一下 `keySchedule__atoyT3nOrMuAmdOTI4mO5g` 的第二個參數會不會是 key
* 發現第二個參數內容如下, 第三個參數為 0x20
```
0000027DE7651309  D2 92 0D A6 8A DE A9 F6 63 67 B9 60 AD 4B 5F 8B  Ò..¦.Þ©öcg¹`.K_.  
0000027DE7651319  F7 67 9A 9B 30 35 6D 76 EF 3F 8A 28 DF 21 F1 11  ÷g..05mvï?.(ß!ñ.  
0000027DE7651329  38 92 0A 7A 23 A1 2A 28 F9 93 1C 52 BD 93 50 FB  8..z#¡*(ù..R½.Pû
```
* 持續觀察這個位址, 並照著前面所說進入到能打字的狀態後, 送幾次 request, 會發現這邊的數值會有所變化, 以下是幾次的觀察

```
0000027DE7651309  D1 92 0D A6 8A DE A9 F6 63 67 B9 60 AD 4B 5F 8B  Ñ..¦.Þ©öcg¹`.K_.  
0000027DE7651319  F7 67 9A 9B 30 35 6D 76 EF 3F 8A 28 DF 21 F1 11  ÷g..05mvï?.(ß!ñ.  
0000027DE7651329  3B 92 0A 7A 23 A1 2A 28 F9 93 1C 52 BD 93 50 FB  ;..z#¡*(ù..R½.Pû  
```

```
0000027DE7651309  D3 92 0D A6 8A DE A9 F6 63 67 B9 60 AD 4B 5F 8B  Ó..¦.Þ©öcg¹`.K_.  
0000027DE7651319  F7 67 9A 9B 30 35 6D 76 EF 3F 8A 28 DF 21 F1 11  ÷g..05mvï?.(ß!ñ.  
0000027DE7651329  39 92 0A 7A 23 A1 2A 28 F9 93 1C 52 BD 93 50 FB  9..z#¡*(ù..R½.Pû  
```

```
0000027DE7651309  D0 92 0D A6 8A DE A9 F6 63 67 B9 60 AD 4B 5F 8B  Ð..¦.Þ©öcg¹`.K_.  
0000027DE7651319  F7 67 9A 9B 30 35 6D 76 EF 3F 8A 28 DF 21 F1 11  ÷g..05mvï?.(ß!ñ.  
0000027DE7651329  3A 92 0A 7A 23 A1 2A 28 F9 93 1C 52 BD 93 50 FB  :..z#¡*(ù..R½.Pû  
```
* 幾次下來發現, 前面有說到 xor IV 的部分就是從這邊的末 0x10 bytes 來的
* 用某一次 request 來驗證這邊的前 0x20 bytes 是否為 key, 末 0x10 bytes 是否為 IV, 發現能解字串內容
* 觀察 key 和 IV 的變化, 看起來就是規律的 +1/-1, 還有 IV 初始值有兩種可能
* 直接猜到底 +/- 了多少, 解看看流量的密文, 就解成功了