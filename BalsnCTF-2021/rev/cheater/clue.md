# Program
* 0x2127445DA28: money
    * 0x140075178: cmp money, 3690h
    * 0x140072DCD: set money
* 0x140141334: State
    * 為 2 則進到可以打字的畫面
    * aswd 移動, z 選擇, x 確定後進到 WinHttpOpen
* 有 decrypt/encrypt 函數
* 0x140073B8C: encrypt
    * 0x14007347F IV: 0xFB5093BD521C93F9282AA1237A0A923B
                       0xFB5093BD521C93F9282AA1237A0A923A

    * 0x14007347F key: 0x50CA96F7E7DBB519647023BD61992E82

                       0x7A0CD87E1B9312D67C724D752AAF9C4E
                       0xC6D62F384C748A97088A08EB24A8E08A
    * 猜測是 128-bit AES
        * IV  : 0xFB5093BD521C93F9282AA1237A0A923B
        * Key : 0x11f121df288a3fef766d35309b9a67f78b5f4bad60b96763f6a9de8aa60d92d1
* 0x140073B96: encode

* 加密:
    * 資料: Successfully=_= FLAG{ZZZZ} 
    * 以 0x20 padding
    * 輸出
        * 000002C9ABC8E150  82 2E 99 61 BD 23 70 64 19 B5 DB E7 F7 96 CA 50  ...a½#pd.µÛç÷.ÊP (gi6ZYb0jcGQZtdvn95bKUA==)
        * 000002C9ABC8E160  71 A2 61 C2 39 0B E6 0B CF 9E AD 1F 2D 82 86 D2  q¢aÂ9.æ.Ï...-..Ò (caJhwjkL5gvPnq0fLYKG0g==)
        * gi6ZYb0jcGQZtdvn95bKUHGiYcI5C+YLz56tHy2ChtI=

DB6DCC802B70FF8C4E59D2461969E768

68 e7 69 19 46 d2 59 4e 8c ff 70 2b 80 cc 6d db

68 46 8c 80 
e7 d2 ff cc 
69 59 70 6d 
19 4e 2b db

a = 0x1969e768
b = 0x4e59d246
c = 0x2b70ff8c
d = 0xdb6dcc80

input_13 = ((((((input_1 << 16) | input_1) & 0xFFFF0000FFFFi64) << 8) | ((input_1 << 16) | input_1) & 0xFFFF0000FFFFi64) & 0xFF00FF00FF00FFi64 | ((((((input_3 << 16) | input_3) & 0xFFFF0000FFFFi64) << 8) | ((input_3 << 16) | input_3) & 0xFFFF0000FFFFi64) << 8) & 0xFF00FF00FF00FF00ui64);

000000DD1DBFEAA0  00 00 01 01 11 10 01 11 10 00 11 01 00 00 10 11  ................  
000000DD1DBFEAB0  10 01 01 11 00 10 10 00 01 01 00 11 11 10 11 11  ................  
000000DD1DBFEAC0  00 00 10 01 10 01 01 10 01 00 01 01 01 11 00 01  ................  
000000DD1DBFEAD0  11 00 11 11 11 11 10 10 00 11 11 11 00 00 00 10  ................  

* https://gitlab.com/yawning/bsaes/blob/0a714cd429ec/ct64/aes_ct64.go

00000290E7081309  D2 92 0D A6 8A DE A9 F6 63 67 B9 60 AD 4B 5F 8B  Ò..¦.Þ©öcg¹`.K_.  
00000290E7081319  F7 67 9A 9B 30 35 6D 76 EF 3F 8A 28 DF 21 F1 11  ÷g..05mvï?.(ß!ñ.  

0000020DF0BA1309  D1 92 0D A6 8A DE A9 F6 63 67 B9 60 AD 4B 5F 8B  Ñ..¦.Þ©öcg¹`.K_.  
0000020DF0BA1319  F7 67 9A 9B 30 35 6D 76 EF 3F 8A 28 DF 21 F1 11  ÷g..05mvï?.(ß!ñ.  

0000020DF0BA1329  3B 92 0A 7A 23 A1 2A 28 F9 93 1C 52 BD 93 50 FB  ;..z#¡*(ù..R½.Pû  

0000026895C41309  D2 92 0D A6 8A DE A9 F6 63 67 B9 60 AD 4B 5F 8B  Ò..¦.Þ©öcg¹`.K_.  
0000026895C41319  F7 67 9A 9B 30 35 6D 76 EF 3F 8A 28 DF 21 F1 11  ÷g..05mvï?.(ß!ñ.  
0000026895C41329  38 92 0A 7A 23 A1 2A 28 F9 93 1C 52 BD 93 50 FB  8..z#¡*(ù..R½.Pû  




* maybe key: 00000290E7081309  D2 92 0D A6 8A DE A9 F6 63 67 B9 60 AD 4B 5F 8B  Ò..¦.Þ©öcg¹`.K_.  
8b5f4bad60b96763f6a9de8aa60d92d2
11f121df288a3fef766d35309b9a67f7
11f121df288a3fef766d35309b9a67f78b5f4bad60b96763f6a9de8aa60d92d1

# pcap

## 1
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
* winhttp!WinHttpOpen
* winhttp!WinHttpConnect
* winhttp!WinHttpOpenRequest
* winhttp!WinHttpSendRequest
* winhttp!WinHttpReadData
    * 成功讀到 base64 字串
* 0x14006BE55: COM 物件一直執行到
    * 0x14007302E: Init
    * 0x140073089: Send / Recv 
    * 0x1400730E4: ?
    * 0x1400730EC: Read Base64
    * 0x140073160: decode?
    * 0x140073320: decrypt
        * 0x140071FD9: xmm0 解出字串, 每 0x10 個字一起解

```
05INporeqfZjZ7lgrUtfi/dnmpswNW127z+KKN8h8RE= :
d3 92 0d a6 8a de a9 f6 63 67 b9 60 ad 4b 5f 8b f7 67 9a 9b 30 35 6d 76 ef 3f 8a 28 df 21 f1 11

OZIKeiOhKij5kxxSvZNQ+29XPzP5Q61kNGFyb+bMn8A= :
39 92 0a 7a 23 a1 2a 28 f9 93 1c 52 bd 93 50 fb 6f 57 3f 33 f9 43 ad 64 34 61 72 6f e6 cc 9f c0

AGHrWuOtb5rQ+OC7CbmDPQ== :
00 61 eb 5a e3 ad 6f 9a d0 f8 e0 bb 09 b9 83 3d

"Successfully=_= "
```

* 組合在一起解才能解

## 2
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

## 3
```
GET /antibalsn/gameState HTTP/1.1
Connection: Keep-Alive
Accept: */*
User-Agent: Mozilla/4.0 (compatible; Win32; WinHttp.WinHttpRequest.5)
Host: flag-online.balsn.tw:7414

HTTP/1.0 200 OK
Server: BaseHTTP/0.6 Python/3.8.12
Date: Sat, 16 Oct 2021 03:36:14 GMT
Content-type: text/html

bRvh/P2mhVRKOjx+3yPxqcFYKk6W3x7kO28IY5ckcf4C3YMbBuN941wrmtNfLOz9xXO65th7ZAeVad+Z8HPRxTJeuRIKTaqv6cAN28UFbOJJA2uefQLFzp+Fl3B8T4Kk
```

## 4
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

## 5
```
GET /antibalsn/gameState HTTP/1.1
Connection: Keep-Alive
Accept: */*
User-Agent: Mozilla/4.0 (compatible; Win32; WinHttp.WinHttpRequest.5)
Host: flag-online.balsn.tw:7414

HTTP/1.0 200 OK
Server: BaseHTTP/0.6 Python/3.8.12
Date: Sat, 16 Oct 2021 03:36:55 GMT
Content-type: text/html
```

## 6
```
GET /antibalsn/gameState HTTP/1.1
Connection: Keep-Alive
Accept: */*
User-Agent: Mozilla/4.0 (compatible; Win32; WinHttp.WinHttpRequest.5)
Host: flag-online.balsn.tw:7414

HTTP/1.0 200 OK
Server: BaseHTTP/0.6 Python/3.8.12
Date: Sat, 16 Oct 2021 03:36:57 GMT
Content-type: text/html
```

## 7
```
GET /antibalsn/gameOver/zdeuKXamubFEU24lGKBlaBR/RX2Xr71Ww7j2PxWzKbGXxP8RXOct7OyeqLo32C0tIxYWM53JpmatzOnY8fNJ+xc4P+RAd7vx34oWFrDQ69zWjSDFwaczbav/bndVj4jKEkHXnxaffFsi4VHyIcM/2OZZVLDNcsMPzkeJQNoy5DHaIVy3NfER1MdQA20O9Y4ff2nWBcdxWJd9SGt0T3F/ZS6NOSAXagSUe6XF8Lz7e7LlYlBt2UkKw+FZSVlxr3XUZj7VDYYM61iOSNqXpozD1FbkC9iQihkDZ8as91SBQRk= HTTP/1.1
Connection: Keep-Alive
Accept: */*
User-Agent: Mozilla/4.0 (compatible; Win32; WinHttp.WinHttpRequest.5)
Host: flag-online.balsn.tw:7414

HTTP/1.0 200 OK
Server: BaseHTTP/0.6 Python/3.8.12
Date: Sat, 16 Oct 2021 03:37:36 GMT
Content-type: text/html
```

## 8
```
GET /antibalsn/gameOver/Lf9qPeoKXgzno0hTiuAr+57MFeOSp69vgcqawBGckN9rHdMnJyaoVTPgaV6lqwvuz4zQPGLNbnBs1Vvt741zBwWuWHqMVJEwZsQOt3TZHM4aCDuhqNLAh1YzA9JCFPZc7U3rQZmRBqkS7/3m1qLHhlrWYs+DUv0qp7WRAxvQERajujTSYA4mh4iFqrZH6UrXnHx1QKNWd749iDfU7J8AAcSzPnjl9cod9W1iq1x5lKiNAvbmJ5lhlmvN6tCI0pI3wEF7r94gCZF4YwT70FOzjsyU3f6ipFUifPUXgVJhIkN5G/xqk96nhO2Kz+6/1KkGJamXlwykSdhUzMWmGuESJ4GTliI9NJ4fAGMJx5cl0FY= HTTP/1.1
Connection: Keep-Alive
Accept: */*
User-Agent: Mozilla/4.0 (compatible; Win32; WinHttp.WinHttpRequest.5)
Host: flag-online.balsn.tw:7414

HTTP/1.0 200 OK
Server: BaseHTTP/0.6 Python/3.8.12
Date: Sat, 16 Oct 2021 03:40:13 GMT
Content-type: text/html
```

## 9
```
GET /antibalsn/gameState HTTP/1.1
Connection: Keep-Alive
Accept: */*
User-Agent: Mozilla/4.0 (compatible; Win32; WinHttp.WinHttpRequest.5)
Host: flag-online.balsn.tw:7414

HTTP/1.0 200 OK
Server: BaseHTTP/0.6 Python/3.8.12
Date: Sat, 16 Oct 2021 03:40:18 GMT
Content-type: text/html

z7EP7CgNyYCtNb4fia2LO2dTA+Xtcwm4AL5tXmJmO9k=
```

## 10
```
GET /antibalsn/gameState HTTP/1.1
Connection: Keep-Alive
Accept: */*
User-Agent: Mozilla/4.0 (compatible; Win32; WinHttp.WinHttpRequest.5)
Host: flag-online.balsn.tw:7414

HTTP/1.0 200 OK
Server: BaseHTTP/0.6 Python/3.8.12
Date: Sat, 16 Oct 2021 03:40:34 GMT
Content-type: text/html

n8sWY0lKjZGmL6uzGoQKReCk2fNsaoQEPuCJJpT1twA=
```
