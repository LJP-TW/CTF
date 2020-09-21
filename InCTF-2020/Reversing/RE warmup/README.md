# RE warmup
題目給了 `warmup`

亂嘗試一番後, 試到

```
./warmup -V
GNU strings (GNU Binutils) 2.35
Copyright (C) 2020 Free Software Foundation, Inc.
This program is free software; you may redistribute it under the terms of
the GNU General Public License version 3 or (at your option) any later version.
This program has absolutely no warranty.
[1]    15942 segmentation fault (core dumped)  ./warmup -V./warmup -V
GNU strings (GNU Binutils) 2.35
Copyright (C) 2020 Free Software Foundation, Inc.
This program is free software; you may redistribute it under the terms of
the GNU General Public License version 3 or (at your option) any later version.
This program has absolutely no warranty.
```

發現原來他是 GNU strings, 下載 source code 配著 `warmup` 反編譯的 code 看

發現多了 `-z` 選項

其會設定一個 global 變數, 看看這個變數在哪被用到

就找到 `sub_400E10` function 再做可疑的動作

將其後續行為寫成 `decrypt.py` 解出 flag

`inctf{U5uaL_W4rmUPs_NEED_STr1nGS_SO_1_GAVE_IT}`