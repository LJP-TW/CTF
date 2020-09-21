# jazz
這題是個 RUST 逆向, RUST 的安全機制讓組語變得非常難讀, 反編譯也派不上什麼用場了。

這題還是能看出一點端倪, 從哪邊是對哪邊是錯開始找起

![](https://raw.githubusercontent.com/LJP-TW/CTF/master/InCTF-2020/Reversing/jazz/img/1.png)

看得出來 `bl` 要是 1 才是隊的

繼續往前找

![](https://raw.githubusercontent.com/LJP-TW/CTF/master/InCTF-2020/Reversing/jazz/img/2.png)

這邊做了幾個註解, 是經過好幾次動態測試所猜測的


大概知道目標是什麼後, 再來逆向, 會更知道要找什麼

逆一逆的結論就是, 發現比對的密文是

```
bcc00abc5ef9b6d5c5084db15509349512ce6708fb8af1d21ad82b6428c23972b442687a3823cf04903498e1e8b00c691d22b9611f172a5de1ff5c7d31be1a6bd71fa24318abcc57d08d5fcc432c436996ecce78a906dd8e11a1feca340b90cb
```

而輸入會被 AES CBC 加密, key 和 iv 是固定死的

```
key : ecade918dbfabf53034f654bef523292aec1c4d013dd5d2805ea539714e06dd1 
iv  : d71c2d1b9b71fb9eae777564016cfa3a
```

(斷點在 `call crypto::aes::cbc_encryptor::h211c41356831deed` 即可觀察到 key、iv)

![](https://raw.githubusercontent.com/LJP-TW/CTF/master/InCTF-2020/Reversing/jazz/img/3.png)

知道是 AES CBC、有 key、iv、密文, 如此一來可知我們輸入的明文要是

```
2bb5a2eb68ebc96ec73198ae710522a4d0b0067e4279bccce7cdc1927ea989ee2bf743323f09b317eedf139ff8ae319fade4d3c0a4e60cd87e1e092dfa3a68f47eb66744a1fe247b12d4dd9988eedf13ac1b2348f59dd74f
```

而我們輸入的明文會經過 pad 轉換

![](https://raw.githubusercontent.com/LJP-TW/CTF/master/InCTF-2020/Reversing/jazz/img/4.png)

FLAG: `inctf{fly_m3_70_7h3_m00n_l37_m3_pl4y_4m0n6_7h3_574r5_4nd_l37_m3_533_wh47_5pr1n6_15_l1k3}`

沒有使用到任何 IDA plugin 也是能看懂 RUST, 重點關注在 function call 以及搞懂關鍵的 for loop 還是能大概懂程式邏輯
