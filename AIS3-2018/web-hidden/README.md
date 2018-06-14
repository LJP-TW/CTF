這題連進去後 會發現等個幾秒 

會有一個 'Get flag in the next page' 的 button 跳出來

然後按下去又會一直重複一樣的事情

觀察一下 source code

可以發現到按下這個 button, 就只是送出一個 data 包含有 c, s 兩個變數的 POST Request 而已

然後每按一次, c 值就會加1, s 值則是變成其他亂數

所以就合理懷疑

**c 代表第幾層關卡**

**s 代表通過這層關卡的key**

再來

1. 不知道這有幾層關卡

2. 不想每次要進到下關都要等上幾秒

所以直接寫一個 script

直接抓c, s值, 直接送 POST Request 出去, 直到內容不是 "Hmm... no flag here!" 為止

看他會發生啥事

然後就發現了 到了第17xxx層(忘了第幾層了)時 Flag 就在 Header 裡面~~~

