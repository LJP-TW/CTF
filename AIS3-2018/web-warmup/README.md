這題一連進去後會被 redirect 到

http://104.199.235.135:31331/index.php?p=7

打web通常可以先注意幾個東西

> 看有沒有註解藏東西

沒那麼簡單~~

> 有沒有 robots.txt

嗯。看來沒有

> 檢查 Headers

唉呦, 有個 Partial-Flag 看起來是自訂的

> 檢查 Cookies

啥東都沒有

然後又看到這個 GET Requests 的參數是 p=7

**那 p=0 勒**

就發現 p= 多少, Partial-Flag 就顯示 Flag 的第幾個字~