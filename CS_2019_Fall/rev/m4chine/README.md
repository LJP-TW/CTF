# Write-up

一開始拿到的是 .pyc
就先用 uncompyle6 反編出 .py

```
pip install uncompyle6 --user
uncompyle6 m4chine*.pyc
```

反編出來的結果我存到 m4chine.py

內容只是簡單的 VM, 自訂了自己的 op code
我做一點更改 變成 m4chine_edited.py
好讓我 dump 出來這個自定義語言的組語
結果在 reverse.asm
最後就可以根據 reverse.asm 反推敲出 flag
反推 flag 的腳本是 solve.py









