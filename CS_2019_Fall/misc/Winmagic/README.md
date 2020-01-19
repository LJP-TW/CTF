# Write-up
這題給了 .pdb .exe .cpp
經過一番估狗 最後 solution 如下

參考 [這篇](https://stackoverflow.com/questions/7065419/how-do-i-debug-an-existing-c-executable-with-pdb-but-without-source-code)
```
devenv /debugexe Winmagic.exe
```
其中 devenv 是 visual studio

此時應該會跳出 visual studio 的畫面
按下 F10 可以逐步執行
逐步到可以看到 cipher 內容是什麼後
就可以拿出來跟 key xor 出 flag 囉
