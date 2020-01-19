# Write-up
**線索 1**
```python
assert(E ** ( I * pi ) + len(key) == 0)
```
E, I, pi 都是 sympy 中定義的變數, 分別是 Exp, 虛數, 跟圓周率
這個 assert 限制, 可以反推出 len(key) 一定要為 1

**線索 2**
key 的 binary 若為 0x00001111
則會跑 stage0 4次 再跑 stage1 4次
而 stage0 stage1 都不會有 overflow 的問題
這表示, 可以反推!

統整兩個線索, 我們可以直接寫逆操作回來的 decrypt.py
並因為 key 長度只有 1, 表示 key 只有 0 ~ 255 的可能
可以暴力的 0 ~ 255 都當作 key 帶入看看
