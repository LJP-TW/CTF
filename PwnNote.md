CTF Pwn Note
===

# 流程

## 架設題目
```shell
ncat -kvl [port] -c [command]
```
可以在最後加上 `&` 背景執行
keyword: `linux fg`

## 找弱點

### gdb

#### 套件
https://github.com/longld/peda

#### 使用方式

##### 動態 Debug
```
sudo gdb [program_path] `pidof [program_path]`
```

##### 設定中斷點

##### 執行

##### 暫存器/Memory賦值

### IDA

## 寫 exploit

### Python 套件
https://github.com/Gallopsled/pwntools

### 不同板本 libc
以下用一個狀況舉例
在 ret2lib 若想 return 到 `_IO_gets`, 但 localhost 的 libc 跟 target host 的版本不同
已知 target host 的 libc 為 libc-2.23.so.i386
透過指令
```shell
readelf -s libc-2.23.so.i386 | grep -E '(main|gets)@@'
```
可以得到 `_IO_gets` `__libc_start_main` 的 address
兩者的 offset 加上 libc 的 base address 就是你該 return 到的位置

# 攻擊手段

## ret2lib
用各種手段, 讓 Instruction Pointer 指到 libc 中你想利用的 function 上








