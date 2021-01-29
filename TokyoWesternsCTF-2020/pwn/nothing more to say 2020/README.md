# nothing more to say 2020

## Intro

功能僅有接收使用者輸入, 並且 echo 出來

## Vulns

存在 format string vuln

## Exploit

1. 通過 fmt vuln leak libc
2. 通過 fmt vuln 將 printf_got 蓋成 system

3. 輸入 sh