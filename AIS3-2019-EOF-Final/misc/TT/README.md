AIS3-EOF-Final 2020 - [misc] TT
===
- [Description](#Description)
- [Exploit](#Exploit)
- [Reference](#Reference)

# Description
![](https://i.imgur.com/OdyhaiR.png)

# Exploit
1. UAF, 把 fd 改成 `__malloc_hook`
2. 將 one-gadget 寫到 `__malloc_hook` 
3. 呼叫 `malloc` 觸發 one-gadget

# Reference

###### tags: `CTF`