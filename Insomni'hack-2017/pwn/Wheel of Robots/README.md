0x6030E0 d_mem
0x6030E8 f_mem
0x6030F0 b_mem
0x6030F8 a_mem
0x603100 c_mem
0x603108 e_mem
0x603110 choice_buf
0x603114 b_enable
0x603118 d_enable
0x60311C f_enable
0x603120 a_enable
0x603124 c_enable
0x603128 e_enable
0x603130 wheels
0x603138 b_itlg
0x603140 c_clt
0x603148 f_power
0x603150 (未用到的 bss 段)

b_enable 能被 overflow 改掉

若能創 chunk 到上面那些全域變數, 基本上就能 arbitrary write

先申請 b_mem (能寫 0x20 ~ 0x60 size 的 chunk), free 掉, 蓋掉 b_enable 就能再度寫這塊 free chunk

---

先申請 f_mem, 設 f_power 為 0x61, 並 free 掉

再申請 b_mem (size 0x60), free 掉, 蓋 b_enable, 將 free chunk 的 fd 寫到 0x603140

蓋 b_enable, 申請 b_mem (size 0x60), 申請 c_mem (size 0x60), 此時 c_mem 指向 0x603150

free b_mem, 蓋 b_enable, 將 free chunk 的 fd 寫到 c_mem + 2 - 8

蓋 b_enable, 申請 b_mem, 蓋 b_enable, 再度申請 b_mem, 此時 b_mem 指向全域變數, 至此, 能改寫全域變數
但到此步只能 overwrite 全域變數中從 b_enable 開始的參數, 還要想辦法改寫到 mem 才能實質 arbitrary write

申請 c_mem (size 0x30), 申請 f_mem, 此兩塊 chunk 會連續, 蓋 c_clt 後, 就能 heap overflow, 打 unlink 到全域變數上

將 fake chunk size 寫 0x20, FD 為 0x603100-0x18, BK 為 0x603100-0x10, prev_size 寫 0x20, 將 f_mem 的 prev_inuse 寫為 0

在此之前先申請一塊 a_mem(0x20), 避免 f_mem 跟 top chunk 合併觸發 malloc_consolidate, 加上因為先前 fastbin 中有錯誤地址而導致 crash
free f_mem 觸發 unlink, 至此, 0x603100 上面存的值會是 0x603100-0x18
至此能操控 memory pointer, 可以亂寫囉





