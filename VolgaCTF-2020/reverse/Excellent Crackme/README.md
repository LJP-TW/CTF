# Excellent Crackme
題目給了 `VolgaCTF_excel_crackme.xlsm`

其寫了 VBA 巨集, 要看巨集內容需要密碼

不過可以用一些手段繞過密碼保護

參考 https://superuser.com/questions/807926/how-to-bypass-the-vba-project-password-from-excel

照著做後, 不用輸入密碼就能看到裡面檔案有一個 Module1 和四個亂碼物件

對其右鍵另存檔案後, 就有了 `Module1 ed2.bas`

逆向他後, 就發現是要解方程式 `array.csv`

其中每一橫排代表一個方程式 A1X0 + A2X1 + ... + A44X44 = Yi

每一直排中的數字代表 Ai, 最後一排直排為總和 Yi, 要解出 \[X0, X1, ..., X44\]

共有 45 個變數, 45 個方程式, 所以是解得出來的線性系統

用工具解完後就能得到 Flag

`VolgaCTF{7h3_M057_M47h_cr4ckM3_y0u_3V3R_533N}`
