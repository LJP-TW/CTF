# pwn / 265 - uml
## Solution

By [@LJP](https://github.com/ljp-tw)
Credits to [@HexRabbit](https://github.com/HexRabbit), [@wxrdnx](https://github.com/wxrdnx)

* uml = User Mode Linux
* 以正常的 linux 來說, 操作 /dev/mem 會直接操作到 physical memory
* 在 uml 中操作 /dev/mem, 會操作到其模擬 physical memory 的其中一塊 virtual memory
* 逆向此題的 linux, 並以實驗驗證, 發現其是以 0x60000000 作為 physical memory 的起始點
* 發現在 0x6036c000~0x60483000 和 0x60490000~0x60498000 有 rwx 區段
* 由 [@HexRabbit](https://github.com/HexRabbit) 找到在其 [source code](https://github.com/torvalds/linux/blob/12119cfa1052d512a92524e90ebee85029a918f8/arch/um/os-Linux/umid.c#L409) 有一段程式碼, 呼叫到 initcall / exitcall, 且其 function table 坐落在可寫區段
* 打法為在 rwx 區間寫入 shellcode, 並改寫 remove_umid_dir function pointer, 使其指向 shellcode, 最終退出程式, 觸發呼叫 remove_umid_dir
