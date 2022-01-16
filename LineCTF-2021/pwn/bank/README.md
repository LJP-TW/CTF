# Pwn / 428pts - bank

## Solution
By [@LJP-TW](https://github.com/LJP-TW)

* (感謝 [@jaidTw](https://github.com/jaidTw) 翻譯)

### Vuln
The `user` structure is defined as follows:

![](https://raw.githubusercontent.com/LJP-TW/CTF/master/LineCTF-2021/pwn/bank/img1.png)

And here's the function for editing user's memo:

![](https://raw.githubusercontent.com/LJP-TW/CTF/master/LineCTF-2021/pwn/bank/img2.png)

First, `memo_size` is initialized to 0x32, and if an user became VIP, `memo_size` will get increased by 0x10, which means it's possible to overwrite `custom_transfer` by editing VIP's memo. `custom_transfer()` is a function pointer which can be leveraged to control the execution flow and it is called when VIP user is going to transfer their money.

![](https://raw.githubusercontent.com/LJP-TW/CTF/master/LineCTF-2021/pwn/bank/img3.png)

For becoming a VIP, the following is the function for upgrading an user:

![](https://raw.githubusercontent.com/LJP-TW/CTF/master/LineCTF-2021/pwn/bank/img4.png)

In the `if` condition, first, `check_all_account_ok()` checks wheter if in all accounts possessed by the current user, the amount of money is greater than 0. Next, `transfer_count++` have to be greater than `0x13`, this value will get increased by 1 everytime we make a new trasnfer. Finally, `so_rich()` returns true only if the first account of the current user having money more than 200000000.

The first and second requirment is easy to be satisfied, while for the third requirment, in this challenge, the only way to earn money is by winning a lottery. The following figure shows the function that set up the RNG for the lottery. Apprently, it's using a fixed seed and hence the value can be easily predicted.

![](https://raw.githubusercontent.com/LJP-TW/CTF/master/LineCTF-2021/pwn/bank/img5.png)

Now we are able to control the function pointer, and the last piece is to leak the address of libc.
In fact, after winning a lottery, we are asked to leave some information:

![](https://raw.githubusercontent.com/LJP-TW/CTF/master/LineCTF-2021/pwn/bank/img6.png)

At this point, the `name` array will have some residue containg a valid libc address that can be leaked and used to compute the address of one-gadget.

### Exploitation

Finally, our attack works as follows
1. Win a lottery
2. Leak libc
3. Make a VIP user
4. Edit VIP user's `custom_transfer` to one-gadget
5. Use "transfer" to trigger one-gadget