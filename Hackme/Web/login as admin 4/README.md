# Hint
- There is no return or exit to terminate this process
    ```php
    if($_POST['name'] === 'admin') {
        if($_POST['password'] !== $password) {
            // show failed message if you input wrong password
            header('Location: ./?failed=1');
        }
    }
    ```
- You need some tools
    [This article helps me a lot](http://puremonkey2010.blogspot.com/2016/10/wireshark-decrypting-tls-browser.html)



