hxp-36C3 2019 - [rev] xmas_future
===
- [Description](#Description)
    - [CORS](#CORS)
    - [Breakpoint](#Breakpoint)
    - [Reverse wasm](#Reverse-wasm)
    - [Answer](#Answer)
- [Reference](#Reference)

# Description
題目給了一份網頁，有用到 js 和 wasm

![](https://i.imgur.com/bnp8gyL.png)


簡單的看完 hxp2019.js 後，感覺上重點應該在
```javascript
/**
* @param {string} pwd
* @returns {bool}
*/
export function check(pwd) {
    var ptr0 = passStringToWasm0(pwd, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len0 = WASM_VECTOR_LEN;
    var ret = wasm.check(ptr0, len0);
    return ret !== 0;
}
```
從變數名稱猜，ptr0 應該是指向輸入字串，len0 應該是這字串多長

接著就要看 wasm.check 實際上做了什麼

## CORS
若直接點開 html 的話，在 console 中會跳出
```
Access to script at 'file:///D:/Share/Git/CTF/hxp-36C3/rev/xmas_future/xmas_future/hxp2019.js' from origin 'null' has been blocked by CORS policy: Cross origin requests are only supported for protocol schemes: http, data, chrome, chrome-extension, https.
```

若是用
```
php -S 0.0.0.0:1337
```

這樣去架 server 就不會有此問題

## Breakpoint
Firefox 可以透過 Debugger 直接在想要下斷點的 js 語句旁邊點一下

![](https://i.imgur.com/gDu287l.png)

## Reverse wasm
上面是透過動態分析，靜態分析則有以下的工具能反編出 .c 出來

[WebAssembly/wabt](https://github.com/WebAssembly/wabt)

反推出的 c 雖然只比 asm 好看了一點，但還是能參考參考

## Answer
理解完 code 後，發現程式邏輯很簡單

把反向的邏輯寫到 `exploit.py` 就解出來ㄌ

# Reference
- [WebAssembly/wabt](https://github.com/WebAssembly/wabt)

###### tags: `CTF`