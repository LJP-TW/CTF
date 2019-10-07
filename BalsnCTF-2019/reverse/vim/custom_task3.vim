" go to line 4, and make line 5 combine with line 4
" line 4 is empty, so just remove line 4
" set mark a to line 4
" set mark b to line 2
" set mark c to line 4
" set mark Z, Y to line 2
" set mark X to line 4
" go to bottom and create new line 21
exe "norm! `cJ`cma`Xmc`Ymb`amc`bmZ`bmY`cmX`ZmbGo\<esc>"
" set mark a, c to line 21, go back to line 2
exe "norm! ma`amc`b"
" set g:l = 2 (line number)
exe "let g:l=getline('.')"
" go to line 21, create a new line 22
exe "norm! `co"
exe "norm! ".(strgetchar(g:l[16:], 0) % 32 + 1)."ax"
exe "norm! ^rXo"
exe "norm! ".(strgetchar(g:l[17:], 0) % 32 + 1)."ax"
exe "norm! ^rXo"
exe "norm! ".(strgetchar(g:l[18:], 0) % 32 + 1)."ax"
exe "norm! ^rXo"
exe "norm! ".(strgetchar(g:l[19:], 0) % 32 + 1)."ax"
exe "norm! ^rXo"
exe "norm! ".(strgetchar(g:l[20:], 0) % 32 + 1)."ax"
exe "norm! ^rXo"
exe "norm! ".(strgetchar(g:l[21:], 0) % 32 + 1)."ax"
exe "norm! ^rXo"
exe "norm! ".(strgetchar(g:l[22:], 0) % 32 + 1)."ax"
exe "norm! ^rXo"
exe "norm! ".(strgetchar(g:l[23:], 0) % 32 + 1)."ax"
exe "norm! ^rXo"
exe "norm! ".(strgetchar(g:l[24:], 0) % 32 + 1)."ax"
exe "norm! ^rXo"
exe "norm! ".(strgetchar(g:l[25:], 0) % 32 + 1)."ax"
exe "norm! ^rXo"
exe "norm! ".(strgetchar(g:l[26:], 0) % 32 + 1)."ax"
exe "norm! ^rXo"
exe "norm! ".(strgetchar(g:l[27:], 0) % 32 + 1)."ax"
exe "norm! ^rXo"
exe "norm! ".(strgetchar(g:l[28:], 0) % 32 + 1)."ax"
exe "norm! ^rXo"
exe "norm! ".(strgetchar(g:l[29:], 0) % 32 + 1)."ax"
exe "norm! ^rXo"
exe "norm! ".(strgetchar(g:l[30:], 0) % 32 + 1)."ax"
exe "norm! ^rXo"
exe "norm! ".(strgetchar(g:l[31:], 0) % 32 + 1)."ax"
exe "norm! ^rXo"

