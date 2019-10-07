" Create new line at prev & next
" set mark [a-z] to line 1, set mark b to line 2
exe "norm! O\<esc>jo\<esc>ggmambmcmdmemfmgmhmimjmkmlmmmnmompmqmrmsmtmumvmwmxmymzggjmb"
" set mark Y, Z to line 2, set mark X to line 1, add new line at bottom
" set mark a, c to line 4, and go back to line 2
exe "norm! `bmZ`bmY`cmX`ZmbGo\<esc>ma`amc`b"
" global variable l = 2 (line number)
exe "let g:l=getline('.')"
" go to line 4 and create new line 5
exe "norm! `co"
" write 'x' * (ord(g:l[index]) % 32 + 1) 
exe "norm! ".(strgetchar(g:l[0:], 0) % 32 + 1)."ax"
" go to first char at line, replace first char with 'X', create new line
exe "norm! ^rXo"
exe "norm! ".(strgetchar(g:l[1:], 0) % 32 + 1)."ax"
exe "norm! ^rXo"
exe "norm! ".(strgetchar(g:l[2:], 0) % 32 + 1)."ax"
exe "norm! ^rXo"
exe "norm! ".(strgetchar(g:l[3:], 0) % 32 + 1)."ax"
exe "norm! ^rXo"
exe "norm! ".(strgetchar(g:l[4:], 0) % 32 + 1)."ax"
exe "norm! ^rXo"
exe "norm! ".(strgetchar(g:l[5:], 0) % 32 + 1)."ax"
exe "norm! ^rXo"
exe "norm! ".(strgetchar(g:l[6:], 0) % 32 + 1)."ax"
exe "norm! ^rXo"
exe "norm! ".(strgetchar(g:l[7:], 0) % 32 + 1)."ax"
exe "norm! ^rXo"
exe "norm! ".(strgetchar(g:l[8:], 0) % 32 + 1)."ax"
exe "norm! ^rXo"
exe "norm! ".(strgetchar(g:l[9:], 0) % 32 + 1)."ax"
exe "norm! ^rXo"
exe "norm! ".(strgetchar(g:l[10:], 0) % 32 + 1)."ax"
exe "norm! ^rXo"
exe "norm! ".(strgetchar(g:l[11:], 0) % 32 + 1)."ax"
exe "norm! ^rXo"
exe "norm! ".(strgetchar(g:l[12:], 0) % 32 + 1)."ax"
exe "norm! ^rXo"
exe "norm! ".(strgetchar(g:l[13:], 0) % 32 + 1)."ax"
exe "norm! ^rXo"
exe "norm! ".(strgetchar(g:l[14:], 0) % 32 + 1)."ax"
exe "norm! ^rXo"
exe "norm! ".(strgetchar(g:l[15:], 0) % 32 + 1)."ax"
exe "norm! ^rXo"
