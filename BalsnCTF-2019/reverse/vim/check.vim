" v /= 2
exe ":s/xx/x/g"
" if v odd, v += 1
exe "norm! xaxx\<esc>"
exe ":s/^\\(\\%(xx\\)*\\)x\\?$/\\1/g"
" v /= 2
exe ":s/xx/x/g"
" y76 = table36/53[i] * 2 - 2
exe "norm! xIX\<esc>`cma`Kmc`Lmb`amc`bmM`bmL`cmK`Mmb`bmJ`bmI`bmH`cmG`dmF`Imb`JmcGo\<esc>ma`amd`byy`dP`cyy`dP`d{jmd`dJxx^x"
" y mod 32
exe ":s/\\(x\\{32}\\)*//g"
" y += 1
exe "norm! IX\<esc>"
" z = y * 2 - 2
exe "norm! `dma`Fmd`Gmc`Hmb`amb`bmJ`bmI`bmH`cmG`dmF`Imb`JmcGo\<esc>ma`amd`byy`dP`cyy`dP`d{jmd`dJxx^x"
" z mod 32
exe ":s/\\(x\\{32}\\)*//g"
" z += 1
exe "norm! IX\<esc>"
" delete y, x = z * 2 - 2
exe "norm! `dma`Fmd`Gmc`Hmb`amc`bV}dggmb`cmb`bmJ`bmI`bmH`cmG`dmF`Imb`JmcGo\<esc>ma`amd`byy`dP`cyy`dP`d{jmd`dJxx^x"
" x mod 32
exe ":s/\\(x\\{32}\\)*//g"
" x += 1
exe "norm! IX\<esc>"
" delete z
exe "norm! `dma`Fmd`Gmc`Hmb`amc`bV}dggmb`cmb`bma`Kmc`Lmb`amd`dmM`cmL`bmK`cmJ`dmI`Lmb`MmcGo\<esc>ma`amd"
" w = v + x - 2
exe "norm! `byy`dP`cyy`dP`d{jmd`dJxx^x"
" w mod 32
exe ":s/\\(x\\{32}\\)*//g"
