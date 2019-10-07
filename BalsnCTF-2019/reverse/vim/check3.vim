" v += 1
exe "norm! IX\<esc>"
exe "norm! `dma`Imd`Jmc`Kmb`ame"
" delete x, v
exe "norm! `dV}dggmd`cV}dggmc"
exe "norm! `ema`Nme`Omd`Pmc`Qmb`amg`emR`fmQ`bmP`cmO`dmN`Qmb`Rmc"
exe "norm! Go\<esc>ma`amd"
" v = (global + w1 - 2) mod 32
exe "norm! `byy`dP`cyy`dP`d{jmd`dJxx^x"
exe ":s/\\(x\\{32}\\)*//g"

" v += 1
exe "norm! IX\<esc>"
exe "norm! `dma`Nmd`Omc`Pmb`ame"
" delete w1
exe "norm! `fV}dggmf"
exe "norm! `emR`gmQ`bmP`cmO`dmN`Qmb`Rmc"
" v2 = (v + w2 - 2) mod 32
exe "norm! Go\<esc>ma`amd`byy`dP`cyy`dP`d{jmd`dJxx^x"
exe ":s/\\(x\\{32}\\)*//g"

" v2 += 1
exe "norm! IX\<esc>"
exe "norm! `dma`Nmd`Omc`Pmb`amf"
" delete v, w2
exe "norm! `eV}dggme`gV}dggmg`fyy`dP`fV}dggmf"

exe "norm! `b1jmb`c1jmc`d{jmdxJ`dma`Smg`Tmf`Ume`Vmd`Wmc`Xmb`amf`fmZ`bmY`cmX`Zmb`bmW`bmV`Wmb"
exe "norm! `bV}yGpma`Vmb`amc`c"
