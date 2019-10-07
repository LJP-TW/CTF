" w += 1
exe "norm! IX\<esc>"
" delete x
exe "norm! `dma`Imd`Jmc`Kmb`ame"
" delete v
exe "norm! `dV}dggmd`cV}dggmc"
exe "norm! `ema`Nme`Omd`Pmc`Qmb`amf`cmR`bmQ`cmP`dmO`emN`Rmb`bmM`bmL`cmK`MmbGo\<esc>ma`amc"
" from table53[0] copy to 74 and if odd, += 1 
exe "norm! `byy`cP`c{jmc`cxaxx\<esc>"
exe ":s/^\\(\\%(xx\\)*\\)x\\?$/\\1/g"
