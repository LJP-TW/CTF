" go to line 21, remove empty line 21
exe "norm! `cJ`cma`Xmc`Ymb`amd`b" 
" select line 2 and remove it, go back to file head
exe "norm! V}dgg"
" mark b to 2
" mark c to 2
" mark X,Y,Z to 2
" mark W,V to 19
" mark U,T,S to 1  
exe "norm! mb`cmb`dmc`bmZ`bmY`bmX`cmW`dmV`emU`fmT`gmS`Ymb`ZmcGo\<esc>"
" mark a to 36
" mark d to 36
" mark R to 2
" mark Q to 2
" mark P to 2
" mark O to 36
exe "norm! ma`amd`cmR`bmQ`cmP`dmO`RmbGo\<esc>"
" mark a to 37
" mark c to 37
" mark d to 2
exe "norm! ma`amc`bmd"
" copy flag[0], [4], [8], [12] to line 37, 38, 39, 40
exe "norm! `dyy`cP`d4jmd"
exe "norm! `dyy`cP`d4jmd"
exe "norm! `dyy`cP`d4jmd"
exe "norm! `dyy`cP`b1jmb"
exe "norm! `bmd"
" copy flag[1], [5], [9], [13] to line 41, 42, 43, 44
exe "norm! `dyy`cP`d4jmd"
exe "norm! `dyy`cP`d4jmd"
exe "norm! `dyy`cP`d4jmd"
exe "norm! `dyy`cP`b1jmb"
exe "norm! `bmd"
" copy flag[2], [6], [10], [14] to line 45, 46, 47, 48
exe "norm! `dyy`cP`d4jmd"
exe "norm! `dyy`cP`d4jmd"
exe "norm! `dyy`cP`d4jmd"
exe "norm! `dyy`cP`b1jmb"
exe "norm! `bmd"
" copy flag[3], [7], [11], [15] to line 49, 50, 51, 52
exe "norm! `dyy`cP`d4jmd"
exe "norm! `dyy`cP`d4jmd"
exe "norm! `dyy`cP`d4jmd"
exe "norm! `dyy`cP"

exe "norm! `c{jmc`cma`Omd`Pmc`Qmb`ame`emf`fmR`bmQ`bmP`cmO`dmN`emM`Qmb`RmcGo\<esc>"
exe "norm! ma`amd`bmL`cmK`bmJ`cmI`dmH`emG`Kmb`LmcGo\<esc>"
exe "norm! ma`amd`b"
