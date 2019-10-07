" connect 4 string and remove 'X' and mod 32
exe "norm! IX\<esc>`dJ`dma`Gme`Hmd`Imc`Jmb`ame`eyy`dP`eV}dggme`d{jmd`dJxxJxxJxx"
exe ":s/\\(x\\{32}\\)*//g"
