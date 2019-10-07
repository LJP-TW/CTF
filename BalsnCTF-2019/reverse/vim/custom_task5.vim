" put flag[0] to line 55, put 'X' to line 56
exe "norm! yy`dP`dOX\<esc>"
" ???
" line 55: flag[0][2:]
" line 56: flag[0][1:]
exe "norm! me`d{jmd`dx`cyy`eP`dvyjPxxVy`epkJx`dxjV`ekd`ex"
" line 56 mod 32
exe ":s/\\(x\\{32}\\)*//g"
