exe "norm! ggJxJxJxJxJxJx^16ld$"
exe ":s/ /_/g"
exe "norm! j"
exe ":s/^> Balsn{\\([a-z_]\\+\\)r}$/\\1/g"
exe ":%s/\\n//g"
" Welcome_to_th1s_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
" select all and ROT13 encoding
exe "norm! ^v$g?"
