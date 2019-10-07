exe "norm! ggdGiWelcome to th1s flag checker written in vim script.\nEnter the flag in Balsn{.+} format and then press <Enter>.\n\nThis script is tested with vim 8.0.1453 + default vimrc (ubuntu 18.04).\nIf it runs very slow, try to disable X11 forwarding before launching vim.\nIt should terminate in 30 seconds.\n\n>\ "
" starti
call cursor(line('.'), col('.') + 1)
inoremap <CR> <Esc>
exe "norm! i Balsn{abcdefghijklmnopr}\n"
