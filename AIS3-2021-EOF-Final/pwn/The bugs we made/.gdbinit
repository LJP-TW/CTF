define clearflag
    # set _IO_2_1_stdin_.file._IO_read_ptr = 0
    set _IO_2_1_stdout_.file._mode = 0

    set _IO_file_jumps.__finish = 0x54871
    set _IO_file_jumps.__pbackfail = 0x54872
    set _IO_file_jumps.__xsgetn = 0x54873
    set _IO_file_jumps.__seekoff = 0x54874
    set _IO_file_jumps.__seekpos = 0x54875
    set _IO_file_jumps.__setbuf = 0x54876
    set _IO_file_jumps.__sync = 0x54877
    set _IO_file_jumps.__doallocate = 0x54878
    set _IO_file_jumps.__seek = 0x54879
    set _IO_file_jumps.__close = 0x5487a
    set _IO_file_jumps.__stat = 0x5487b
    set _IO_file_jumps.__showmanyc = 0x5487c
    set _IO_file_jumps.__imbue = 0x5487d
end

# b *__vfscanf_internal+1691

b *__run_exit_handlers+140
b *__run_exit_handlers+198
