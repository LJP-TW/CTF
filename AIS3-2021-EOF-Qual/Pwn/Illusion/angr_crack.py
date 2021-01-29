#!/usr/bin/env python3
import angr
import sys
import claripy

def main():
    pj = angr.Project('illusion')

    state = pj.factory.entry_state()

    fn = b'flag'
    fsize = 64
    content = claripy.BVS('the_flag', fsize * 8)
    flagfile = angr.storage.SimFile(fn, content=content, size=fsize)

    state.fs.insert(fn, flagfile)

    sm = pj.factory.simgr(state)

    target_addr = 0x401d52
    avoid_addr  = 0x401211
    sm.explore(find=target_addr, avoid=avoid_addr)

    if sm.found:
        for sol in sm.found:
            sol0 = sol.solver.eval(content, cast_to=bytes)
            print(sol0)

if __name__ == '__main__':
    main()


