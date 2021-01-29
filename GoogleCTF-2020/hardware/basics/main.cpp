#include "obj_dir/Vcheck.h"

#include <iostream>
#include <memory>

int main(int argc, char *argv[]) {
    Verilated::commandArgs(argc, argv);
    std::cout << "Enter password:" << std::endl;
    auto check = std::make_unique<Vcheck>();

    for (int i = 0; i < 100 && !check->open_safe; i++) {
        int c = fgetc(stdin);
        if (c == '\n' || c < 0) break;
        check->data = c & 0x7f;
        check->clk = false;
        check->eval();
        check->clk = true;
        check->eval();
        std::cout << i << ':' << check->my_test << std::endl;
        std::cout << i << ':' << check->my_test2 << std::endl;
        std::cout << i << " 1:" << check->my_memory1 << std::endl;
        std::cout << i << " 2:" << check->my_memory2 << std::endl;
        std::cout << i << " 3:" << check->my_memory3 << std::endl;
        std::cout << i << " 4:" << check->my_memory4 << std::endl;
        std::cout << i << " 5:" << check->my_memory5 << std::endl;
        std::cout << i << " 6:" << check->my_memory6 << std::endl;
        std::cout << i << " 7:" << check->my_memory7 << std::endl;
        std::cout << i << " 8:" << check->my_memory8 << std::endl;
    }
    std::cout << "Final:" << check->my_test << std::endl;
    std::cout << "Final:" << check->my_test2 << std::endl;
    std::cout << "Final1:" << check->my_memory1 << std::endl;
    std::cout << "Final2:" << check->my_memory2 << std::endl;
    std::cout << "Final3:" << check->my_memory3 << std::endl;
    std::cout << "Final4:" << check->my_memory4 << std::endl;
    std::cout << "Final5:" << check->my_memory5 << std::endl;
    std::cout << "Final6:" << check->my_memory6 << std::endl;
    std::cout << "Final7:" << check->my_memory7 << std::endl;
    std::cout << "Final8:" << check->my_memory8 << std::endl;
    if (check->open_safe) {
        std::cout << "CTF{real flag would be here}" << std::endl;
    } else {
        std::cout << "=(" << std::endl;
    }
    return 0;
}

