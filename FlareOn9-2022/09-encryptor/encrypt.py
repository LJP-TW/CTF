#!/usr/bin/env python3
import copy

def cipherStep4_2_4015BE(num0, num1, num2):
    output = 0
    while True:
        cf = num1 & 1
        num1 = num1 >> 1

        if num1 == 0:
            break

        if cf != 0:
            output += num0
            output -= num2
            if output < num2:
                output += num2

        cf = num0 & 1
        num0 = num0 << 1
        num0 -= num2
        if num0 < num2:
            num0 += num2
    return output

def inverse_4015be(output, num2):
    # TODO


def cipherStep4_4016CC(num0, num1, num2):
    output = 1
    while True:
        cf = num1 & 1
        num1 = num1 >> 1

        if num1 == 0:
            break

        if cf != 0:
            output = cipherStep4_2_4015BE(output, num0, num2)
        num0 = cipherStep4_2_4015BE(num0, num0, num2)
    return output

def inverse_4016cc(output, num1, num2):
    orderlist = []
    while True:
        cf = num1 & 1
        num1 = num1 >> 1

        if num1 == 0:
            break
        
        if cf != 0:
            orderlist.append(1)
        else:
            orderlist.append(0)
    orderlist = orderlist[::-1]
    skip = 1
    for i in orderlist:
        if i == 1:
            num0 = inverse_4015be(output, output, num2)
            skip = 0
        else:
            if skip == 1:
                continue
            num0 = inverse_4015be(num0, num0, num2)
    assert(output == 1)
    return num0
