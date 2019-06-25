#!/usr/bin/python

def main():
    width = 650
    height = 410
    fi = open('./color.txt', 'rb')
    fo = open('./output.txt', 'a')
    try:
        for h in range(height):
            for w in range(width):
                byte = fi.read(1)
                if ord(byte) == 1:
                    fo.write('1')
                else:
                    fo.write('0')
            fo.write('\n')

    finally:
        fi.close()
        fo.close()
    fi.close()
    fo.close()

if __name__ == "__main__":
    main()
