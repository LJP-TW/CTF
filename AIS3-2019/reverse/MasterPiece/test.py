#!/usr/bin/python

def main():
    fi = open('./color.txt', 'rb')
    try:
        byte = fi.read(1)
        print ord(byte)

    finally:
        fi.close()
    fi.close()

if __name__ == "__main__":
    main()
