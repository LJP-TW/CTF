#!/bin/sh
gcc -o exploit -static -pthread exploit.c
cp ./exploit ./initramfs/home/pwn/exploit
cd initramfs
find . | cpio -H newc -o > ../rootfs.cpio
cd ..
# cat rootfs.cpio | gzip > rootfs.cpio.gz