#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/syscall.h>

int main()
{
    int fd, sz;
    char c[100];

    printf("=> %d\n", O_RDONLY);
//    fd = open("./openReadWrite.txt", O_RDONLY);
    fd = syscall(SYS_open, "./openReadWrite.txt", O_RDONLY, 0);

    if (fd < 0)
        return 1;

//    sz = read(fd, c, 26);
    sz = syscall(SYS_read, fd, c, 26); 
    
//    sz = write(2, c, 26);
    sz = syscall(SYS_write, 2, c, 26);

    close(fd);

    return 0;
}
