#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct chunk {
    size_t prev_size;
    size_t size;
    struct chunk *fd;
    struct chunk *bk;
    char buf[10];
};

int main()
{
    char *a = malloc(10);
    struct chunk c;
    c.size = 0x20;
     
    printf("c.fd: attacker's data\n");
    strcpy((char *)&c.fd, "attacker's data");

    // printf("free a\n");
    free(a);

    *((unsigned long long *)a) = (unsigned long long)&c;

    // printf("malloc 10\n");
    malloc(10);

    // printf("allocate victim\n");
    char *victim = malloc(10);
    printf("%s\n", victim);

    return 0;
}