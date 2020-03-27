#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#define BASE 40

char *s_ptr;
char *f_ptr;
char *q_ptr;
int s_flag;
int f_flag;
int q_flag;

void add()
{
    char buf[4];
    char *ptr;
    unsigned int choice;
    puts("What secret do you want to keep?");
    puts("1. Small secret");
    puts("2. Big secret");
    if(!q_flag)
        puts("3. Keep a huge secret and lock it forever");
    memset(buf, 0 ,sizeof(buf));
    read(0, buf, sizeof(buf));
    choice = atoi(buf);

    switch(choice)
    {
        case 1:
            if(f_flag)
                return;
            f_ptr = calloc(1, BASE);
            f_flag = 1;
            puts("Tell me your secret: ");
            read(0, f_ptr, BASE);
            break;
        case 2:
            if(s_flag)
                return;
            s_ptr = calloc(1, BASE*100);
            s_flag = 1;
            puts("Tell me your secret: ");
            read(0, s_ptr, BASE*100);
            break;
        case 3:
            if(q_flag)
                return;
            q_ptr = calloc(1, BASE*10000);
            q_flag = 1;
            puts("Tell me your secret: ");
            read(0, q_ptr, BASE*10000);
            break;
    }

}

void del()
{
    char buf[4];
    int choice;
    puts("Which Secret do you want to wipe?");
    puts("1. Small secret");
    puts("2. Big secret");
    memset(buf, 0, sizeof(buf));
    read(0, buf, sizeof(buf));
    choice = atoi(buf);

    switch(choice)
    {
        case 1:
            free(f_ptr);
            f_flag = 0;
            break;
        case 2:
            free(s_ptr);
            s_flag = 0;
            break;
    }

}

void update()
{
    char buf[4];
    int choice;
    puts("Which Secret do you want to renew?");
    puts("1. Small secret");
    puts("2. Big secret");
    memset(buf, 0, sizeof(buf));
    read(0, buf, sizeof(buf));
    choice = atoi(buf);

    switch(choice)
    {
        case 1:
            if(f_flag)
            {
                puts("Tell me your secret: ");
                read(0, f_ptr, BASE);
            }
            break;
        case 2:
            if(s_flag)
            {
                puts("Tell me your secret: ");
                read(0, s_ptr, BASE*100);
            }
            break;
    }
    
}

void handler(){
    puts("Timeout!");
    exit(1);
}

void init_prog(){

    setvbuf(stdout, 0,2,0);
    signal(SIGALRM, handler);
    alarm(60);
}


int main()
{
    init_prog();
    puts("Waking Sleepy Holder up ...");
    int fd = open("/dev/urandom", O_RDONLY);
    unsigned int rand_size;
    read(fd, &rand_size, sizeof(rand_size));
    rand_size %= 4096;
    malloc(rand_size);
    sleep(3);
    char buf[4];
    unsigned int choice;
    puts("Hey! Do you have any secret?");
    puts("I can help you to hold your secrets, and no one will be able to see it :)");
    while(1){
        puts("1. Keep secret");
        puts("2. Wipe secret");
        puts("3. Renew secret");

        memset(buf, 0 ,sizeof(buf));
        read(0, buf, sizeof(buf));
        choice = atoi(buf);
        switch(choice){
            case 1:
                add();
                break;
            case 2:
                del();
                break;
            case 3:
                update();
                break;
        }
    }

}
