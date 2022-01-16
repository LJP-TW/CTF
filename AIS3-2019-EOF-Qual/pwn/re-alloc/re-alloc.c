#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#define TIMEOUT 60
#define MAXSIZE 0x78
#define MAX 2

void handler(int signum){
    puts("Timeout");
    _exit(1);
}

void init_proc(){
    setvbuf(stdin,0,2,0);
    setvbuf(stdout,0,2,0);
    setvbuf(stderr,0,2,0);
    signal(SIGALRM,handler);
    alarm(TIMEOUT);
}

long long read_long(){
    char buf[0x10];
    long long choice ;
    __read_chk(0,buf,0x10,0x11);
    choice = atoll(buf);
    return choice;
}

size_t read_input(char *buf,unsigned int size){
    size_t ret ;
    ret = __read_chk(0,buf,size,size);
    if(ret <= 0){
        puts("read error");
        _exit(1);
    }
    if(buf[ret-1] == '\n')
        buf[ret-1] = '\x00';
    return ret ;
}


char *heap[MAX];
void allocate(){
    size_t idx = 0;
    size_t size = 0 ;
    size_t ret = 0 ;
    char *ptr = NULL;
    printf("Index:");
    idx = read_long();
    if(idx < MAX && !heap[idx]){
        printf("Size:");
        size = read_long();
        if(size > 0x78){
            puts("Too large!");
            return;
        }
        ptr = realloc(NULL,size); // 此處用法形同使用 malloc(size)

        if(!ptr){
            puts("alloc error");
            return;
        }

        heap[idx] = ptr ;
        printf("Data:");
        ret = read_input(heap[idx],size);
        heap[idx][ret] = '\x00';
        return;
    }
    puts("Invalid !");
		
}

void reallocate(){
    size_t idx = 0;
    size_t size = 0 ;
    char *ptr = NULL;
    printf("Index:");
    idx = read_long();
    if(idx < MAX && heap[idx]){

        printf("Size:");
        size = read_long();
        if(size > 0x78){
            puts("Too large!");
            return;
        }
        ptr = realloc(heap[idx],size); // 若 heap[idx] 為 0 則形同使用 malloc(size), 但此 heap[idx] 不可能為 0
                                       // 若 size 為 0 則形同使用 free(heap[idx]), return 0, heap[idx] 不變 => double free

        if(!ptr){
            puts("alloc error");
            return;
        }

        heap[idx] = ptr ;
        printf("Data:");
        read_input(heap[idx],size);
        return ;
    }
    puts("Invalid !");
}

void rfree(){
    size_t idx= 0;
    printf("Index:");
    idx = read_long();
    if(idx < MAX){
        realloc(heap[idx],0); // 若 heap[idx] 為 0 則形同使用 malloc(0);
	    heap[idx] = NULL ;
        return ;
    }
    puts("Invalid !");
}

void menu(){
    puts("$$$$$$$$$$$$$$$$$$$$$$$$$$$$");
    puts("🍊      RE Allocator      🍊");
    puts("$$$$$$$$$$$$$$$$$$$$$$$$$$$$");
    puts("$   1. Alloc               $");
    puts("$   2. Realloc             $");
    puts("$   3. Free                $");
    puts("$   4. Exit                $");
    puts("$$$$$$$$$$$$$$$$$$$$$$$$$$$");
    printf("Your choice: ");
}

int main(void){
    int choice = 0;
    init_proc();
    while(1){
        menu();
        scanf("%d",&choice);
	switch(choice){
            case 1:
                allocate();
                break;
            case 2:
                reallocate();
                break;
            case 3:
                rfree();
                break;
            case 4:
                _exit(0);
                break ;
            default:
                puts("Invalid Choice");
                break;
        }
    }
}
