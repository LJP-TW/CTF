#include <stdio.h>
#include <stdlib.h>

typedef struct _exe {
    void (*fp)(char *);
    char *msg;
} exe;

typedef struct _info {
    int id;
    char name[8];
} info;

void echo(char *msg)
{
    printf("%s\n", msg);
}

void execute(char *msg)
{
    system(msg);
}

int main()
{ 
    info *myInfo = malloc(sizeof(info) * 1);
    exe *program = malloc(sizeof(exe) * 1);
   
    program->fp = echo;
    program->msg = "You're welcome! Try to execute /bin/sh";

    printf("Your id : ");
    scanf("%d", &myInfo->id);
    getchar();

    printf("Your name : ");
    gets(myInfo->name);

    program->fp(program->msg);
}
