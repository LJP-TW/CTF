#include<stdio.h>
#include<stdlib.h>
#include<fcntl.h>



void init(){
    setvbuf(stdout,0,2,0);
    setvbuf(stdin,0,2,0);
    setvbuf(stderr,0,2,0);
}

int read_int(){
    char buf[0x10];
    __read_chk( 0 , buf , 0xf , 0x10 );
    return atoi( buf );
}

void welcome_func(){
    puts( "Hello ~~~" );
}

void bye_func(){
    puts( "Bye ~~~" );
}

void menu(){
    puts( "1. add a box" );
    puts( "2. exit" );
    puts( ">" );
}

struct MessegeBox{
    void (*welcome)();
    void (*bye)();
};

void backdoor(){
    system("sh");
}

int main(){

    init();
    
    struct MessegeBox* msgbox = (struct MessegeBox*) malloc( sizeof( struct MessegeBox ) );

    msgbox->welcome = welcome_func;
    msgbox->bye = bye_func;

    msgbox->welcome();
    free( msgbox );

    int n = 3, size;
    char *msg;

    while( n-- ){
        printf( "Size of your messege: " );
        size = read_int();
        
        msg = (char*) malloc( size );

        printf( "Messege: " );
        read( 0 , msg , size );

        printf( "Saved messege: %s\n" , msg );

        free( msg );
    }

    msgbox->bye();
    
    return 0;
}