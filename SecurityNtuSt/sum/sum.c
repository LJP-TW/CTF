#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

FILE *f;
int sum = 0;
int i = 0;

void get_shell()
{
	execl("/bin/sh", "sh", NULL);
}

void chall()
{
	int array[16] = { 0 };
	while(fscanf(f, "%d", &array[i++]) != EOF) {
		sum += array[i - 1];
	}
	printf("Sum = %d\n", sum);
}

int main(int argc, char *argv[])
{
	alarm(600);
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);

	f = fopen(argv[1], "r");
	if(f == NULL) {
		puts("Can not open file");
		exit(1);
	}
	chall();
	fclose(f);
}
