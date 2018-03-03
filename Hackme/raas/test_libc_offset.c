#include <stdio.h>
#include <stdlib.h>

int main()
{
	printf("system > %p\n", (void *)system);
	system("echo 'system call'");
	printf("system > %p\n", (void *)system);
	
	char test[8];
	gets(test);

	return 0;
}
