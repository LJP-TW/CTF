#include <stdio.h>
#include <unistd.h>

void get_shell()
{
	execl("/bin/sh", "sh", NULL);
}

void chall()
{
	int array[16] = { 0 };
	while(1) {
		puts("1. Read\n2. Write\n3. Dump\n?. Exit\n");
		printf("Your choice: ");
		int opt, idx, val, i;
		scanf("%d", &opt);
		switch (opt) {
			case 1:
				puts("Read");
				printf("Index ( 0 ~ 15 ) = ");
				scanf("%d", &idx);
				printf("Array[%d] = %d\n", idx, array[idx]);
				break;
			case 2:
				puts("Write");
				printf("Index ( 0 ~ 15 ) = ");
				scanf("%d", &idx);
				printf("Value = ");
				scanf("%d", &val);
				array[idx] = val;
				printf("Array[%d] = %d\n", idx, array[idx]);
				break;
			case 3:
				puts("Dump");
				printf("How many ( 1 ~ 15 ) = ");
				scanf("%d", &idx);
				for(i = 0; i < idx; i++) {
					printf("Array[%d] = %d\n", i, array[i]);
				}
				break;
			default:
				puts("Bye! Don't forget to capture the flag");
				return;
		}
	}
}

int main()
{
	alarm(600);
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);
	printf("control EIP to %p to get a shell!\n", &get_shell);
	chall();
}
