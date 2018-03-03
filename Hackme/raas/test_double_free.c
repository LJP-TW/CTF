#include <stdio.h>
#include <stdlib.h>
#define DEBUG 1

int main()
{
	char *p = malloc(32);
	char *q = malloc(32);

#if DEBUG == 1
//  Result in Success !?!?!
	free(p);
	free(q);
	free(p);
#elif DEBUG == 2
//  Result in Segment fault lol
	free(p);
	free(p);
	free(q);
#endif
	return 0;
}
