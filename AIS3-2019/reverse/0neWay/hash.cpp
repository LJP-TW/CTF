#include <iostream>

using namespace std;

int main()
{
    unsigned long long int arr[] = {20};
    unsigned long long int r = 0x1505;
    for(int i = 0; i < 1; ++i)
    {
        r *= 33;
        r += arr[i];
    }

    printf("0x%llx\n", r);

    return 0;
}
