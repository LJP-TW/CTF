// Winmagic.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include <iostream>
#include <io.h>
#define _CRT_RAND_S  
#include <stdlib.h>
#include <time.h>
#include <windows.h>


void get_flag() {
	int password;
	int magic;
	HANDLE hstdin;
	srand(time(NULL));
	char key[] = "Do_you_know_why_my_teammate_Orange_is_so_angry?????";
	char cipher[] = {00,00,00,00...};
	password = rand();

	printf("Give me maigc :");

	scanf_s("%d", &magic);
	if (password == magic) {
		for (int i = 0; i < sizeof(cipher); i++) {
			printf("%c", cipher[i] ^ key[i]);
		}
	}


};


int main()
{
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stdin, NULL, _IONBF, 0);
	get_flag();
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
