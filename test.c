
#include <stdio.h>

char ubuf1[0x7fff];
char ubuf2[0x3fff];

char ibuf[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};

int main() {
	printf("Sizes: ubuf1=%6u, ubuf2=%6u\n", sizeof ubuf1, sizeof ubuf2);
	return 0;
}
