// gcc main.c -o main -z relro -z now
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void init() {
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);
    setbuf(stderr, NULL);
}

int main()
{
    init();
    printf("stderr: %p\n", stderr);
    printf("FSOP?: ");
    read(0, stderr, 0x1f0);
}