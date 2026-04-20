#ifndef INIT_CPP
#define INIT_CPP
#include <csignal>
#include <cstdlib>
#include <unistd.h>
#include "integer_lib/Types.h"

void getshell()
{
    system("/bin/sh");
}

void alarm_handler(int trash)
{
    std::cout << "Time out" << std::endl;
    exit(-1);
}

void __attribute__((constructor)) init(void)
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    signal(SIGALRM, alarm_handler);
    alarm(30);
}

void print_banner()
{
    std::cout << "Welcome to integer compression service\n";
}

#define ADD_CMD         1
#define DEL_CMD         2
#define COMPRESS_CMD    3
#define EXIT_CMD        4

void print_menu()
{
    std::cout << "\n[Menu]\n";
    std::cout << "1. Add integer\n";
    std::cout << "2. Delete integer\n";
    std::cout << "3. Compress\n";
    std::cout << "4. Exit\n";
}

uint64 read_int(char* prompt_msg = nullptr)
{
    if (prompt_msg)
        std::cout << prompt_msg;

    uint64 x;
    std::cin >> x;
    return x;
}

#endif