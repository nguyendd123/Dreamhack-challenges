#include <iostream>
#include <vector>

#include "integer_lib/Archiver.h"
#include "Common.cpp"

int main(void)
{
    print_banner();

    IntegerArchiver* archiver = new IntegerArchiver;

    while (1) {
        print_menu();

        uint64 cmd = read_int(">> ");
        
        if ( cmd == ADD_CMD )
            archiver->add(read_int("[?] value = "));
        else if ( cmd == DEL_CMD )
            std::cout << "[+] value = " << archiver->del() << '\n';
        else if ( cmd == COMPRESS_CMD )
            archiver->compress();
        else if ( cmd == EXIT_CMD )
            break;
        else
            std::cerr << "[!] Invalid command\n"; 
    }

    delete archiver;
}