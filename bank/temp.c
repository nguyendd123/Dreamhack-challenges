#include <stdio.h>
#define __int32 __int32_t
#define __int64 __int64_t
#define Account

struct Account // sizeof=0x18
{
    int in_use;
    int account_type;
    int *account_number;
    __int64 balance;
};

struct User
{
    __int32 unknown1;
    __int32 stt;
    char id[8];
    char password[8];
    __int32 cnt;
    __int32 unknown2;
    Account *accounts[10];
};


int main(){

}