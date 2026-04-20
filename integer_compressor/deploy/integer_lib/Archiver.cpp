#include <cstdio>
#include "Archiver.h"

IntegerArchiver::IntegerArchiver()
    : IntegerCompressor(this), IntegerDecompressor(this)
{

}

void IntegerArchiver::add(uint64 x)
{
    if ( x <= 0xFF )
        pack_byte(static_cast<uint8>(x));
    else if ( x <= 0xFFFF )
        pack_word(static_cast<uint16>(x));
    else if ( x <= 0xFFFFFFFF )
        pack_dword(static_cast<uint32>(x));
    else
        pack_qword(static_cast<uint64>(x));
}

uint64 IntegerArchiver::del()
{
    if ( vec_element_types.size() == 0)
        error("No more data");

    int type = vec_element_types.front();
    vec_element_types.erase(vec_element_types.begin());

    if ( type == BYTE_TYPE )
        return static_cast<uint64>(unpack_byte());
    else if ( type == WORD_TYPE )
        return static_cast<uint64>(unpack_word());
    else if ( type == DWORD_TYPE )
        return static_cast<uint64>(unpack_dword());
    else if ( type == QWORD_TYPE )
        return static_cast<uint64>(unpack_qword());
    else
        error("Invalid element type");
}

void IntegerArchiver::compress()
{
    std::cout << "[+] Compressed size : " << size() << '\n';
    std::cout << "[+] Compressed data : " << to_hexstring() << '\n';
}

void IntegerArchiver::decompress()
{
    return;
}

void IntegerArchiver::error(const char* msg)
{
    std::cerr << msg << '\n';
    exit(EXIT_FAILURE);
}