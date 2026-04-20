#include "Decompressor.h"
#include "Archiver.h"

IntegerDecompressor::IntegerDecompressor(IntegerStream* stream_)
    : stream(stream_)
{
    
}

uint8 IntegerDecompressor::unpack_byte()
{
    if ( stream->size() == 0 )
        reinterpret_cast<IntegerArchiver*>(stream)->error("No more data");
    
    return stream->del_uint8();
}

uint16 IntegerDecompressor::unpack_word()
{
    uint16 x = unpack_byte();

    if ( x & 0x80 ) {
        if ( (x & 0xC0) == 0xC0 )
            x = (unpack_byte() << 8) | unpack_byte();
        else
            x = ((x & 0x7f) << 8) | unpack_byte();
    }

    return x;
}

uint32 IntegerDecompressor::unpack_dword()
{
    uint32 x = unpack_byte();

    if ( x & 0x80 ) {
        if ( (x & 0xC0) == 0xC0 ) {
            if ( (x & 0xE0) == 0xE0 )
                x = (unpack_byte() << 24) | (unpack_byte() << 16) |
                    (unpack_byte() << 8) | unpack_byte();
            else
                x = ((x & 0x3f) << 24) | (unpack_byte() << 16) |
                    (unpack_byte() << 8) | unpack_byte();
        }
        else
            x = ((x & 0x7f) << 8) | unpack_byte();
    }

    return x;
}

uint64 IntegerDecompressor::unpack_qword()
{
    return unpack_dword() | (static_cast<uint64>(unpack_dword()) << 32);
}