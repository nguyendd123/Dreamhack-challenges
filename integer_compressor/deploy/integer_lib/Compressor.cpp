#include "Compressor.h"
#include "Archiver.h"

IntegerCompressor::IntegerCompressor(IntegerStream* stream_)
    : stream(stream_)
{
    
}

void IntegerCompressor::pack_byte(uint8 x)
{
    stream->add_uint8(x);

    vec_element_types.push_back(BYTE_TYPE);
}

void IntegerCompressor::pack_word(uint16 x)
{
    if ( x < 0x80 ) {
        stream->add_uint8(static_cast<uint8>(x));
    }
    else if ( x < 0x4000 ) {
        stream->add_uint16(x | 0x8000);
    }
    else {
        stream->add_uint8(0xff);
        stream->add_uint16(x);
    }

    vec_element_types.push_back(WORD_TYPE);
}

void IntegerCompressor::pack_dword(uint32 x)
{
    if ( x < 0x80 ) {
        stream->add_uint8(static_cast<uint8>(x));
    }
    else if ( x < 0x4000 ) {
        stream->add_uint16(static_cast<uint16>(x | 0x8000));
    }
    else if ( x < 0x20000000 ) {
        stream->add_uint32(x | 0xC0000000);
    }
    else {
        stream->add_uint8(0xff);
        stream->add_uint32(x);
    }

    vec_element_types.push_back(DWORD_TYPE);
}

void IntegerCompressor::pack_qword(uint64 x)
{
    pack_dword(static_cast<uint32>(x));
    pack_dword(static_cast<uint32>(x >> 32));
    
    vec_element_types.push_back(QWORD_TYPE);
}