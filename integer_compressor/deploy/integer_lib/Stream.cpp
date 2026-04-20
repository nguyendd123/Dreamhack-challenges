#include "Stream.h"

IntegerStream::IntegerStream() : capacity(0x10), start(0), end(0)
{ 
    buf = reinterpret_cast<uint8*>(calloc(sizeof(uint8), capacity));
}

IntegerStream::~IntegerStream()
{ 
    if (buf)
        free(buf);
}

std::string IntegerStream::to_hexstring()
{
    std::stringstream hex_stream;

    for ( int i = start; i < end; i++ ) {
        hex_stream << std::setfill('0') << std::setw(sizeof(uint8) * 2) << std::hex
                    << static_cast<uint>(buf[i]);
    }

    return hex_stream.str();
}

void IntegerStream::capacity_check()
{
    if ( end >= capacity ) {
        capacity *= 2;
        buf = reinterpret_cast<uint8*>(realloc(buf, capacity));
    }
}

void IntegerStream::add_uint8(uint8 x)
{
    capacity_check();

    buf[end++] = x;
}

void IntegerStream::add_uint16(uint16 x)
{
    capacity_check();

    buf[end++] = static_cast<uint8>(x >> 8);
    buf[end++] = static_cast<uint8>(x);
}

void IntegerStream::add_uint32(uint32 x)
{
    capacity_check();

    buf[end++] = static_cast<uint8>(x >> 24);
    buf[end++] = static_cast<uint8>(x >> 16);
    buf[end++] = static_cast<uint8>(x >> 8);
    buf[end++] = static_cast<uint8>(x);
}

uint8 IntegerStream::del_uint8()
{
    if (start >= end)
        return 0;
    
    return buf[start++];
}

uint16 IntegerStream::del_uint16()
{
    return (del_uint8() << 8) | del_uint8();
}

uint32 IntegerStream::del_uint32()
{
    return (del_uint8() << 24) | (del_uint8() << 16) | (del_uint8() << 8) | del_uint8();
}