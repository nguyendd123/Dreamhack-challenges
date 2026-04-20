#ifndef INTEGER_DECOMPRESSOR_HEADER
#define INTEGER_DECOMPRESSOR_HEADER

#include "Types.h"
#include "Common.h"
#include "Stream.h"


class IntegerDecompressor {
public:
    IntegerDecompressor(IntegerStream* stream_);
protected:
    uint8 unpack_byte();
    uint16 unpack_word();
    uint32 unpack_dword();
    uint64 unpack_qword();
private:
    IntegerStream* stream;
};

#endif