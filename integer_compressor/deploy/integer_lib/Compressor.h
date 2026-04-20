#ifndef INTEGER_COMPRESSOR_HEADER
#define INTEGER_COMPRESSOR_HEADER

#include "Types.h"
#include "Common.h"
#include "Stream.h"

class IntegerCompressor {
public:
    IntegerCompressor(IntegerStream* stream_);
protected:
    std::vector<uint8> vec_element_types;

    void pack_byte(uint8 x);
    void pack_word(uint16 x);
    void pack_dword(uint32 x);
    void pack_qword(uint64 x);
private:
    IntegerStream* stream;
};

#endif