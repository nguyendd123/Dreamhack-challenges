#ifndef INTEGER_PIPE_HEADER
#define INTEGER_PIPE_HEADER

#include "Types.h"
#include "Common.h"
#include "Stream.h"
#include "Compressor.h"
#include "Decompressor.h"

class IntegerArchiver
    : public IntegerCompressor, public IntegerDecompressor, public IntegerStream {
public:
    IntegerArchiver();

    void add(uint64 x);
    uint64 del();
    void compress();
    void decompress();
    virtual void error(const char* msg);
};

#endif