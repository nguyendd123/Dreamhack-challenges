#ifndef INTEGER_STREAM_HEADER
#define INTEGER_STREAM_HEADER

#include <vector>
#include <string>
#include <iomanip>
#include "Types.h"
#include "Common.h"

class IntegerStream {
private:
    uint8* buf;
    uint capacity;
    uint start;
    uint end;

    void capacity_check();
public:
    IntegerStream();
    ~IntegerStream();
    inline uint size() { return end - start; };
    

    void add_uint8(uint8 x);
    void add_uint16(uint16 x);
    void add_uint32(uint32 x);

    uint8 del_uint8();
    uint16 del_uint16();
    uint32 del_uint32();

    std::string to_hexstring();
};

#endif