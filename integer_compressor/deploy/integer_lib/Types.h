#ifndef INTEGER_TYPE_HEADER
#define INTEGER_TYPE_HEADER

typedef          char   int8;   ///< signed 8 bit value
typedef signed   char   sint8;  ///< signed 8 bit value
typedef unsigned char   uint8;  ///< unsigned 8 bit value
typedef          short  int16;  ///< signed 16 bit value
typedef unsigned short  uint16; ///< unsigned 16 bit value
typedef          int    int32;  ///< signed 32 bit value
typedef unsigned int    uint32; ///< unsigned 32 bit value

typedef long long           int64;  ///< signed 64 bit value
typedef unsigned long long  uint64; ///< unsigned 64 bit value

#define BYTE_TYPE  1
#define WORD_TYPE  2
#define DWORD_TYPE 3
#define QWORD_TYPE 4

#endif