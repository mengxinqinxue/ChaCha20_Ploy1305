#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdint.h>

void str_Char2Hex(char* charBuff, char* hexBuff);
void str_Hex2Char(char* hexBuff, int hlen, char* charBuff);
void XOR_U8(void* src1, void* src2, void* dst, uint32_t len);
void str_reverse(unsigned char* str, int len);
void memcpy_(void* dst, void* src, uint32_t size);

#define big_little_swap32(x) ((x & 0x000000ff) << 24 ) | ((x & 0x0000ff00) << 8) | ((x & 0x00ff0000) >> 8) | ((x & 0xff000000 ) >> 24);

#define CYCLE_LSHIFT_NBIT_TYPE(data, nbit, type) ((type)((data >> (sizeof(type) << 3) - nbit) | (data << nbit)));


