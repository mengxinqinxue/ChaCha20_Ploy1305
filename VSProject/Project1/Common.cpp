#include "Common.h"

void str_Char2Hex(char* charBuff, char* hexBuff)
{
    char aH, aL;
    int i = 0;
    int j = 0;
    long int len = strlen(charBuff);
    for (j = 0; j < len; j++)
    {
        aH = toupper(charBuff[j]); 
        aL = toupper(charBuff[++j]);
        if (aH > 0x39)
            aH -= 0x37;
        else
            aH -= 0x30;

        if (aL > 0x39)
            aL -= 0x37;
        else
            aL -= 0x30;
        hexBuff[i] = (aH << 4) | aL;
        i++;
    }
}

void str_Hex2Char(char* hexBuff, int hlen, char* charBuff)
{
    char szTmp[3];
    for (int i = 0; i < hlen; i++)
    {
        sprintf_s(szTmp, "%02x", (unsigned char)hexBuff[i]);
        memcpy(&charBuff[i * 2], szTmp, 2);
    }
}

void XOR_U8(void* src1, void* src2, void* dst, uint32_t len)
{
    uint8_t* a = (uint8_t*)src1;
    uint8_t* b = (uint8_t*)src2;
    uint8_t* c = (uint8_t*)dst;
    while (len--)
    {
        (*c++) = (*a++) ^ (*b++);
    }
}

void str_reverse(unsigned char* str, int len)
{
    char tmp;
    int mid = len / 2;
    for (int i = 0; i < mid; i++)
    {
        tmp = str[i];
        str[i] = str[len - i - 1];
        str[len - i - 1] = tmp;
    }
}

void memcpy_(void* dst, void* src, uint32_t size)
{
    uint8_t* a = (uint8_t*)dst;
    uint8_t* b = (uint8_t*)src;

    uint32_t* aa = (uint32_t*)dst;
    uint32_t* bb = (uint32_t*)src;
    uint32_t i, count, tmp;

    if ((((uint32_t)dst) & 3) || (((uint32_t)src) & 3)) {
        while (size--) {
            *a++ = *b++;
        }
    }
    else {
        count = size / 4;

        for (i = 0; i < count; i++) {
            *aa++ = *bb++;
        }

        tmp = size & 3;

        if (tmp) {
            a += (size & (~0x03));
            b += (size & (~0x03));

            while (tmp--) {
                *a++ = *b++;
            }
        }
    }
}

