#include "ChaCha20_Ploy1305.h"
#include "Common.h"

#define CHACHA20_KEY_STREAM_BYTE (64)
#define CHACHA20_KEY_BYTE (32)
#define POLY1305_KEY_BYTE (32)
#define POLY1305_BLOCK_BYTE (16)
#define POLY1305_TAG_BYTE (16)


uint8_t Poly1305_Clamp_R(uint8_t r[16])
{
    if (NULL == r)
    {
        return 1;
    }
    else
    {
        ;
    }

    r[3] &= 15;
    r[7] &= 15;
    r[11] &= 15;
    r[15] &= 15;
    r[4] &= 252;
    r[8] &= 252;
    r[12] &= 252;

    //big little endian swap
    str_reverse(r, 16);

    return 0;
}

int BN_Add(char* strHex_M, char* strHex_D, char* strHex_Res)
{
    BIGNUM* pBNa = BN_new();
    BIGNUM* pBNb = BN_new();
    BIGNUM* pBNr = BN_new();

    BN_hex2bn(&pBNa, strHex_M);
    BN_hex2bn(&pBNb, strHex_D);
    BN_add(pBNr, pBNa, pBNb);
    char* pR = BN_bn2hex(pBNr);
    strcpy_s(strHex_Res, strlen(pR) + 1, pR);

    OPENSSL_free(pR);
    BN_free(pBNa);
    BN_free(pBNb);
    BN_free(pBNr);

    return 0;
}

int BN_Mul(char* strHex_M, char* strHex_D, char* strHex_Res)
{
    BIGNUM* pBNa = BN_new();
    BIGNUM* pBNb = BN_new();
    BIGNUM* pBNr = BN_new();
    BN_CTX* ctx = BN_CTX_new();

    BN_hex2bn(&pBNa, strHex_M);
    BN_hex2bn(&pBNb, strHex_D);
    BN_mul(pBNr, pBNa, pBNb, ctx);
    char* pR = BN_bn2hex(pBNr);
    strcpy_s(strHex_Res, strlen(pR) + 1, pR);

    OPENSSL_free(pR);
    BN_free(pBNa);
    BN_free(pBNb);
    BN_free(pBNr);
    BN_CTX_free(ctx);

    return 0;
}


int BN_Mod(char* strHex_M, char* strHex_D, char* strHex_Res)
{
    BIGNUM* pBNm = BN_new();
    BIGNUM* pBNd = BN_new();
    BIGNUM* pBNdv = BN_new();
    BIGNUM* pBNrem = BN_new();
    BN_CTX* ctx = BN_CTX_new();

    BN_hex2bn(&pBNm, strHex_M);
    BN_hex2bn(&pBNd, strHex_D);
    BN_div(pBNdv, pBNrem, pBNm, pBNd, ctx);
    char* pdv = BN_bn2hex(pBNdv);
    char* prem = BN_bn2hex(pBNrem);
    strcpy_s(strHex_Res, strlen(prem) + 1, prem);

    OPENSSL_free(pdv);
    OPENSSL_free(prem);
    BN_free(pBNm);
    BN_free(pBNd);
    BN_free(pBNdv);
    BN_free(pBNrem);
    BN_CTX_free(ctx);

    return 0;
}


uint8_t Ploy1305_Get_Tag(uint8_t* key, uint8_t* msg, uint32_t msglen, uint8_t* Tag)
{
    const uint8_t P[] = "3fffffffffffffffffffffffffffffffb";
    uint8_t acc[POLY1305_KEY_BYTE + 1] = { 0 };
    uint8_t r[POLY1305_KEY_BYTE / 2 + 1] = { 0 };
    uint8_t strRes_char[POLY1305_KEY_BYTE * 2 + 2] = { 0 };
    uint8_t acc_char[POLY1305_KEY_BYTE + 4] = { 0 };
    uint8_t block_buf[POLY1305_BLOCK_BYTE + 1] = { 0 };
    uint8_t block_buf_char[POLY1305_BLOCK_BYTE * 2 + 4] = { 0 };
    uint8_t r_char[POLY1305_KEY_BYTE + 1] = { 0 };
    uint8_t s_char[POLY1305_KEY_BYTE + 1] = { 0 };
    uint8_t last_block_len = POLY1305_BLOCK_BYTE;
    uint8_t* s = key + POLY1305_BLOCK_BYTE;
    uint32_t round = msglen / POLY1305_BLOCK_BYTE;

    if (NULL == key || NULL == msg || NULL == Tag)
    {
        return 1;
    }
    else
    {
        ;
    }

    memcpy(r, key, POLY1305_BLOCK_BYTE);

    Poly1305_Clamp_R(r);

    if (0x00 != msglen % POLY1305_BLOCK_BYTE)
    {
        round++;
        last_block_len = msglen % POLY1305_BLOCK_BYTE;
    }
    else
    {
        last_block_len = POLY1305_BLOCK_BYTE;
    }

    str_Hex2Char((char*)acc, POLY1305_BLOCK_BYTE + 1 , (char*)acc_char);

    for (int i = 0; i < round; i++)
    {
        //plaintext_block with 0x01 byte 
        block_buf[0] = 0x01;

        if (i < round - 1)
        {

            memcpy(block_buf + 1, msg + i * POLY1305_BLOCK_BYTE, POLY1305_BLOCK_BYTE);
            str_reverse(block_buf + 1, POLY1305_BLOCK_BYTE);
            str_Hex2Char((char*)block_buf, POLY1305_BLOCK_BYTE + 1, (char*)block_buf_char);
        }
        else
        {
            memcpy(block_buf + 1, msg + i * POLY1305_BLOCK_BYTE, last_block_len);
            str_reverse(block_buf + 1, last_block_len);
            str_Hex2Char((char*)block_buf, last_block_len + 1, (char*)block_buf_char);
            *(block_buf_char + (2 * (last_block_len + 1))) = 0x00;
        }

        //Acc + plaintext_block
        BN_Add((char*)acc_char, (char*)block_buf_char, (char*)strRes_char);

        //(Acc+plaintext_block) * r
        str_Hex2Char((char*)r, POLY1305_BLOCK_BYTE, (char*)r_char);
        BN_Mul((char*)strRes_char, (char*)r_char, (char*)strRes_char);

        //Acc = ((Acc+Block)*r) % P
        BN_Mod((char*)strRes_char, (char*)P, (char*)strRes_char);
        memcpy(acc_char, strRes_char, strlen((char*)strRes_char) + 1);

        //Acc + s
        str_reverse(s, POLY1305_BLOCK_BYTE);
        str_Hex2Char((char*)s, POLY1305_BLOCK_BYTE, (char*)s_char);
        str_reverse(s, POLY1305_BLOCK_BYTE);

        BN_Add((char*)acc_char, (char*)s_char, (char*)strRes_char);
    }

    //Special handling
    if (0x30 == strRes_char[0] && 0x00 == strRes_char[1])
    {
        strRes_char[1] = 0x30;
    }

    //Get Tag
    if (POLY1305_BLOCK_BYTE * 2 <= strlen((char*)strRes_char))
    {
        str_Char2Hex((char*)strRes_char + strlen((char*)strRes_char) - POLY1305_BLOCK_BYTE * 2, (char*)Tag);
        str_reverse(Tag, POLY1305_TAG_BYTE);
    }
    else
    {
        memset(Tag, 0x00, POLY1305_TAG_BYTE);
        str_Char2Hex((char*)strRes_char, (char*)Tag);
        str_reverse(Tag, strlen((char*)strRes_char) / 2);
    }

    return 0;
}


uint8_t ChaCha20_Quarter_Round(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d)
{
    if (NULL == a || NULL == b || NULL == c || NULL == d)
    {
        return 1;
    }
    else
    {
        ;
    }
    *a += *b; *d ^= *a; *d = CYCLE_LSHIFT_NBIT_TYPE(*d, 16, uint32_t);
    *c += *d; *b ^= *c; *b = CYCLE_LSHIFT_NBIT_TYPE(*b, 12, uint32_t);
    *a += *b; *d ^= *a; *d = CYCLE_LSHIFT_NBIT_TYPE(*d, 8, uint32_t);
    *c += *d; *b ^= *c; *b = CYCLE_LSHIFT_NBIT_TYPE(*b, 7, uint32_t);

    return 0;
}

uint8_t ChaCha20_Block_Function(uint8_t* key, uint32_t counter, uint8_t* nonce, uint8_t* key_stream)
{
    uint32_t inner_block[16] = { 0 };
    uint32_t initial_block[16] = { 0 };
    uint32_t msglen = 0;

    //built inner block
    inner_block[0] = (0x61707865);
    inner_block[1] = (0x3320646e);
    inner_block[2] = (0x79622d32);
    inner_block[3] = (0x6b206574);

    for (int i = 0; i < 8; i++)
    {
        memcpy_((void*)&inner_block[i + 4], (void*)&key[i * 4], 4);
        inner_block[i + 4] = (inner_block[i + 4]);
    }

    inner_block[12] = counter;

    for (int i = 0; i < 3; i++)
    {
        memcpy_((void*)&inner_block[i + 13], (void*)&nonce[i * 4], 4);
        inner_block[i + 13] = inner_block[i + 13];
    }

    for (int i = 0; i < 16; i++)
    {
        inner_block[i] = inner_block[i];
    }

    memcpy_(initial_block, inner_block, 16 * 4);

    //20 rounds
    for (int i = 0; i < 10; i++)
    {
        ChaCha20_Quarter_Round(&inner_block[0], &inner_block[4], &inner_block[8], &inner_block[12]);
        ChaCha20_Quarter_Round(&inner_block[1], &inner_block[5], &inner_block[9], &inner_block[13]);
        ChaCha20_Quarter_Round(&inner_block[2], &inner_block[6], &inner_block[10], &inner_block[14]);
        ChaCha20_Quarter_Round(&inner_block[3], &inner_block[7], &inner_block[11], &inner_block[15]);
        ChaCha20_Quarter_Round(&inner_block[0], &inner_block[5], &inner_block[10], &inner_block[15]);
        ChaCha20_Quarter_Round(&inner_block[1], &inner_block[6], &inner_block[11], &inner_block[12]);
        ChaCha20_Quarter_Round(&inner_block[2], &inner_block[7], &inner_block[8], &inner_block[13]);
        ChaCha20_Quarter_Round(&inner_block[3], &inner_block[4], &inner_block[9], &inner_block[14]);
    }

    for (int i = 0; i < 16; i++)
    {
        inner_block[i] += initial_block[i];
    }

    memcpy_(key_stream, inner_block, 16 * 4);

    return 0;
}

uint8_t ChaCha20_Encrypt(uint8_t* key, uint32_t counter, uint8_t* nonce, uint8_t* msg, uint32_t msglen, uint8_t* cipher)
{
    uint8_t key_stream[CHACHA20_KEY_STREAM_BYTE] = { 0 };
    uint32_t round = msglen / CHACHA20_KEY_STREAM_BYTE;
    uint8_t last_block_len = 0;

    if (NULL == key || NULL == nonce || NULL == msg || NULL == cipher)
    {
        return 1;
    }
    else
    {
        ;
    }

    if (msglen % CHACHA20_KEY_STREAM_BYTE)
    {
        round++;
        last_block_len = msglen % CHACHA20_KEY_STREAM_BYTE;
    }
    else
    {
        last_block_len = CHACHA20_KEY_STREAM_BYTE;
    }

    for (int i = 0; i < round - 1; i++)
    {
        ChaCha20_Block_Function(key, counter + i, nonce, key_stream);
        XOR_U8(key_stream, msg + i * CHACHA20_KEY_STREAM_BYTE, cipher + i * CHACHA20_KEY_STREAM_BYTE, CHACHA20_KEY_STREAM_BYTE);
    }

    ChaCha20_Block_Function(key, counter + round - 1, nonce, key_stream);
    XOR_U8(key_stream, msg + (round - 1) * CHACHA20_KEY_STREAM_BYTE, cipher + (round - 1) * CHACHA20_KEY_STREAM_BYTE, last_block_len);

    return 0;
}
