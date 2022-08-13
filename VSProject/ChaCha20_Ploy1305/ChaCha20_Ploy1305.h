#include <openssl/bn.h>
#include <string.h>

int BN_Add(char* strHex_M, char* strHex_D, char* strHex_Res);
int BN_Mul(char* strHex_M, char* strHex_D, char* strHex_Res);
int BN_Mod(char* strHex_M, char* strHex_D, char* strHex_Res);
uint8_t Poly1305_Clamp_R(uint8_t r[16]);
uint8_t Ploy1305_Get_Tag(uint8_t* key, uint8_t* msg, uint32_t msglen, uint8_t* Tag);

uint8_t ChaCha20_Quarter_Round(uint32_t* a, uint32_t* b, uint32_t* c, uint32_t* d);
uint8_t ChaCha20_Block_Function(uint8_t* key, uint32_t counter, uint8_t* nonce, uint8_t* key_stream);
uint8_t ChaCha20_Encrypt(uint8_t* key, uint32_t counter, uint8_t* nonce, uint8_t* msg, uint32_t msglen, uint8_t* cipher);
