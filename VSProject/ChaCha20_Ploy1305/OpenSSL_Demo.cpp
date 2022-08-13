#include "Test_ChaCha20_Ploy1305.h"
#include "Common.h"
#include "ChaCha20_Ploy1305.h"

#pragma warning(disable : 4996)

extern "C"
{
#include <openssl/applink.c>
}

int main(int argc, char* argv[])
{
    Test_Ploy1305();
    Test_ChaCha20();

    return 0;
}