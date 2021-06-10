#ifndef URLENCRYPT_H
#define URLENCRYPT_H
#include "utility.h"


class urlEncrypt
{

public:
    static unsigned char* base64Encode(unsigned char* data, uint32_t data_len, unsigned char *result,uint32_t *result_len) ;
    static int base64Decode( const char* data, uint32_t data_len, unsigned char *result, uint32_t *result_len);
};	


#endif
