#ifndef URLENCRYPT_H
#define URLENCRYPT_H
//#include "common.h"
#include "utility.h"


class urlEncrypt
{

public:

//encrypt the src string,and use base64url to encode the cipher to alphabet string
//src: the input char array
//srcLen: the len of src 
//return: the result string
	static std::string getEncryptUrl(uint8_t *src,uint32_t srcLen);

//decrypt the src string,and use base64url to decode the cipher to alphabet string
//src: the input char array
//srcLen: the len of src 
//return: the result string
    static std::string getDecryptUrl(uint8_t *src,uint32_t srcLen);

    static unsigned char* base64Encode(unsigned char* data, uint32_t data_len, unsigned char *result,uint32_t *result_len) ;
    static int base64Decode( const char* data, uint32_t data_len, unsigned char *result, uint32_t *result_len);

private:
	static unsigned char* base64urlEncode(unsigned char* data, uint32_t data_len, unsigned char *result,uint32_t *result_len) ;
	static int base64urlDecode( unsigned char* data, uint32_t data_len,		unsigned char *result, uint32_t *result_len);

};	


#endif
