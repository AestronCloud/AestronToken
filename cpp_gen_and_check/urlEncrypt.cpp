#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/aes.h>
//need -lcrypto lib
#include <iostream>

#include "urlEncrypt.h"
using namespace std;

const static unsigned char* bUrl64 =
		(unsigned char *) "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const static unsigned char* base64 =
		(unsigned char *) "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* maps A=>0,B=>1.. */
const static unsigned char unbUrl64[]={
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0, /* 10 */
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0, /* 20 */
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0, /* 30 */
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0, /* 40 */
  0,   0,   0,   62,   0,  62,   0,   63,  52,  53, /* 50 */
 54,  55,  56,  57,  58,  59,  60,  61,   0,   0, /* 60 */
  0,   0,   0,   0,   0,   0,   1,   2,   3,   4, /* 70 */
  5,   6,   7,   8,   9,  10,  11,  12,  13,  14, /* 80 */
 15,  16,  17,  18,  19,  20,  21,  22,  23,  24, /* 90 */
 25,   0,   0,   0,   0,  63,   0,  26,  27,  28, /* 100 */
 29,  30,  31,  32,  33,  34,  35,  36,  37,  38, /* 110 */
 39,  40,  41,  42,  43,  44,  45,  46,  47,  48, /* 120 */
 49,  50,  51,   0,   0,   0,   0,   0,   0,   0, /* 130 */
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0, /* 140 */
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0, /* ... */
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0, /* ... */
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0, /* ... */
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0, /* ... */
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0, /* ... */
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0, /* ... */
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0, /* ... */
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0, /* ... */
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0, /* ... */
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0, /* ... */
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0, /* ... */
  0,   0,   0,   0,   0,   0,
}; /* This array has 255 elements */

int urlEncrypt::base64Decode( const char* data, uint32_t data_len,
							  unsigned char *result, uint32_t *result_len)
{
	uint32_t cb = 0;
	uint32_t charNo;
	uint32_t pad = 0;

	//Removed from original code because we do not use padding.
	if( data[ data_len -1 ]=='=' )
	{
		++pad ;
	}

	if( data[ data_len -2 ]=='=' )
	{
		++pad ;
	}


	/* Adapted original code to handle missing padding */
//	if (data_len == 1) {
//		return -1;
//	} else if (data_len == 2) {
//		pad = 2;
//		data_len = 4;
//	} else if (data_len % 4 == 2) {
//		pad = 2;
//		data_len += 2;
//	} else if (data_len % 4 == 3) {
//		pad = 1;
//		data_len += 1;
//	} else {
//		pad = 0;
//	}

	*result_len = 3 * data_len / 4 - pad;

	for (charNo = 0; charNo + 4 + pad <= data_len; charNo += 4) {
		uint32_t A = unbUrl64[data[charNo]];
		uint32_t B = unbUrl64[data[charNo + 1]];
		uint32_t C = unbUrl64[data[charNo + 2]];
		uint32_t D = unbUrl64[data[charNo + 3]];

		result[cb++] = (A << 2) | (B >> 4);
		result[cb++] = (B << 4) | (C >> 2);
		result[cb++] = (C << 6) | (D);
	}
	if (pad == 1) {
		uint32_t A = unbUrl64[data[charNo]];
		uint32_t B = unbUrl64[data[charNo + 1]];
		uint32_t C = unbUrl64[data[charNo + 2]];

		result[cb++] = (A << 2) | (B >> 4);
		result[cb++] = (B << 4) | (C >> 2);

	} else if (pad == 2) {
		uint32_t A = unbUrl64[data[charNo]];
		uint32_t B = unbUrl64[data[charNo + 1]];

		result[cb++] = (A << 2) | (B >> 4);

	}

	return 0;
}

unsigned char* urlEncrypt::base64Encode(unsigned char* data, uint32_t data_len, unsigned char *result,uint32_t *result_len)
{

	uint32_t rc = 0; /* result counter */
	uint32_t byteNo; /* I need this after the loop */

	uint32_t modulusLen = data_len % 3;
	uint32_t pad = ((modulusLen & 1) << 1) + ((modulusLen & 2) >> 1); /* 2 gives 1 and 1 gives 2, but 0 gives 0. */

	*result_len = 4 * (data_len + pad) / 3;

	for (byteNo = 0; byteNo+3 <= data_len; byteNo += 3) {
		unsigned char BYTE0 = data[byteNo];
		unsigned char BYTE1 = data[byteNo + 1];
		unsigned char BYTE2 = data[byteNo + 2];
		result[rc++] = base64[BYTE0 >> 2];
		result[rc++] = base64[((0x3 & BYTE0) << 4) + (BYTE1 >> 4)];
		result[rc++] = base64[((0x0f & BYTE1) << 2) + (BYTE2 >> 6)];
		result[rc++] = base64[0x3f & BYTE2];
	}

	if (pad == 2) {
		result[rc++] = base64[data[byteNo] >> 2];
		result[rc++] = base64[(0x3 & data[byteNo]) << 4];
		//*result_len -= 2;
		// Removed from original code because we do not use padding.
		 result[rc++] = '=';
		 result[rc++] = '=';

	} else if (pad == 1) {
		result[rc++] = base64[data[byteNo] >> 2];
		result[rc++] = base64[((0x3 & data[byteNo]) << 4) + (data[byteNo + 1] >> 4)];
		result[rc++] = base64[(0x0f & data[byteNo + 1]) << 2];
		// Removed from original code because we do not use padding.
		 result[rc++] = '=';

		//*result_len -= 1;
	}

	/* We do not use \0 termination in our adaption
	result[rc] = 0;
	*/
	return result;
}

#ifdef AES_BLOCK_SIZE
#undef AES_BLOCK_SIZE
#endif
#define AES_BLOCK_SIZE 16

static AES_KEY aes_key;
#define AES_KEY_LEN  16 // 128bit

static uint8_t key_bin[AES_KEY_LEN] = {0x46,0xb9,0xf9,0xc6,0x14,0x74,0x01,0xab,
							 0x8a,0x2b,0x11,0xbc,0x0a,0xec,0x97,0xb0};
							 
							 
//static uint8_t aes_iv[AES_BLOCK_SIZE]={0x16,0xcc,0xe0,0x17,0x43,0x93,0x49,0x5e,
//                                             0xac,0xa4,0x4a,0x29,0x85,0x8d,0xf6,0x1e} ;  
static uint8_t aes_iv[AES_BLOCK_SIZE];//={0,0,0,0,0,0,0,0,             0,0,0,0,0,0,0,0 } ;  

                                             
#define MAX_URL_SIZE 150
#define MAX_MSG_LEN  256



#if 0
void print_hex(uint8_t* buf, uint32_t len) {
	//Print results:
	for(int i=0;i<len;i++) {
		FUNLOG(Info,"%02X ",buf[i]);
		if(15 == i%16)
			FUNLOG(Info,"\n");
	}
	FUNLOG(Info,"\n");
}
#endif

