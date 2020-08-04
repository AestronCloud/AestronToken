#ifndef UTILITY_H
#define UTILITY_H
//#include "comm.h"
#include "stdio.h"

#include <string.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
//#include <random>

#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <fcntl.h>
#include <execinfo.h>
#include <sstream>
#include <iostream>

#define GET_LOWER32BIT(u64) (0xffffffffULL & (u64))
//#define GET_HIG32BIT(u64) ((uint32_t)(((u64)&0xffffffff00000000ULL) >>32))
#define  GET_HIG32BIT(u64) ({Key64_t taskKey; taskKey.key=(u64); taskKey.fields.field2;})
#define base_likely(x) __builtin_expect(!!(x), 1)
#define base_unlikely(x) __builtin_expect(!!(x), 0)
#define FUNLOG(...)
#define log(...)



// HMAC
inline std::string HmacSign(const std::string& appCertificate,
							const std::string& message, uint32_t signSize) {
	if (appCertificate.empty()) {
		return "";
	}
	unsigned char md[EVP_MAX_MD_SIZE];
	uint32_t md_len = 0;
	HMAC(EVP_sha1(), (const unsigned char*)appCertificate.data(),
		 appCertificate.length(), (const unsigned char*)message.data(),
		 message.length(), &md[0], &md_len);
	return std::string(reinterpret_cast<char*>(md), signSize);
}

inline std::string HmacSign2(const std::string& appCertificate,
							 const std::string& message, uint32_t signSize) {
	if (appCertificate.empty()) {
		return "";
	}
	unsigned char md[EVP_MAX_MD_SIZE];
	uint32_t md_len = 0;
	HMAC(EVP_sha256(), (const unsigned char*)appCertificate.data(),
		 appCertificate.length(), (const unsigned char*)message.data(),
		 message.length(), &md[0], &md_len);
	return std::string(reinterpret_cast<char*>(md), signSize);
}

inline bool IsUUID(const std::string& v) {
	if (v.length() != 32) {
		return false;
	}

	for (uint32_t idx =0; idx < v.length(); ++idx) {
		if (!isxdigit(v[idx])) {
			return false;
		}
	}

	return true;
}

inline int initSalt(){
    srand(time(NULL));
    return 0;
}

static int mysaltInit = initSalt();
inline uint32_t GenerateSalt()
{
//	std::random_device r;
//	return r();
//srand(time(NULL));
	return rand();
}

inline std::string genRandomStr(const int len) {
	static const char certNum[] =
			"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

	std::stringstream ss;

	for (int i = 0; i < len; ++i) {
		ss << certNum[GenerateSalt() % (sizeof(certNum) - 1)];
	}
	return ss.str();
}

class BaseInfo
{
public:
	static uint32_t localIp;
};



#endif
