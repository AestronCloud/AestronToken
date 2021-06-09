#ifndef UTILITY_H
#define UTILITY_H
#include <stdio.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
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

#if defined(DEBUG)
#define FUNLOG(level, fmt, ...)  do { printf( "[%s]: " fmt, __FUNCTION__, __VA_ARGS__); printf("\n"); } while(0)
#else
#define FUNLOG(...)
#endif

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

inline uint32_t GenerateSalt()
{
	return rand();
}


#endif
