#ifndef __TOKEN__H__
#define __TOKEN__H__


// for extern call header file.

#include <string>

using namespace std;

typedef unsigned long uint64_t; 


#ifdef __cplusplus
extern "C" {
#endif


void getToken(string &token, const string &appid, const string &channelName, string &cert, uint64_t uid);

bool verifyToken(const string &token, const string &appid, const string &channelName, uint64_t uid);



#ifdef __cplusplus
}
#endif


#endif /*__TOKEN_H__*/
