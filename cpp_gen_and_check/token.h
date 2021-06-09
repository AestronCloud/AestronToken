#ifndef __TOKEN__H__
#define __TOKEN__H__
#include <string>

using namespace std;


#ifdef __cplusplus
extern "C" {
#endif


void getToken(string &token, const string &appid, const string &channelName, string &cert, uint64_t uid);

bool verifyToken(const string &token, const string &appid, const string &cert, uint64_t uid, const std::string& cname);

void getTokenV3(string &token, const string &appid, const string &channelName, string &cert, const string& uidstr);

#ifdef __cplusplus
}
#endif


#endif /*__TOKEN_H__*/
