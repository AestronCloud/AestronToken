#include <stdio.h>
#include <sstream>
#include <stdio.h>
#include "tokenFactory.h"

using namespace std;

int main()
{
    string appid       = "5zaq309y5lzv4r3elxbufz6t6yzia0i5";
    string cert        = "0lxwdt109ivrzg9w09dhgkk5wgjs8dqy5u08trysf0a4697c";
    
    string channelName = "Rubin's channel";
    uint64_t uid       = 123456789;

    string uidstr      = "WoWoRubin";

    // init Token generator Factory, and set appid cert
    Aestron::Token::TokenFactory& tokenF = *Aestron::Token::TokenFactory::getInstance();
    tokenF.init(appid, cert);

    // generate token
    string token = tokenF.genToken(uid, channelName);
    printf("Token:%s appid:%s channel:%s cert:%s uid:%lu\n\n",
           token.c_str(), appid.c_str(), channelName.c_str(), cert.c_str(), uid);

    // verify token, just for test. Remove if don't need.
    bool verifyResult = tokenF.checkToken(token, uid, channelName);
    printf("veryifytoken ret:%s token:%s appid:%s channel:%s cert:%s uid:%lu\n\n",
           verifyResult == true ? "success" : "failed", token.c_str(), appid.c_str(),
           channelName.c_str(), cert.c_str(), uid);

    // generate token v3, which is used by webrtc.
    string tokenv3 = tokenF.genTokenV3(uidstr, channelName);
    printf("TokenV3:%s appid:%s channel:%s cert:%s uid:%s\n\n",
        tokenv3.c_str(), appid.c_str(), channelName.c_str(), cert.c_str(), uidstr.c_str());

    return 0;
}
