#include <stdio.h>
#include <sstream>
#include <stdio.h>
#include "tokenFactory.h"

using namespace std;

int main()
{
    string appid       = "appid_which_should_be_32_length_";
    string cert        = "mycert_string";
    
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
