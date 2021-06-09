#include <stdio.h>
#include "token.h"
#include <sstream>
#include <stdio.h>

using namespace std;
#define FUNLOG(level, fmt, ...)  do { printf( "[%s]: " fmt, __FUNCTION__, __VA_ARGS__); printf("\n"); } while(0)

void rtcToken()
{
    string token;
    string appid = "myappid_string";
    string cert = "mycert_string";
    
    string channelName = "myChannelId_0";
    uint64_t uid = 12345678;

    getToken(token, appid, channelName, cert, uid);
    printf("rtcToken:%s appid:%s channel:%s cert:%s uid:%lu\n",
           token.c_str(), appid.c_str(), channelName.c_str(), cert.c_str(), uid);

    bool verifyRet = verifyToken(token, appid, cert, uid, channelName);

    printf("veryifytoken ret:%s token:%s appid:%s channel:%s cert:%s uid:%lu\n",
           verifyRet == true ? "success" : "failed", token.c_str(), appid.c_str(),
           channelName.c_str(), cert.c_str(), uid);
}

void rtcTokenV3()
{
    string token;
    string appid = "myappid_string";
    string cert = "mycert_string";
    
    string channelName = "Rubin's channel";
    string uidstr = "WoWoRubin";

    getTokenV3(token, appid, channelName, cert, uidstr);
    printf("rtcTokenV3:%s appid:%s channel:%s cert:%s uid:%s\n",
           token.c_str(), appid.c_str(), channelName.c_str(), cert.c_str(), uidstr.c_str());
}

int main()
{
    // rtc token generator;
    rtcToken();

    // webrtc token generator
    rtcTokenV3();

    return 0;
}
