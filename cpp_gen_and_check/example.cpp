#include <stdio.h>
#include "token.h"
#include <thread>
#include <sstream>
#include <thread>
#include <stdio.h>

#define FULOG(...) 
using namespace std;

void mythread(uint32_t threadIdx)
{
    printf("thread start %u.", threadIdx);

    string token;
    string appid = "m4jxlvauzpen4rteq9p45g641kb";
    string channelName = "myChannelId_";
    std::stringstream os;
    os << channelName << threadIdx;
    channelName = "p5yx1sk4pkx6";

    string cert = "dftj8oxlseg3r4q4zyzucf0xldmhpyk934ihymtw";
    uint64_t uid = 4611686018465182097;

    getToken(token, appid, channelName, cert, uid);
    printf(  "gentoken:%s  appid:%s  channel:%s cert:%s uid:%lu, threadIdx %u\n",
           token.c_str(), appid.c_str(), channelName.c_str(), cert.c_str(), uid, threadIdx);

    bool verifyRet = verifyToken(token, appid, channelName, uid);

    printf( "veryifytoken ret:%s token:%s appid:%s channel:%s cert:%s uid:%lu\n",
           verifyRet == true ? "success" : "failed", token.c_str(), appid.c_str(),
           channelName.c_str(), cert.c_str(), uid);


    string tmptoken = token.replace(8,9, "error");
    bool verifyRet2 = verifyToken(tmptoken, appid, channelName, uid);

    printf( "veryifytoken2 ret:%s token:%s appid:%s channel:%s cert:%s uid:%lu\n",
           verifyRet2 == true ? "success" : "failed", token.c_str(), appid.c_str(),
           channelName.c_str(), cert.c_str(), uid);
    printf( "thread end %u.", threadIdx);
}

void mytest(uint32_t idx)
{
    printf("thread start %u", idx);
    string token;
    string appid = "12345678901234567890123456789012";
    string channelName = "myChannelId_";
    std::stringstream os;
    os << channelName << idx;
    channelName = os.str();

    string cert = "01234567890123456789012345678901";
    uint64_t uid = 12345678;

    getToken(token, appid, channelName, cert, uid);
    printf( "gentoken:%s appid:%s channel:%s cert:%s uid:%lu, threadIdx %u\n",
           token.c_str(), appid.c_str(), channelName.c_str(), cert.c_str(), uid, idx);

    bool verifyRet = verifyToken(token, appid, channelName, uid);

    printf( "veryifytoken ret:%s token:%s appid:%s channel:%s cert:%s uid:%lu\n",
           verifyRet == true ? "success" : "failed", token.c_str(), appid.c_str(),
           channelName.c_str(), cert.c_str(), uid);

    printf( "thread end %u.", idx);
}

void mytest3(uint32_t idx)
{
    printf("thread start %u", idx);
    string token;
    string appid = "5zaq309y5lzv4r3elxbufz6t6y";
    string channelName = "test";

    string cert = "0lxwdt109ivrzg9w09dhgkk5wgjs8dqy5u0";
    string uidstr = "😊";

    getToken3(token, appid, channelName, cert, uidstr);
    printf( "gentoken:%s appid:%s channel:%s cert:%s uid:%s, threadIdx %u\n",
           token.c_str(), appid.c_str(), channelName.c_str(), cert.c_str(), uidstr.c_str(), idx);

    printf( "thread end %u.", idx);
}

int main()
{
    string token;

    std::thread threads[20];

    uint32_t idx = 0;
    for(auto& tr: threads)
    {
        tr = std::thread(mytest3, ++idx);
    }
    for(auto& tr: threads)
    {
        tr.join();
    }

    printf( "main thread exit.");
    return 0;
}
