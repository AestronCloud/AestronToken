#include "token.h"
#include "tokenCheck.h"
#define FUNLOG(...)

void getToken(string &token, const string &appid, const string &channelName, string &cert, uint64_t uid)
{
    TokenCheck tokenchecker;
    uint32_t ret = tokenchecker.init(appid, channelName, uid, cert);
    token = ret != 0 ? "" : tokenchecker.genToken();
    
    FUNLOG(Info, "####gettoken:%s %s. appid:%s, channelName:%s, cert:%s, uid:%lu", 
                  ret == 0 ? "success" : "failed", token.c_str(),  
                  appid.c_str(), channelName.c_str(), cert.c_str(), uid);

    return;
}

void getToken3(string &token, const string &appid, const string &channelName, string &cert, const string& uidstr)
{
    TokenCheck tokenchecker;
    tokenchecker.init3(appid, cert, channelName, uidstr);
    token = tokenchecker.genToken3();
    
    FUNLOG(Info, "####gettoken:%s %s. appid:%s, channelName:%s, cert:%s, uid:%lu", 
                  ret == 0 ? "success" : "failed", token.c_str(),  
                  appid.c_str(), channelName.c_str(), cert.c_str(), uid);

    return;
}

bool verifyToken(const string &token, const string &appid, const string &channelName, uint64_t uid)
{
    TokenCheck tokenchecker;
    uint32_t ret = tokenchecker.init(appid, channelName, uid);
    bool verifyResult = ret != 0 ? false : tokenchecker.checkToken(token);

    FUNLOG(Info, "####verifyToken %s %s appid:%s channelName:%s, uid:%lu", 
                  verifyResult == true ? "success" : "failed", token.c_str(), 
                  appid.c_str(), channelName.c_str(), uid); 
       
    return verifyResult;
}

