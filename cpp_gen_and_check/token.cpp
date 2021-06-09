#include "token.h"
#include "tokenCheck.h"

void getToken(string &token, const string &appid, const string &channelName, string &cert, uint64_t uid)
{
    TokenCheck tokenchecker;
    uint32_t ret = tokenchecker.init(appid, cert);
    token = ret != 0 ? "" : tokenchecker.genToken(uid, channelName);
    
    FUNLOG(Info, "####gettoken:%s %s. appid:%s, channelName:%s, cert:%s, uid:%lu", 
                  ret == 0 ? "success" : "failed", token.c_str(),  
                  appid.c_str(), channelName.c_str(), cert.c_str(), uid);

    return;
}

void getTokenV3(string &token, const string &appid, const string &channelName, string &cert, const string& uidstr)
{
    TokenCheck tokenchecker;
    tokenchecker.init(appid, cert);
    token = tokenchecker.genTokenV3(uidstr, channelName);
    
    FUNLOG(Info, "####gettoken:%s appid:%s, channelName:%s, cert:%s, uid:%s", token.c_str(),  
                  appid.c_str(), channelName.c_str(), cert.c_str(), uidstr.c_str());

    return;
}

bool verifyToken(const string &token, const string &appid, const std::string& cert, uint64_t uid,
                const std::string& cname)
{
    TokenCheck tokenchecker;
    uint32_t ret = tokenchecker.init(appid, cert);

    bool verifyResult = ret != 0 ? false : tokenchecker.checkToken(token, uid, cname);

    FUNLOG(Info, "####verifyToken %s %s appid:%s", verifyResult == true ? "success" : "failed", token.c_str(),
                  appid.c_str()); 
       
    return verifyResult;
}

