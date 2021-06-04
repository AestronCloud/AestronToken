//
// Created by Administrator on 2019/7/22.
//

#ifndef MEDIALBS_TOKENCHECK_H
#define MEDIALBS_TOKENCHECK_H

#include <time.h>
#include <string>
#include "protocol.h"


using namespace std;
using namespace TokenChecker;

const uint32_t VERSION_LENGTH = 3;
const uint32_t APP_ID_LENGTH = 32;
const uint32_t HMAC_LENGTH = 20;
const uint32_t HMAC_SHA256_LENGTH = 32;

class TokenCheck
{
public:
    static TokenCheck* getInstance();
    //TokenCheck(string& token, string& m_appId, string& m_channelName, uint64_t uid, string certificate = CERTIFICATE);
    //TokenCheck(string& token, string& m_appId, string& m_channelName, string& uidStr, string certificate = CERTIFICATE);
    TokenCheck();
    ~TokenCheck(){}

    string version();
    bool checkToken(const string& token);
    TokenCheck parseToken(const string& token);
    string genSignature(const string &certificate, const string& appId, const string& uid, const string& channelName, const string& rawMsg);
    string genToken();


    uint32_t init(const string& appId, const string& channelName, uint64_t uid, string &certificate);
    uint32_t init(const string& appId, const string& channelName, uint64_t uid);

    string version3();
    uint32_t init3(const string& appId, const string& cert, const string& channelName, const string& uidstr);
    string genToken3();

    static map<string, string> initAppIdToCert();

public:
    string m_token;
    string m_appId;
    string m_channelName;
    uint32_t m_crc32ChannelName;
    string m_certificate;
    uint64_t m_uid;
    uint32_t m_crc32Uid;
    string m_uidStr;
    string m_signature;
    bool m_isTokenValid;
    uint32_t m_salt;
    uint32_t m_genTs;
    uint32_t m_effeTs; //有效时间
    static map<string, string> m_appIdToCert;
};

#endif //MEDIALBS_TOKENCHECK_H
