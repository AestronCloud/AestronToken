//
// Created by Administrator on 2019/7/22.
//

#ifndef MEDIALBS_TOKENCHECK_H
#define MEDIALBS_TOKENCHECK_H

#include <time.h>
#include <string>
#include "protocol.h"


namespace Aestron {
namespace Token {

const uint32_t VERSION_LENGTH = 3;
const uint32_t APP_ID_LENGTH = 32;
const uint32_t HMAC_LENGTH = 20;
const uint32_t HMAC_SHA256_LENGTH = 32;

struct TokenResult {
    std::string m_channelName{""};
    uint32_t m_crc32ChannelName{0};
    uint64_t m_uid{0};
    uint32_t m_crc32Uid{0};
    std::string m_uidStr{""};
    std::string m_signature{""};
    uint32_t m_salt{0};
    uint32_t m_genTs{0};
    uint32_t m_effeTs{0};
    bool m_isTokenValid{false};
};

class TokenFactory
{
public:
    static TokenFactory* getInstance();
    ~TokenFactory() = default;

    uint32_t init(const std::string& appId, const std::string &certificate);

    std::string version();
    std::string version3();
    bool checkToken(const std::string& token, uint64_t uid, const std::string& channelName);
    void parseToken(const std::string& token, TokenResult& result);
    std::string genSignature(const std::string &certificate, const std::string& appId, const std::string& uid, const std::string& channelName, const std::string& rawMsg);


    std::string genToken(uint64_t uid, const std::string& channelName);
    std::string genTokenV3(const std::string& uidstr, const std::string& channelName);

public:
    TokenFactory() = default;
    std::string m_appId{""};
    std::string m_certificate{""};
};

}// namespace Token

}// namespace Aestron

#endif //MEDIALBS_TOKENCHECK_H
