#include "tokenCheck.h"
#include "urlEncrypt.h"
#include "packetNew.h"
#include <zlib.h>

#include <sstream>
using namespace std;


TokenCheck* TokenCheck::getInstance()
{
    static TokenCheck tokenchecker;
    return &tokenchecker;
}

uint32_t TokenCheck::init(const string& appId, const string& certificate)
{
    m_appId       = appId;
    m_certificate = certificate;
    return 0;
}

string TokenCheck::version()
{
    return "001";
}

string TokenCheck::version3()
{
    return "003";
}

bool TokenCheck::checkToken(const string &token, uint64_t uid, const string& channelName)
{
    const static uint32_t effecTsGap = 10; //10s的过期波动时间

    TokenResult result;
    result.m_channelName = channelName;
    std::ostringstream oss;
    oss << uid;
    result.m_uid = uid;
    result.m_uidStr = oss.str();

    TokenCheck tokenCheck = parseToken(token, result);
    if(!result.m_isTokenValid)
    {
        FUNLOG(Info,"token %s invalid.\n", token.c_str());
        return false;
    }

    //生成签名用于校验
    RawMsg msg(result.m_salt, result.m_genTs, result.m_effeTs);

    PackBuffer packBufMsg;
    PackNew packMsg(packBufMsg);
    msg.marshal(packMsg);

    string rawMsgStr = string(packMsg.data(), packMsg.size());

    string signatureNow = genSignature(m_certificate, m_appId, result.m_uidStr, result.m_channelName, rawMsgStr);

    FUNLOG(Info, "certificate %s, appId %s, uid %lu, channelName %s, signatureNow size %zu, m_signature size %lu.",
            m_certificate.c_str(), m_appId.c_str(), result.m_uid, result.m_channelName.c_str(),
            signatureNow.size(), result.m_signature.size());

    if ( 0 != signatureNow.compare(result.m_signature))
    {
        FUNLOG(Info, "signatrue generated != signature recv. %s", token.c_str());
        return false;
    }

    return true;
}

TokenCheck TokenCheck::parseToken(const string& token, TokenResult& result)
{
    if(token.empty())
    {
        FUNLOG(Info, "token is %lu, return.", token.size());
        return TokenCheck();
    }

    if (token.substr(0, VERSION_LENGTH) != version())
    {
        return TokenCheck();
    }

    try {
        TokenCheck tokenCheck;
        tokenCheck.m_appId = token.substr(VERSION_LENGTH, APP_ID_LENGTH);

        //todo:错误判断
        uint8_t decodeResult[1024];
        uint32_t resultLen = 0;
        string base64Src = token.substr(VERSION_LENGTH + APP_ID_LENGTH, token.size());
        urlEncrypt::base64Decode(base64Src.c_str(), base64Src.length(), decodeResult, &resultLen);

        //todo:反序列化
        UnpackNew tokenUp(decodeResult, resultLen);
        TokenContent content;
        try {
            content.unmarshal(tokenUp);
        } catch(std::exception& ex) {
            return TokenCheck();
        }

        result.m_signature = content.signature;
        result.m_crc32Uid = content.crc32Uid;
        result.m_crc32ChannelName = content.crc32ChannelName;
        result.m_salt = content.msg.salt;
        result.m_genTs = content.msg.generateTs;
        result.m_effeTs = content.msg.effectiveTs;



        result.m_isTokenValid = true;

        FUNLOG(Info,"token %s, appId %s, crcUid %u, crcChannelName %u, generate ts %u, effective ts %u.",
                token.c_str(), m_appId.c_str(), result.m_crc32Uid, result.m_crc32ChannelName, result.m_genTs,
                result.m_effeTs);
        return tokenCheck;

    } catch (std::exception& e) {
        FUNLOG(Info,"parse error, token %s.", token.c_str());
        return TokenCheck();
    }

    return TokenCheck();
}


string TokenCheck::genSignature(const string &certificate, const string& appId, const string& uid,
                                const string& channelName, const string& rawMsg)
{
    std::stringstream ss;
    ss << appId << uid << channelName << certificate << rawMsg;
    return (HmacSign(certificate, ss.str(), HMAC_LENGTH));
}

string TokenCheck::genToken(uint64_t uid, const std::string& channelName)
{
    //有效期一天
    RawMsg rawMsg(GenerateSalt(), (uint32_t)time(NULL), 24 * 3600);

    PackBuffer packBufMsg;
    PackNew packMsg(packBufMsg);
    rawMsg.marshal(packMsg);

    string rawMsgStr = string(packMsg.data(), packMsg.size());

    std::ostringstream oss;
    oss << uid;
    string uidstr = oss.str();

    //序列化
    TokenContent content;
    content.signature = genSignature(m_certificate, m_appId, uidstr, channelName, rawMsgStr);
    content.crc32Uid = crc32(0, reinterpret_cast<Bytef*>(const_cast<char*>(uidstr.c_str())), uidstr.length());
    content.crc32ChannelName = crc32(0, reinterpret_cast<Bytef*>(const_cast<char*>(channelName.c_str())), channelName.length());

    content.msg = rawMsg;

    PackBuffer packBuf;
    PackNew tokenPack(packBuf);
    content.marshal(tokenPack);

    //base64
    uint8_t base64Result[1024];
    uint32_t resultLen = 0;

    urlEncrypt::base64Encode((unsigned char*)tokenPack.data(), tokenPack.size(), base64Result, &resultLen);

    base64Result[resultLen] = '\0';

    std::stringstream ss;
    ss << TokenCheck::version() << m_appId << string((char*)base64Result, resultLen);

    FUNLOG(Info,"%s, baseResult %s, crc32Uid %u, salt %u, generate ts %u, effective ts %u.\n",
            ss.str().c_str(), base64Result, content.crc32Uid, rawMsg.salt, rawMsg.generateTs, rawMsg.effectiveTs);
    return ss.str();
}

string TokenCheck::genTokenV3(const string& uidstr, const string& channelName)
{
    //有效期一天
    RawMsg rawMsg(GenerateSalt(), (uint32_t)time(NULL), 24 * 3600);

    PackBuffer packBufMsg;
    PackNew packMsg(packBufMsg);
    rawMsg.marshal(packMsg);

    string rawMsgStr = string(packMsg.data(), packMsg.size());

    // serialize
    TokenContent content;
    content.signature = genSignature(m_certificate, m_appId, uidstr, channelName, rawMsgStr);
    content.crc32Uid = crc32(0, reinterpret_cast<Bytef*>(const_cast<char*>(uidstr.c_str())), uidstr.length());
    content.crc32ChannelName = crc32(0, reinterpret_cast<Bytef*>(const_cast<char*>(channelName.c_str())), channelName.length());

    content.msg = rawMsg;

    PackBuffer packBuf;
    PackNew tokenPack(packBuf);
    content.marshal(tokenPack);

    // base64
    uint8_t base64Result[1024];
    uint32_t resultLen = 0;

    urlEncrypt::base64Encode((unsigned char*)tokenPack.data(), tokenPack.size(), base64Result, &resultLen);

    base64Result[resultLen] = '\0';

    std::stringstream ss;
    ss << TokenCheck::version3() << m_appId << string((char*)base64Result, resultLen);

    FUNLOG(Info,"gentoken %s, baseResult %s, crc32Uid %u, salt %u, generate ts %u, effective ts %u.\n",
            ss.str().c_str(), base64Result, content.crc32Uid, rawMsg.salt, rawMsg.generateTs, rawMsg.effectiveTs);
    return ss.str();
}
