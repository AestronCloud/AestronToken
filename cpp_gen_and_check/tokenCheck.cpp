#include "tokenCheck.h"
#include "urlEncrypt.h"
#include "packetNew.h"
#include <zlib.h>

#include <sstream>

#define FUNLOG(...)

std::map<string, string> TokenCheck::m_appIdToCert = TokenCheck::initAppIdToCert();

TokenCheck* TokenCheck::getInstance()
{
    static TokenCheck tokenchecker;
    return &tokenchecker;
}


uint32_t TokenCheck::init(const string& appId, const string& channelName, uint64_t uid)
{
    string cert = "";
    return init(appId, channelName, uid, cert); 
}

uint32_t TokenCheck::init(const string& appId, const string& channelName, uint64_t uid, string& certificate)
{
    if ( certificate.empty())
    {
    	FUNLOG(Info,"init verifytoken appId %s, channelName %s, uid %lu",
       	        appId.c_str(), channelName.c_str(), uid);
        m_certificate = "";
    }
    else
    {
    	FUNLOG(Info,"init gettoken appId %s, channelName %s, uid %llu, certificate %s.",
       	        appId.c_str(), channelName.c_str(), uid, certificate.c_str());
        m_certificate = certificate;
    }

    m_appId       = appId;
    m_channelName = channelName;
    m_uid         = uid;

    stringstream sUidStr;

    sUidStr << m_uid;
    m_uidStr = sUidStr.str();

    //m_certificate = "";
    map<string, string>::iterator itCert = m_appIdToCert.find(m_appId);
    if(itCert != m_appIdToCert.end())
    {
        m_certificate = itCert->second;
    }


    FUNLOG(Info, "use cert:%s to init.", m_certificate.c_str());

    return 0;
}

map<string, string> TokenCheck::initAppIdToCert()
{
    map<string, string> tmpMap;
    /* add appid-cert map element here */

    return tmpMap;
}

TokenCheck::TokenCheck()
    : m_crc32ChannelName(0)
    , m_crc32Uid(0)
    , m_uidStr("")
    , m_signature("")
    , m_isTokenValid(false)
    , m_salt(0)
    , m_genTs(0)
    , m_effeTs(0)
{

}


string TokenCheck::version()
{
    return "001";
}

bool TokenCheck::checkToken(const string &token)
{
    const static uint32_t effecTsGap = 10; //10s的过期波动时间

    TokenCheck tokenCheck = parseToken(token);
    if(!tokenCheck.m_isTokenValid)
    {
        FUNLOG(Info,"token %s invalid.\n", token.c_str());
        return false;
    }

    //生成签名用于校验
    RawMsg msg(tokenCheck.m_salt, tokenCheck.m_genTs, tokenCheck.m_effeTs);

    PackBuffer packBufMsg;
    PackNew packMsg(packBufMsg);
    msg.marshal(packMsg);

    string rawMsgStr = string(packMsg.data(), packMsg.size());

    string signatureNow = genSignature(m_certificate, m_appId, m_uidStr, m_channelName, rawMsgStr);

    m_genTs = tokenCheck.m_genTs;
    m_effeTs = tokenCheck.m_effeTs;
    FUNLOG(Info,"certificate %s, appId %s, uid %llu, channelName %s, signatureNow size %zu, m_signature size %zu.",
            m_certificate.c_str(), m_appId.c_str(), m_uid, m_channelName.c_str(), signatureNow.size(), tokenCheck.m_signature.size());

    if ( 0 != signatureNow.compare(tokenCheck.m_signature))
    {
        FUNLOG(Info,"signatrue generated != signature recv.\n");
        return false;
    }

    //校验时间
    //if(m_genTs + m_effeTs + effecTsGap < time.now())
    //{
        //FUNLOG(Info, "token is not effective, genTs %u, effeTs %u, effeGap %u, now %u.", m_genTs, m_effeTs, effecTsGap, SelectorEPoll::m_iNow);
    //    return false;
    //}

    return true;
}

TokenCheck TokenCheck::parseToken(const string& token)
{
    if(token.empty())
    {
        FUNLOG(Info,"token is null, return.\n");
        return TokenCheck();
    }

    if (token.substr(0, VERSION_LENGTH) != version())
    {
        FUNLOG(Info,"version error.\n");
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
        }catch(std::exception& ex){
            FUNLOG(Info,"unpack error.\n");
            return TokenCheck();
        }

        tokenCheck.m_signature = content.signature;
        tokenCheck.m_crc32Uid = content.crc32Uid;
        tokenCheck.m_crc32ChannelName = content.crc32ChannelName;

        tokenCheck.m_salt = content.msg.salt;
        tokenCheck.m_genTs = content.msg.generateTs;
        tokenCheck.m_effeTs = content.msg.effectiveTs;

        tokenCheck.m_isTokenValid = true;

        FUNLOG(Info,"token %s, appId %s, crcUid %u, crcChannelName %u, generate ts %u, effective ts %u.",
                token.c_str(), tokenCheck.m_appId.c_str(), tokenCheck.m_crc32Uid, tokenCheck.m_crc32ChannelName, tokenCheck.m_genTs, tokenCheck.m_effeTs);
        return tokenCheck;

    } catch (std::exception& e) {
        FUNLOG(Info,"parse error, token %s.", token.c_str());
        return TokenCheck();
    }

    return TokenCheck();
}


string TokenCheck::genSignature(const string &certificate, const string& appId, const string& uid, const string& channelName, const string& rawMsg)
{
        std::stringstream ss;
        ss << appId << uid << channelName << certificate << rawMsg;
        return (HmacSign(certificate, ss.str(), HMAC_LENGTH));
}

string TokenCheck::genToken()
{
    //有效期一天
    RawMsg rawMsg(GenerateSalt(), (uint32_t)time(NULL), 24 * 3600);

    PackBuffer packBufMsg;
    PackNew packMsg(packBufMsg);
    rawMsg.marshal(packMsg);

    string rawMsgStr = string(packMsg.data(), packMsg.size());
    m_signature = genSignature(m_certificate, m_appId, m_uidStr, m_channelName, rawMsgStr);
    m_crc32Uid = crc32(0, reinterpret_cast<Bytef*>(const_cast<char*>(m_uidStr.c_str())), m_uidStr.length());
    m_crc32ChannelName = crc32(0, reinterpret_cast<Bytef*>(const_cast<char*>(m_channelName.c_str())), m_channelName.length());

    //序列化
    TokenContent content;
    content.signature = m_signature;
    content.crc32Uid = m_crc32Uid;
    content.crc32ChannelName = m_crc32ChannelName;
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

    FUNLOG(Info,"gentoken %s, baseResult %s, crc32Uid %u, salt %u, generate ts %u, effective ts %u.\n",
            ss.str().c_str(), base64Result, m_crc32Uid, rawMsg.salt, rawMsg.generateTs, rawMsg.effectiveTs);
    return ss.str();
}


