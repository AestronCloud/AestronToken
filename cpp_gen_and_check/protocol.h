//======================================================================================
#ifndef _PROTOCOL_HEADER_
#define _PROTOCOL_HEADER_
//======================================================================================
#include "packet.h"
#include "packetNew.h"
#include <iostream>
#include <string>

namespace TokenChecker
{
struct RawMsg: public MarshallableNew
{
    uint32_t salt;
    uint32_t generateTs; //生成时的时间
    uint32_t effectiveTs; //持续时长
    RawMsg(uint32_t salt, uint32_t genTs, uint32_t effeTs)
    : salt(salt)
    , generateTs(genTs)
    , effectiveTs(effeTs){}
    RawMsg()
    : salt(0)
    , generateTs(0)
    , effectiveTs(0){}
    virtual void marshal(PackNew& p) const
    {
        p << salt << generateTs << effectiveTs;
    }

    virtual void unmarshal(const UnpackNew& up)
    {
        up >> salt >> generateTs >> effectiveTs;
    }
};

struct TokenContent: public MarshallableNew
{
    std::string signature;
    uint32_t crc32Uid;
    uint32_t crc32ChannelName;
    RawMsg msg;
    virtual void marshal(PackNew& p) const
    {
        p << signature << crc32Uid << crc32ChannelName << msg;
    }

    virtual void unmarshal(const UnpackNew& up)
    {
        up >> signature >> crc32Uid >> crc32ChannelName >> msg;
    }
};

}

#endif // _PROTOCOL_HEADER_
