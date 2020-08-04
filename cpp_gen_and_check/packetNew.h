//
// Created by Administrator on 2018/12/13.
//
//新的packet文件，因为之前的文件对大小端的处理有误，但是全网都已经使用了这套大小端处理逻辑
//现在不能随便改这个大小端逻辑，针对web那边发过来的二进制数据，单独起一个文件进行解析处理
//其中也涉及到网络字节序，大小端的处理逻辑，也是其中和之前的不同点
//注：目前只能用于web与该前端之间的交互，千万不要使用在其他地方
#ifndef LBSFORVIDEO_PACKETNEW_H
#define LBSFORVIDEO_PACKETNEW_H

#include "int_types.h"
#include "blockbuffer.h"
#include "varstr.h"
#include "header.h"
#include "packet.h"
#include "utility.h"

#include <string>
#include <iostream>
#include <stdexcept>
#include <map> // CARE
#include <arpa/inet.h>

//using namespace Endian;

class PackNew
{
private:
    PackNew (const PackNew & o);
    PackNew & operator = (const PackNew& o);
public:
    uint64_t xhtonll(uint64_t i64)
    {
        return((uint64_t(htonl((uint32_t)i64)) << 32) |htonl((uint32_t(i64>>32))));
    }

    // IMPORTANT remember the buffer-size before pack. see data(), size()
    // reserve a space to replace packet header after pack parameter
    // sample below: OffPack. see data(), size()
    PackNew(PackBuffer & pb, size_t off = 0) : m_buffer(pb)
    {
        m_offset = pb.size() + off;
        m_buffer.resize(m_offset);
    }

    // access this packet.
    char * data()
    {
        return m_buffer.data() + m_offset;
    }
    const char * data()  const
    {
        return m_buffer.data() + m_offset;
    }
    size_t size() const
    {
        return m_buffer.size() - m_offset;
    }

    PackNew & push(const void * s, size_t n)
    {
        m_buffer.append((const char *)s, n); return *this;
    }
    PackNew & push(const void * s)
    {
        m_buffer.append((const char *)s); return *this;
    }

    PackNew & push_uint8(uint8_t u8)
    {
        return push(&u8, 1);
    }
    PackNew & push_uint16(uint16_t u16)
    {
        u16 = htons(u16); return push(&u16, 2);
    }
    PackNew & push_uint32(uint32_t u32)
    {
        u32 = htonl(u32); return push(&u32, 4);
    }
    PackNew & push_uint64(uint64_t u64)
    {
        u64 = xhtonll(u64); return push(&u64, 8);
    }

    PackNew & push_varstr(const Varstr & vs)
    {
        return push_varstr(vs.data(), vs.size());
    }
    PackNew & push_varstr(const void * s)
    {
        return push_varstr(s, strlen((const char *)s));
    }
    PackNew & push_varstr(const std::string & s)
    {
        return push_varstr(s.data(), s.size());
    }
    PackNew & push_varstr(const void * s, size_t len)
    {
        if(len > 0xFFFF) throw PackError("push_varstr: varstr too big");
        return push_uint16(uint16_t(len)).push(s, len);
    }
    PackNew & push_varstr32(const void * s, size_t len)
    {
        if(len > 0xFFFFFFFF) throw PackError("push_varstr32: varstr too big");
        return push_uint32(uint32_t(len)).push(s, len);
    }
#ifdef WIN32
    PackNew & push_varwstring32(const std::wstring &ws)
    {
        size_t len = ws.size() * 2;
        return push_uint32((uint32_t)len).push(ws.data(), len);
    }
#endif

    virtual ~PackNew()
    {
    }
public:
    // replace. pos is the buffer offset, not this Pack m_offset
    size_t replace(size_t pos, const void * data, size_t rplen)
    {
        m_buffer.replace(pos, (const char*)data, rplen);
        return pos + rplen;
    }
    size_t replace_uint8(size_t pos, uint8_t u8)
    {
        return replace(pos, &u8, 1);
    }
    size_t replace_uint16(size_t pos, uint16_t u16)
    {
        //u16 = xhtons(u16);
        u16 = htons(u16);
        return replace(pos, &u16, 2);
    }
    size_t replace_uint32(size_t pos, uint32_t u32)
    {
        //u32 = xhtonl(u32);
        u32 = htonl(u32);
        return replace(pos, &u32, 4);
    }
protected:
    PackBuffer & m_buffer;
    size_t m_offset;
};


class UnpackNew
{
public:
    uint64_t xntohll(uint64_t i64) const
    {
        return((uint64_t(ntohl((uint32_t)i64)) << 32) |ntohl((uint32_t(i64>>32))));
    }

    UnpackNew(const void * data, size_t size)
    {
        reset(data, size);
    }
    void reset(const void * data, size_t size) const
    {
        m_data = (const char *)data;
        m_size = size;
    }

    virtual ~UnpackNew()
    {
        m_data = NULL;
    }

    operator const void *() const
    {
        return m_data;
    }
    bool operator!() const
    {
        return(NULL == m_data);
    }

    std::string pop_varstr() const
    {
        Varstr vs = pop_varstr_ptr();
        return std::string(vs.data(), vs.size());
    }

    std::string pop_varstr32() const
    {
        Varstr vs = pop_varstr32_ptr();
        return std::string(vs.data(), vs.size());
    }
#ifdef WIN32
    std::wstring pop_varwstring32() const
    {
        Varstr vs = pop_varstr32_ptr();
        return std::wstring((wchar_t *)vs.data(), vs.size() / 2);
    }
#endif
    std::string pop_fetch(size_t k) const
    {
        return std::string(pop_fetch_ptr(k), k);
    }

    void finish() const
    {
        if(!empty()) throw UnpackError("finish: too much data");
    }

    uint8_t pop_uint8() const
    {
        if(m_size < 1u)
            throw UnpackError("pop_uint8: not enough data");

        uint8_t i8 = *((uint8_t*)m_data);
        m_data += 1u; m_size -= 1u;
        return i8;
    }

    uint16_t pop_uint16() const
    {
        if(m_size < 2u)
            throw UnpackError("pop_uint16: not enough data");

        uint16_t i16 = *((uint16_t*)m_data);
        //i16 = xntohs(i16);
        i16 = ntohs(i16);
        m_data += 2u; m_size -= 2u;
        return i16;
    }

    uint32_t pop_uint32() const
    {
        if(m_size < 4u)
            throw UnpackError("pop_uint32: not enough data");
        uint32_t i32 = *((uint32_t*)m_data);
        //FUNLOG(Info, "endian for test i32 %u", i32);

        //i32 = xntohl(i32);
        i32 = ntohl(i32);

        //FUNLOG(Info, "endian for test i32 after %u", i32);
        m_data += 4u; m_size -= 4u;
        return i32;
    }

    uint64_t pop_uint64() const
    {
        if(m_size < 8u)
            throw UnpackError("pop_uint64: not enough data");
        uint64_t i64 = *((uint64_t*)m_data);

        i64 = xntohll(i64);

        m_data += 8u; m_size -= 8u;
        return i64;
    }

    Varstr pop_varstr_ptr() const
    {
        // Varstr { uint16_t size; const char * data; }
        Varstr vs;
        vs.m_size = pop_uint16();
        vs.m_data = pop_fetch_ptr(vs.m_size);
        return vs;
    }

    Varstr pop_varstr32_ptr() const
    {
        Varstr vs;
        vs.m_size = pop_uint32();
        vs.m_data = pop_fetch_ptr(vs.m_size);
        return vs;
    }

    const char * pop_fetch_ptr(size_t k) const
    {
        if(m_size < k)
        {
            //abort();
            throw UnpackError("pop_fetch_ptr: not enough data");
        }

        const char * p = m_data;
        m_data += k; m_size -= k;
        return p;
    }

    bool empty() const
    {
        return m_size == 0;
    }
    const char * data() const
    {
        return m_data;
    }
    size_t size() const
    {
        return m_size;
    }

private:
    mutable const char * m_data;
    mutable size_t m_size;
};

struct MarshallableNew
{
    virtual void marshal(PackNew &) const = 0;
    virtual void unmarshal(const UnpackNew &) = 0;
    virtual ~MarshallableNew()
    {
    }
    virtual std::ostream & trace(std::ostream & os) const
    {
        return os << "trace MarshallableNew [ not immplement ]";
    }
};

// Marshallable helper
inline std::ostream & operator << (std::ostream & os, const MarshallableNew & m)
{
    return m.trace(os);
}

inline PackNew & operator << (PackNew & p, const MarshallableNew & m)
{
    m.marshal(p);
    return p;
}

inline const UnpackNew & operator >> (const UnpackNew & p, const MarshallableNew & m)
{
    const_cast<MarshallableNew &>(m).unmarshal(p);
    return p;
}

// base type helper
inline PackNew & operator << (PackNew & p, bool sign)
{
    p.push_uint8(sign ? 1 : 0);
    return p;
}

inline PackNew & operator << (PackNew & p, uint8_t i8)
{
    p.push_uint8(i8);
    return p;
}

inline PackNew & operator << (PackNew & p, uint16_t  i16)
{
    p.push_uint16(i16);
    return p;
}

inline PackNew & operator << (PackNew & p, uint32_t  i32)
{
    p.push_uint32(i32);
    return p;
}
inline PackNew & operator << (PackNew & p, uint64_t  i64)
{
    p.push_uint64(i64);
    return p;
}

inline PackNew & operator << (PackNew & p, const std::string & str)
{
    p.push_varstr(str);
    return p;
}
#ifdef WIN32
inline PackNew & operator << (PackNew & p, const std::wstring & str)
{
    p.push_varwstring32(str);
    return p;
}
#endif
inline PackNew & operator << (PackNew & p, const Varstr & pstr)
{
    p.push_varstr(pstr);
    return p;
}

inline const UnpackNew & operator >> (const UnpackNew & p, Varstr & pstr)
{
    pstr = p.pop_varstr_ptr();
    return p;
}

// pair.first helper
// XXX std::map::value_type::first_type unpack ��Ҫ�ر���
inline const UnpackNew & operator >> (const UnpackNew & p, uint32_t & i32)
{
    i32 =  p.pop_uint32();
    return p;
}

inline const UnpackNew & operator >> (const UnpackNew & p, uint64_t & i64)
{
    i64 =  p.pop_uint64();
    return p;
}

inline const UnpackNew & operator >> (const UnpackNew & p, std::string & str)
{
    // XXX map::value_type::first_type
    str = p.pop_varstr();
    return p;
}
#ifdef WIN32
inline const UnpackNew & operator >> (const UnpackNew & p, std::wstring & str)
{
    // XXX map::value_type::first_type
    str = p.pop_varwstring32();
    return p;
}
#endif
inline const UnpackNew & operator >> (const UnpackNew & p, uint16_t & i16)
{
    i16 =  p.pop_uint16();
    return p;
}
inline const UnpackNew & operator >> (const UnpackNew & p, uint8_t & i8)
{
    i8 =  p.pop_uint8();
    return p;
}

inline const UnpackNew & operator >> (const UnpackNew & p, bool & sign)
{
    sign =  (p.pop_uint8() == 0) ? false : true;
    return p;
}


template <class T1, class T2>
inline PackNew& operator << (PackNew& s, const std::pair<T1, T2>& p)
{
    s << p.first << p.second;
    return s;
}

template <class T1, class T2>
inline const UnpackNew& operator >> (const UnpackNew& s, std::pair<const T1, T2>& p)
{
    const T1& m = p.first;
    T1 & m2 = const_cast<T1 &>(m);
    s >> m2 >> p.second;
    return s;
}

template <class T1, class T2>
inline const UnpackNew& operator >> (const UnpackNew& s, std::pair<T1, T2>& p)
{
    s >> p.first >> p.second;
    return s;
}

// container marshal helper
template < typename ContainerClass >
inline void marshal_container(PackNew & p, const ContainerClass & c)
{
    p.push_uint32(uint32_t(c.size())); // use uint32 ...
    for(typename ContainerClass::const_iterator i = c.begin(); i != c.end(); ++i)
        p << *i;
}

template < typename OutputIterator >
inline void unmarshal_container(const UnpackNew & p, OutputIterator i)
{
    for(uint32_t count = p.pop_uint32(); count > 0; --count)
    {
        typename OutputIterator::container_type::value_type tmp;
        p >> tmp;
        *i = tmp;
        ++i;
    }
}

//add by heiway 2005-08-08
//and it could unmarshal list,vector etc..
template < typename OutputContainer>
inline void unmarshal_containerEx(const UnpackNew & p, OutputContainer & c)
{
    for(uint32_t count = p.pop_uint32() ; count >0 ; --count)
    {
        typename OutputContainer::value_type tmp;
        tmp.unmarshal(p);
        c.push_back(tmp);
    }
}

#endif //LBSFORVIDEO_PACKETNEW_H
