package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"math/rand"
	"strconv"
	"time"
	"os"
)

const VERSION_LEN int = 3
const APPIDSTR_LEN int = 32

func version() string {
	return "001"
}

func version3() string {
	return "003"
}

type Token struct {
	appid string // appidStr
	cert  string //
}

func (this *Token) init(appid string, cert string) {
	this.appid = appid
	this.cert = cert
}

func (this *Token) genSignature(uid uint64, cname string, salt uint32, gents uint32, effts uint32) []byte {

	buffer := new(bytes.Buffer)
	buffer.WriteString(this.appid)
	buffer.WriteString(strconv.FormatUint(uid, 10))
	buffer.WriteString(cname)
	buffer.WriteString(this.cert)

	binary.Write(buffer, binary.BigEndian, []uint32{salt, gents, effts})

	key := []byte(this.cert)
	mac := hmac.New(sha1.New, key)
	mac.Write(buffer.Bytes())

	return mac.Sum(nil)
}

func (this *Token) genSignature2(uidstr string, cname string, salt uint32, gents uint32, effts uint32) []byte {

	buffer := new(bytes.Buffer)
	buffer.WriteString(this.appid)
	buffer.WriteString(uidstr)
	buffer.WriteString(cname)
	buffer.WriteString(this.cert)

	binary.Write(buffer, binary.BigEndian, []uint32{salt, gents, effts})

	key := []byte(this.cert)
	mac := hmac.New(sha1.New, key)
	mac.Write(buffer.Bytes())

	return mac.Sum(nil)
}

/* 生成token入口 */
func (this *Token) genToken(uid uint64, cname string) string {
	// 生成时间，盐值，有效期
	var gents uint32 = uint32(time.Now().Unix())
	rand.Seed(time.Now().UnixNano())
	var salt uint32 = rand.Uint32()
	var effts uint32 = 864000

	resbuffer := new(bytes.Buffer)

	// 序列号签名
	sigbuf := this.genSignature(uid, cname, salt, gents, effts)
	var siglen uint16
	siglen = uint16(len(sigbuf))
	binary.Write(resbuffer, binary.BigEndian, siglen)
	binary.Write(resbuffer, binary.BigEndian, sigbuf)

	// 序列化uid crc32
	bytesbuffer := new(bytes.Buffer)
	bytesbuffer.WriteString(strconv.FormatUint(uid, 10))
	crc32uid := crc32.ChecksumIEEE(bytesbuffer.Bytes())
	binary.Write(resbuffer, binary.BigEndian, crc32uid)

	// 序列化 channel name crc32
	bytesbuffer.Reset()
	bytesbuffer.WriteString(cname)
	crc32cname := crc32.ChecksumIEEE(bytesbuffer.Bytes())
	binary.Write(resbuffer, binary.BigEndian, crc32cname)

	// 序列化盐值、生成时间、有效时间
	binary.Write(resbuffer, binary.BigEndian, salt)
	binary.Write(resbuffer, binary.BigEndian, gents)
	binary.Write(resbuffer, binary.BigEndian, effts)

	res := version() + this.appid + base64.StdEncoding.EncodeToString(resbuffer.Bytes())

	return res
}

/* The entrance of generating the token*/
/* 生成webrtc token入口 */
func (this *Token) genTokenV3(uidstr string, cname string) string {
	// Generation time, salt, expiration date
	// 生成时间，盐值，有效期
	var gents uint32 = uint32(time.Now().Unix())
	rand.Seed(time.Now().UnixNano())
	var salt uint32 = rand.Uint32()
	var effts uint32 = 864000

	resbuffer := new(bytes.Buffer)

	// Serialize the signature
	// 序列号签名
	sigbuf := this.genSignature2(uidstr, cname, salt, gents, effts)
	var siglen uint16
	siglen = uint16(len(sigbuf))
	binary.Write(resbuffer, binary.BigEndian, siglen)
	binary.Write(resbuffer, binary.BigEndian, sigbuf)

	// Serialize the crc32 checksum of the UID
	// 序列化uid crc32
	bytesbuffer := new(bytes.Buffer)
	bytesbuffer.WriteString(uidstr)
	crc32uid := crc32.ChecksumIEEE(bytesbuffer.Bytes())
	binary.Write(resbuffer, binary.BigEndian, crc32uid)

	// Serialize the crc32 checksum of the  channel name
	// 序列化 channel name crc32
	bytesbuffer.Reset()
	bytesbuffer.WriteString(cname)
	crc32cname := crc32.ChecksumIEEE(bytesbuffer.Bytes())
	binary.Write(resbuffer, binary.BigEndian, crc32cname)

	// Serialize the salt, generation time, and expiration date
	// 序列化盐值、生成时间、有效时间
	binary.Write(resbuffer, binary.BigEndian, salt)
	binary.Write(resbuffer, binary.BigEndian, gents)
	binary.Write(resbuffer, binary.BigEndian, effts)

	res := version3() + this.appid + base64.StdEncoding.EncodeToString(resbuffer.Bytes())

	return res
}

func (this *Token) parseToken(s string) (uint32, uint32, uint32, string) {
	if len(s) < VERSION_LEN+APPIDSTR_LEN {
		return 0, 0, 0, ""
	}

	ver := s[0:VERSION_LEN]
	if ver != version() {
		return 0, 0, 0, ""
	}

	appid := s[VERSION_LEN : VERSION_LEN+APPIDSTR_LEN]
	encstr := s[VERSION_LEN+APPIDSTR_LEN:]
	if len(appid) < 1 {
		return 0, 0, 0, ""
	}
	if len(encstr) < 1 {
		return 0, 0, 0, ""
	}

	decodeBytes, err := base64.StdEncoding.DecodeString(encstr)
	if err != nil {
		fmt.Println(err)
		return 0, 0, 0, ""
	}

	decbuffer := bytes.NewBuffer(decodeBytes)

	var siglen uint16
	binary.Read(decbuffer, binary.BigEndian, &siglen)
	sigbytes := make([]byte, siglen)
	decbuffer.Read(sigbytes)
	sigstr := string(sigbytes)

	var crc32uid, crc32cname, salt, gents, effts uint32

	binary.Read(decbuffer, binary.BigEndian, &crc32uid)
	binary.Read(decbuffer, binary.BigEndian, &crc32cname)
	binary.Read(decbuffer, binary.BigEndian, &salt)
	binary.Read(decbuffer, binary.BigEndian, &gents)
	binary.Read(decbuffer, binary.BigEndian, &effts)

	return salt, gents, effts, sigstr
}

func (this *Token) checkToken(token string, cname string, uid uint64) bool {

	salt, gents, effts, sigstr := this.parseToken(token)

	if gents == 0 {
		fmt.Println("parseToken failed")
		return false
	}

	// check if time expired, 检查token是否过期
	if (gents + effts) < uint32(time.Now().Unix()) {
		fmt.Println("token expired")
		return false
	}

	// check if signature valid, 检查签名是否有效
	signatureNow := string(this.genSignature(uid, cname, salt, gents, effts))
	if sigstr == signatureNow {
		fmt.Println("token valid!!!!")
		return true
	} else {
		fmt.Println("token invalid????")
		return false
	}
}

func main() {
	// init token witch appid and cert;
	var token Token
	token.init("appid_which_should_be_32_length_", "mycert_string")

	// generate token
	fmt.Println("token:", token.genToken(3344444444123123, "45612312312312"))

	// generate token v3, which is used by Aestron webrtc.
	fmt.Println("WebRtc token:", token.genTokenV3("Rubin", "test"))

	// this is for check token test. remove if don't need
	tokenstr := os.Args[1]
	cname := os.Args[2]
	uid, _ := strconv.ParseUint(os.Args[3], 10, 64)
	fmt.Println(token.checkToken(tokenstr, cname, uid))
	fmt.Println(token.genToken(uid, cname));
}
