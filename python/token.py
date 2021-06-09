# /bin/python
# -*- coding: UTF-8 -*-
import hmac
from struct import pack
from hashlib import sha1
import time
import random
import base64
from zlib import crc32

class Token:
    def __init__(self, appid, cert):
        self._appid = appid
        self._cert = cert

    def version(self):
        return "001"

    def version3(self):
        return "003"        

    def genSignature(self, uid, cname, salt, gents, effts):
        return hmac.new(
            self._cert, 
            "".join([self._appid, str(uid), cname, self._cert, pack(">I", salt), pack(">I", gents), pack(">I", effts)]),
            sha1
            ).digest()

    def genToken(self, uid, cname):
        gents = int(time.time())                   #生成时间
        effts = 864000                             #有效期
        salt = random.randint(0, 2147483648)       #盐值 0-2**31
        uidstr = str(uid)

        print(crc32(str(uid)), int(bin(crc32(uidstr) & 0xFFFFFFFF), 2), type(crc32(str(uid))), bin(crc32(str(uid))))
        sign = self.genSignature(uidstr, cname, salt, gents, effts)
        return self.version() + self._appid + base64.b64encode("".join([
            pack(">H", len(sign)), self.genSignature(uid, cname, salt, gents, effts),
            pack(">I", int(bin(crc32(uidstr) & 0xFFFFFFFF), 2)),
            pack(">I", int(bin(crc32(cname) & 0xFFFFFFFF), 2)),
            pack(">I", salt),
            pack(">I", gents),
            pack(">I", effts)]))

    def genTokenV3(self, uidstr, cname):
        gents = int(time.time())                   #生成时间
        effts = 864000                             #有效期
        salt = random.randint(0, 2147483648)       #盐值 0-2**31

        print(crc32(uidstr), int(bin(crc32(uidstr) & 0xFFFFFFFF), 2), type(crc32(uidstr)), bin(crc32(uidstr)))
        sign = self.genSignature(uidstr, cname, salt, gents, effts)
        return self.version3() + self._appid + base64.b64encode("".join([
            pack(">H", len(sign)), self.genSignature(uidstr, cname, salt, gents, effts),
            pack(">I", int(bin(crc32(uidstr) & 0xFFFFFFFF), 2)),
            pack(">I", int(bin(crc32(cname) & 0xFFFFFFFF), 2)),
            pack(">I", salt),
            pack(">I", gents),
            pack(">I", effts)]))            

# init token generator witch appid and cert
token = Token("myappid_string", "mycert_string")

# generator token
print(token.genToken(3344444444123123, "45612312312312"))

# generator token v3, which is used by webrtc.
print(token.genTokenV3("Rubin", "test"))
