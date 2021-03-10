extern crate base64;
extern crate bytes;
extern crate rand;
extern crate chrono;
extern crate crc;


use bytes::{BufMut};
use std::{u32, u64};
use chrono::prelude::*;
use crc::{crc32};

struct  Token {
    appid: String,
    cert: String
}

impl Token {
    fn new(_appid: String, _cert: String) -> Token {
        Token{
            appid: _appid,
            cert: _cert
        }
    }
}

impl Token {
    fn version(&self) -> &str {
        "001"
    }
}

impl Token {
    fn gen_signature(&self, uid:u64, cname: &str, salt:u32, gents:u32, effts:u32) -> [u8; hmacsha1::SHA1_DIGEST_BYTES] {

        let mut buf = vec![];

        buf.put(self.appid.as_bytes());
        buf.put(uid.to_string().as_bytes());
        buf.put(cname.as_bytes());
        buf.put(self.cert.as_bytes());
        buf.put_u32(salt);
        buf.put_u32(gents);
        buf.put_u32(effts);

        hmacsha1::hmac_sha1(self.cert.as_bytes(), &buf)
    }
}

impl Token {
    fn gen_token(&self, uid:u64, cname:&str) -> String{

        let salt:u32 = rand::random::<u32>();
        let dt = Local::now();
        let gents = dt.timestamp() as u32;
        let effts:u32 = 864000;
        let res:String = String::new();

        let mut buf = vec![];
        let sign = self.gen_signature(uid, cname, salt, gents, effts);
        buf.put_u16(sign.len() as u16);
        buf.put_slice(&sign);
        buf.put_u32(crc32::checksum_ieee(uid.to_string().as_bytes()));
        buf.put_u32(crc32::checksum_ieee(cname.as_bytes()));
        buf.put_u32(salt);
        buf.put_u32(gents);
        buf.put_u32(effts);

        let b64 = base64::encode(buf);
        return res + self.version() + &self.appid + &b64;
    }
}

fn main() {
    let token = Token::new("m4jxlvauzpen4rteq9p45g641kb".to_string(), 
    "dftj8oxlseg3r4q4zyzucf0xldmhpyk934ihymtw".to_string());
    println!("{}", token.gen_token(3344444444123123, "45612312312312"));
}
