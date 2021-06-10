'use strict';

const crypto = require('crypto');
const crc32 = require('crc32');

const CONSTANT = {
  VERSION_LENGTH: 3,
  APP_ID_LENGTH: 32,
  TWO_LENGTH: 2,
  FOUR_LENGTH: 4
}

const HELPER = {
  /**
   * @description Buffer to ArrayBuffer 
   * @params Buffer
   */

  toArrayBuffer(buf) {
    let ab = new ArrayBuffer(buf.length);
    let view = new Uint8Array(ab);
    for (let i = 0; i < buf.length; ++i) {
      view[i] = buf[i];
    }
    return ab;
  },

  /**
   * @description ArrayBuffer to Buffer 
   * @params ArrayBuffer
   */

  toBuffer(ab) {
    let buf = [];
    let view = new Uint8Array(ab);
    for (let i = 0; i < ab.byteLength; ++i) {
      buf[i] = view[i];
    }
    return Buffer.from(buf);
  }
}

class Token {
  constructor({ cert, appid }) {
    if (!cert || !appid) throw new Error('初始化需要appid与证书');
    this.cert = cert;
    this.appid = appid;
  }

  /**
   * @description token校验入口
   * @param params
   */

  checkToken({ token, channelName, uid, version = '003' }) {
    const { salt, genTs, effeTs, signature } = this.parseToken(token, version);
    // 时间校验
    if ((genTs + effeTs) < Date.now() / 1000 ) {
      console.log('token已失效');
      return;
    }
    // 生成签名用于校验
    const signatureNow = this.genSignature(uid, channelName, { salt, genTs, effeTs } );

    if (signatureNow === signature) {
      console.log('token校验通过');
      return;
    }

    console.log('signatrue generated != signature recv.');
    return;
  }

  genToken({ version = '003', channelName, uid, duration = 86400 }) {
    const { TWO_LENGTH, FOUR_LENGTH } = CONSTANT;
    const salt = parseInt(Math.random() * 100000);
    const genTs = parseInt(Date.now() / 1000);
    const effeTs = duration; // 秒

    // 生成签名并转为buffer
    const signature = this.genSignature(uid, channelName, { salt, genTs, effeTs } );
    const sbf = Buffer.from(signature, 'base64')

    const signLength = sbf.length;
    const ab = new ArrayBuffer(TWO_LENGTH + signLength + 5 * FOUR_LENGTH);
    const db = new DataView(ab);
    db.setUint16(0, signLength);
    for (let i = 0; i < signLength; i++) {  
      db.setUint8(i + TWO_LENGTH, sbf[i]);
    }
    db.setUint32(TWO_LENGTH + signLength, parseInt(crc32(uid), 16));
    db.setUint32(TWO_LENGTH + signLength + FOUR_LENGTH, parseInt(crc32(channelName), 16));
    db.setUint32(TWO_LENGTH + signLength + FOUR_LENGTH * 2, salt);
    db.setUint32(TWO_LENGTH + signLength + FOUR_LENGTH * 3, genTs);
    db.setUint32(TWO_LENGTH + signLength + FOUR_LENGTH * 4, effeTs);
    return `${version}${this.appid}${HELPER.toBuffer(ab).toString('base64')}`;
  }

  /**
   * @description 生成签名函数
   * @param
   */
  genSignature(uid, channelName, { salt, genTs, effeTs }) {
    let ssBf = Buffer.from(this.appid + uid + channelName + this.cert);
    let rawBf = new Uint32Array([salt, genTs, effeTs]).reverse();
    rawBf = Buffer.from(new Uint8Array(rawBf.buffer).reverse());
    let hmac = crypto.createHmac('sha1', this.cert);
    hmac.update(Buffer.concat([ssBf, rawBf]));
    return hmac.digest().toString('base64');
  }

  /**
   * @description
   * @param token
   */
  parseToken(token, version) {
    const { TWO_LENGTH, FOUR_LENGTH, VERSION_LENGTH, APP_ID_LENGTH } = CONSTANT;
    if (!token) {
      console.log('token is null, return.\n');
      return;
    }
    if (token.substr(0, VERSION_LENGTH) !== version) {
      console.log('version error.\n');
      return;
    }

    const tokenCheck = {};
    tokenCheck.appId = token.substr(VERSION_LENGTH, APP_ID_LENGTH);

    //todo:错误判断
    let base64Src = token.substr(VERSION_LENGTH + APP_ID_LENGTH);
    let base64Bf = Buffer.from(base64Src, 'base64');
    let base64Ab = HELPER.toArrayBuffer(base64Bf);
    let base64Dv = new DataView(base64Ab);
    // 读取前两个字节为signature length
    const signatureLenth = base64Dv.getUint16(0);

    let signAb = new Uint8Array(base64Ab);
    signAb = signAb.slice(TWO_LENGTH, TWO_LENGTH + signatureLenth);

    //todo:反序列化
    tokenCheck.signature = HELPER.toBuffer(signAb).toString('base64');
    tokenCheck.crc32Uid = base64Dv.getUint32(TWO_LENGTH + signatureLenth);
    tokenCheck.crc32ChannelName = base64Dv.getUint32(TWO_LENGTH + signatureLenth + FOUR_LENGTH);
    tokenCheck.salt = base64Dv.getUint32(TWO_LENGTH + signatureLenth + 2 * FOUR_LENGTH);
    tokenCheck.genTs = base64Dv.getUint32(TWO_LENGTH + signatureLenth + 3 * FOUR_LENGTH);
    tokenCheck.effeTs = base64Dv.getUint32(TWO_LENGTH + signatureLenth + 4 * FOUR_LENGTH);
    tokenCheck.isTokenValid = true;

    console.log('sdk parseToken: token %s, appId %s, crcUid %s, crcChannelName %s, generate ts %s, effective ts %s.',
      token, tokenCheck.appId, tokenCheck.crc32Uid, tokenCheck.crc32ChannelName, tokenCheck.genTs, tokenCheck.effeTs);
    return tokenCheck;
  }
}

module.exports = Token;





