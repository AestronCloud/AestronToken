'use strict';

const Service = require('@bigo/bgegg').Service;
const crypto = require("crypto");
const VERSION = '001';
const VERSION_LENGTH = 3;
const APP_ID_LENGTH = 32;
const HMAC_LENGTH = 20;
const HMAC_SHA256_LENGTH = 32;
const CERTIFATE = '01234567890123456789012345678901';

class SdkService extends Service {

  /**
   * @description
   * 1. tokenCheck = parseToken(token)
   * 2. string signatureNow = genSignature(m_certificate, m_appId, m_uidStr, m_channelName, rawMsgStr);
   * 3. 0 != signatureNow.compare(tokenCheck.m_signature)
   * @param params
   */

  checkToken({ token, appid, channelName, uid }) {
    const { ctx } = this;
    const { salt, genTs, effeTs, signature } = this.parseToken(token);
    // 时间校验
    if ((genTs + effeTs) < Date.now() / 1000 ) {
      return ctx.fail({ msg: 'token已失效' });
    }

    // 生成签名用于校验
    const signatureNow = this.genSignature(appid, uid, channelName, { salt, genTs, effeTs } );

    if (signatureNow === signature) {
      return ctx.success({ data: this.genSignatureRes(token) });
    }

    const msg = 'signatrue generated != signature recv.\n'
    ctx.logger.warn(msg);
    return ctx.fail({ msg });
  }

  /**
   * @description 生成签名函数
   * @param
   */
  genSignature(appid, uid, channelName, { salt, genTs, effeTs }) {
    let ssBf = Buffer.from(appid + uid + channelName + CERTIFATE);
    let rawBf = new Uint32Array([salt, genTs, effeTs]).reverse();
    rawBf = Buffer.from(new Uint8Array(rawBf.buffer).reverse());
    
    let hmac = crypto.createHmac('sha1', CERTIFATE);
    hmac.update(Buffer.concat([ssBf, rawBf]));
    return hmac.digest().toString('base64');
  }

  /**
   * @description 生成签名函数
   * @param
   */
  genSignatureRes(token) {
    const key = 'B!g0@6v7';
    let hmac = crypto.createHmac('sha1', key);
    hmac.update(token);
    return hmac.digest('hex');
  }

  /**
   * @description
   * @param token
   */
  parseToken(token) {
    const { ctx } = this;
    if (!token) {
      return ctx.fail({ msg: 'token is null, return.\n' });
    }
    if (token.substr(0, VERSION_LENGTH) !== VERSION) {
      return ctx.fail({ msg: 'version error.\n' });
    }

    const tokenCheck = {};
    tokenCheck.appId = token.substr(VERSION_LENGTH, APP_ID_LENGTH);

    //todo:错误判断
    let base64Src = token.substr(VERSION_LENGTH + APP_ID_LENGTH);
    let base64Bf = new Buffer(base64Src, 'base64');
    let base64Ab = ctx.helper.toArrayBuffer(base64Bf);
    let base64Dv = new DataView(base64Ab);
    // 读取前两个字节为signature length
    const signByteLength = 2;
    const otherByteLength = 4;
    const signatureLenth = base64Dv.getUint16(0);

    let signAb = new Uint8Array(base64Ab);
    signAb = signAb.slice(signByteLength, signByteLength + signatureLenth);

    //todo:反序列化
    tokenCheck.signature = ctx.helper.toBuffer(signAb).toString('base64');
    tokenCheck.crc32Uid = base64Dv.getUint32(signByteLength + signatureLenth);
    tokenCheck.crc32ChannelName = base64Dv.getUint32(signByteLength + signatureLenth + otherByteLength);
    tokenCheck.salt = base64Dv.getUint32(signByteLength + signatureLenth + 2 * otherByteLength);
    tokenCheck.genTs = base64Dv.getUint32(signByteLength + signatureLenth + 3 * otherByteLength);
    tokenCheck.effeTs = base64Dv.getUint32(signByteLength + signatureLenth + 4 * otherByteLength);
    tokenCheck.isTokenValid = true;

    ctx.logger.info('sdk parseToken: token %s, appId %s, crcUid %u, crcChannelName %u, generate ts %u, effective ts %u.',
      token, tokenCheck.appId, tokenCheck.crc32Uid, tokenCheck.crc32ChannelName, tokenCheck.genTs, tokenCheck.effeTs);
    return tokenCheck;
  }

}

module.exports = SdkService;
