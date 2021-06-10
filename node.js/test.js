/**
 * created by zhangzihao on {2021/6/10}
 */
const RtcToken = require('./token');

const appid = '你的appid';
const channelName = '你的频道名称';
const uid = '你的uid';
const cert = '你的证书';
const duration = 86400; // 有效时间 单位秒 从生成开始算
const version = '003' // 版本号 目前为 001 与 003 均为字符串

if (!appid || !channelName || !uid || !cert) {
    console.log('appid,channelName,uidStr,cert 不可为空');
    return;
}

const rtcToken = new RtcToken({ appid, cert });

console.log(`appid=${appid},channelName=${channelName},uid=${uid}`);
const token = rtcToken.genToken({ channelName, uid, duration, version });
rtcToken.checkToken({ token, channelName, uid, duration, version });
console.log('token =', token);