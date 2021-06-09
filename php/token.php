<?php

define('BIG_ENDIAN', pack('L', 1) === pack('N', 1));

class Token {
    private $VERSION;
    private $VERSION3;
    private $APPID;
    private $CERTIFICATE;

    /**
     * 初始化appid, 证书，以及版本号
     */
    function __construct($appid, $cert) {
        $this->APPID = $appid;
        $this->CERTIFICATE = $cert;
        $this->VERSION = "001";
        $this->VERSION3 = "003";
    }

    private function genSignature($uid, $cname, $salt, $gents, $effts) {
      return hash_hmac('sha1', $this->APPID . $uid . $cname . $this->CERTIFICATE . pack("N", $salt) . 
                pack("N", $gents) . pack("N", $effts), $this->CERTIFICATE, true);
    }

    /**
     * @return string
     *         token字符串
     * @paramater uid u64位，cname string
     *         uid 是用户唯一标识，cname是频道名
     *         由于php默认不支持64位uid，建议自定义32位uid
     */
    function genToken($uid, $cname) {
        // 生成时间，盐值，有效期
        $gents = time();
        echo "gents: " . $gents . "\n";

        // 随机数，0-2^31
        $salt = mt_rand(0, 2147483648);  
        echo "salt: " . $salt . "\n";

        // 有效期，一天
        $effts = 864000;

        $sigbuf = $this->genSignature($uid, $cname, $salt, $gents, $effts);
        return $this->VERSION . $this->APPID . 
                base64_encode(
                    pack("n", strlen($sigbuf)) . $sigbuf . 
                    pack("N", crc32("" . $uid)) . pack("N", crc32($cname)) . 
                    pack("N", $salt) . pack("N", $gents) . pack("N", $effts)
                );   
    }

    function genTokenV3($uid, $cname) {
        // 生成时间，盐值，有效期
        $gents = time();
        echo "gents: " . $gents . "\n";

        // 随机数，0-2^31
        $salt = mt_rand(0, 2147483648);  
        echo "salt: " . $salt . "\n";

        // 有效期，一天
        $effts = 864000;

        $sigbuf = $this->genSignature($uid, $cname, $salt, $gents, $effts);
        return $this->VERSION3 . $this->APPID . 
                base64_encode(
                    pack("n", strlen($sigbuf)) . $sigbuf . 
                    pack("N", crc32("" . $uid)) . pack("N", crc32($cname)) . 
                    pack("N", $salt) . pack("N", $gents) . pack("N", $effts)
                );   
    }
}

$token = new Token("myappid_string", "mycert_string");
// token generator
echo $token->genToken(3344444444123123, "45612312312312") . "\n";

// tokenV3, webrtc should use this token
echo $token->genTokenV3("Rubin", "test") . "\n";

?>