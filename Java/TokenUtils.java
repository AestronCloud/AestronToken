package sg.bigo.token;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Random;
import java.util.zip.CRC32;


public class TokenUtils {
    private static final String TAG = "TokenUtils";
    public static final int VER_OFFSET = 0;
    public static final int VER_SIZE = 3;
    public static final int APPID_OFFSET = VER_OFFSET + VER_SIZE;
    public static final int APPID_SIZE = 32;
    public static final int TOKEN_OFFSET = APPID_OFFSET + APPID_SIZE;
    public static final int HMAC_LENGTH = 20;

    public static void parseTokenInfo(String rawToken) {
        try {
            byte[] tokenBytes = Base64.getDecoder().decode(rawToken.substring(TOKEN_OFFSET));
            ByteBuffer tokenBb = ByteBuffer.wrap(tokenBytes);
            tokenBb.put(tokenBytes);
            tokenBb.rewind();
            TokenContent tokenContent = new TokenContent();
            tokenContent.unmarshall(tokenBb);
            System.out.println(tokenContent.toString());
        } catch (Throwable e) {
            System.out.println(e.toString());
        }
    }
    
    public static int crc32(String data) {
        // get bytes from string
        byte[] bytes = data.getBytes();
        return crc32(bytes);
    }

    public static int crc32(byte[] bytes) {
        CRC32 checksum = new CRC32();
        checksum.update(bytes);
        return (int)checksum.getValue();
    }
    
    public static byte[] hmacSign(String keyString, byte[] msg) throws InvalidKeyException, NoSuchAlgorithmException {
        SecretKeySpec keySpec = new SecretKeySpec(keyString.getBytes(), "HmacSHA1");
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(keySpec);
        return mac.doFinal(msg);
    }
    
    public static byte[] byteMerger(byte[] byte_1, byte[] byte_2, byte[] byte_3, byte[] byte_4, byte[] byte_5){  
        byte[] byte_6 = new byte[byte_1.length+byte_2.length+byte_3.length+byte_4.length+byte_5.length];  
        System.arraycopy(byte_1, 0, byte_6, 0, byte_1.length);  
        System.arraycopy(byte_2, 0, byte_6, byte_1.length, byte_2.length);  
        System.arraycopy(byte_3, 0, byte_6, byte_1.length+byte_2.length, byte_3.length); 
        System.arraycopy(byte_4, 0, byte_6, byte_1.length+byte_2.length+byte_3.length, byte_4.length); 
        System.arraycopy(byte_5, 0, byte_6, byte_1.length+byte_2.length+byte_3.length+byte_4.length, byte_5.length); 
        return byte_6;  
    }  
    
    public static String genToken(String uid, String appid, String cert,  String channelName) {
        return genTokenWidthHead(uid, appid, cert, channelName, "001");
    }

    public static String genTokenV3(String uid, String appid, String cert,  String channelName) {
        return genTokenWidthHead(uid, appid, cert, channelName, "003");
    }

    private static String genTokenWidthHead(String uid, String appid, String cert, String channelName, String head) {
        RawMsg rawMsg = new RawMsg();
        Random ran = new Random();
        rawMsg.salt = ran.nextInt(1000000000);
        rawMsg.startTs = Long.valueOf(System.currentTimeMillis() / 1000).intValue();
        rawMsg.dur = 24 * 3600;
        ByteBuffer buffer = ByteBuffer.allocate(rawMsg.size());
        rawMsg.marshall(buffer);
        try {
            TokenContent tokenContent = new TokenContent();
            tokenContent.signature = hmacSign(cert, byteMerger(appid.getBytes(),
                    uid.getBytes(), channelName.getBytes(), cert.getBytes(), buffer.array()));
            tokenContent.crc32Uid = crc32(uid);
            tokenContent.crc32ChannelName = crc32(channelName);
            tokenContent.rawMsg = rawMsg;
            ByteBuffer buffer2 = ByteBuffer.allocate(tokenContent.size());
            tokenContent.marshall(buffer2);
            String base = Base64.getEncoder().encodeToString(buffer2.array());
            return head + appid + base;
        } catch (Exception e) {
            return "";
        }
    }

    public static void main(String[] args) {
        String token = TokenUtils.genToken("123456789", "tomycvho4ae2qbi5zmae8v2fom4qfohp", "asdasdadsad","channelName");
        String tokenV3 = TokenUtils.genTokenV3("123456789", "tomycvho4ae2qbi5zmae8v2fom4qfohp", "asdasdadsad","channelName");
        System.out.println(token);
        System.out.println(tokenV3);
        TokenUtils.parseTokenInfo(token);
        TokenUtils.parseTokenInfo(tokenV3);
    }
}
