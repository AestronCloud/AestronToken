package sg.bigo.tokengentest;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;

public interface Marshallable {
    int size();

    ByteBuffer marshall(ByteBuffer out);

    void unmarshall(ByteBuffer in) throws InvalidProtocolData;
    
    public static int calcMarshallSize(byte[] byteArray) {
        if (byteArray != null) {
            return (2 + byteArray.length);
        }
        return 2;
    }

    public static int calcMarshallSize(String string) {
        if (string != null) {
            return 2 + string.getBytes().length;
        }
        return 2;
    }
    
    public static byte[] unMarshallByteArray(ByteBuffer bb) throws InvalidProtocolData {
        try {
            byte[] data = null;
            short byteLen = bb.getShort();
            if (byteLen < 0) {
                throw new InvalidProtocolData("byteLen < 0");
            }
            if (byteLen > 0) {
                data = new byte[byteLen];
                bb.get(data);
                return data;
            } else {
                return null;
            }
        } catch (BufferUnderflowException e) {
            throw new InvalidProtocolData(e);
        }
    }
}
