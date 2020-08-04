package sg.bigo.tokengentest;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;

public class TokenContent implements Marshallable {
    public byte[] signature;
    public int crc32Uid;
    public int crc32ChannelName;
    public RawMsg rawMsg = new RawMsg();

    @Override
    public int size() {
        return 8 + Marshallable.calcMarshallSize(this.signature) + rawMsg.size(); //todo unsupported: | sg.bigo.opensdk.lbs.pcs.PCS_RawMsg rawMsg
    }

    @Override
    public String toString() {
        return "PCS_TokenContent{" +
                "signature=" + new String(signature) +
                ",crc32Uid=" + crc32Uid +
                ",crc32ChannelName=" + crc32ChannelName +
                ",rawMsg=" + rawMsg +
                "}";
    }

    @Override
    public ByteBuffer marshall(final ByteBuffer out) {
        if (this.signature != null) {
            out.putShort((short) this.signature.length);
            out.put(this.signature);
        } else {
            out.putShort((short) 0);
        }
        out.putInt(this.crc32Uid);
        out.putInt(this.crc32ChannelName);
        rawMsg.marshall(out);
        //todo PsiType:PCS_RawMsg rawMsg not supported
        return out;
    }

    @Override
    public void unmarshall(final ByteBuffer in) throws InvalidProtocolData {
        try {
            this.signature = Marshallable.unMarshallByteArray(in);
            this.crc32Uid = in.getInt();
            this.crc32ChannelName = in.getInt();
            this.rawMsg.unmarshall(in);
        } catch (BufferUnderflowException ex) {
            throw new InvalidProtocolData(ex);
        }
    }
}
