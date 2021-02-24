package sg.bigo.token;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;

public class RawMsg implements Marshallable {
    public int salt;
    public int startTs;
    public int dur;

    @Override
    public int size() {
        return 12;
    }

    @Override
    public String toString() {
        return "PCS_RawMsg{" +
                "salt=" + salt +
                ",startTs=" + startTs +
                ",dur=" + dur +
                "}";
    }

    @Override
    public ByteBuffer marshall(final ByteBuffer out) {
        out.putInt(this.salt);
        out.putInt(this.startTs);
        out.putInt(this.dur);
        return out;
    }

    @Override
    public void unmarshall(final ByteBuffer in) throws InvalidProtocolData {
        try {
            this.salt = in.getInt();
            this.startTs = in.getInt();
            this.dur = in.getInt();
        } catch (BufferUnderflowException ex) {
            throw new InvalidProtocolData(ex);
        }
    }
}