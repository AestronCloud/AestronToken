package sg.bigo.tokengentest;

public class InvalidProtocolData extends Exception {
    private static final long serialVersionUID = 1L;

    public InvalidProtocolData(Exception e) {
        super("Invalid Protocol Data", e);
    }

    public InvalidProtocolData(String error) {
        super(error);
    }
}
