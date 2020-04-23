package host_app;

/**
 * @author Daniel Zatovic
 */
public class Cryptogram {
    final static byte CRYPTOGRAM_MAGIC = 0x31;
    final static byte CRYPTOGRAM_HEADER_LENGTH = 4;

    final static byte OFFSET_CRYPTOGRAM_MAGIC = 0;
    final static byte OFFSET_CRYPTOGRAM_LENGTH = 1;
    final static byte OFFSET_CRYPTOGRAM_SEQNUM = 2;
    final static byte OFFSET_CRYPTOGRAM_INS = 3;
    final static byte OFFSET_CRYPTOGRAM_DATA = CRYPTOGRAM_HEADER_LENGTH;

    public byte seqnum;
    public byte ins;
    public byte[] payload;

    public Cryptogram(byte instruction, byte sequenceNumber, byte[] payloadData) {
        seqnum = sequenceNumber;
        ins = instruction;
        payload = payloadData;
    }

    public Cryptogram(byte[] cryptogramData) {
        if (cryptogramData[OFFSET_CRYPTOGRAM_MAGIC] != CRYPTOGRAM_MAGIC) {
            throw new IllegalArgumentException("Invalid cryptogram received.");
        }

        short length = cryptogramData[OFFSET_CRYPTOGRAM_LENGTH];
        payload = new byte[length];

        System.arraycopy(cryptogramData, OFFSET_CRYPTOGRAM_DATA, payload, 0, payload.length);

        ins = cryptogramData[OFFSET_CRYPTOGRAM_INS];
        seqnum = cryptogramData[OFFSET_CRYPTOGRAM_SEQNUM];
    }

    public byte[] getBytes() {
        byte[] bytes = new byte[CRYPTOGRAM_HEADER_LENGTH + payload.length];

        bytes[OFFSET_CRYPTOGRAM_MAGIC] = CRYPTOGRAM_MAGIC;
        bytes[OFFSET_CRYPTOGRAM_LENGTH] = (byte) payload.length;
        bytes[OFFSET_CRYPTOGRAM_SEQNUM] = seqnum;
        bytes[OFFSET_CRYPTOGRAM_INS] = ins;

        System.arraycopy(payload, 0, bytes, OFFSET_CRYPTOGRAM_DATA, payload.length);
        return bytes;
    }
}

