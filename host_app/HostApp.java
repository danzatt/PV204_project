package host;

import src.main.java.applet.SecureChannelApplet;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;


import javax.crypto.KeyAgreement;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;

public class HostApp {
    private static final String APPLET_AID = "12345678912345678900";
    private static final byte INS_DH_INIT = (byte) 0x50;
    final static byte CLA_SIMPLEAPPLET = (byte) 0xB0;
    
    private static byte[] sharedSecret;
    /**
     * Main entry point.
     *
     * @param args
     */
    public static void main(String[] args) throws Exception {
        CardSimulator simulator = new CardSimulator();

        System.out.println("ALICE: Generate DH keypair ...");
        KeyPairGenerator aliceKpairGen = KeyPairGenerator.getInstance("EC");

        aliceKpairGen.initialize(CurveSpecs.EC_P256K_PARAMS);
        KeyPair aliceKpair = aliceKpairGen.generateKeyPair();

        // Alice creates and initializes her ECDH KeyAgreement object
        System.out.println("ALICE: Initialization ...");
        KeyAgreement aliceKeyAgree = KeyAgreement.getInstance("ECDH");
        aliceKeyAgree.init(aliceKpair.getPrivate());

        // Alice encodes her public key, and sends it over to Bob.
        byte[] alicePubKeyEnc = aliceKpair.getPublic().getEncoded();

        ECPoint publicKey = ((ECPublicKey) aliceKpair.getPublic()).getW();
        byte[] publicKeyX = publicKey.getAffineX().toByteArray();
        if (publicKeyX[0] == 0) {  // trim the leading zero
            byte[] tmp = new byte[publicKeyX.length - 1];
            System.arraycopy(publicKeyX, 1, tmp, 0, tmp.length);
            publicKeyX = tmp;
        }

        byte[] publicKeyY = publicKey.getAffineY().toByteArray();
        if (publicKeyY[0] == 0) {  // trim the leading zero
            byte[] tmp = new byte[publicKeyY.length - 1];
            System.arraycopy(publicKeyY, 1, tmp, 0, tmp.length);
            publicKeyY = tmp;
        }

        byte[] publicKeyWRaw = new byte[1 + publicKeyX.length * 2];
        publicKeyWRaw[0] = 0x04; // uncompressed form
        System.arraycopy(publicKeyX, 0, publicKeyWRaw, 1, publicKeyX.length);
        System.arraycopy(publicKeyY, 0, publicKeyWRaw, 1 + publicKeyX.length, publicKeyY.length);

        AID appletAID = AIDUtil.create(APPLET_AID);
        simulator.installApplet(appletAID, SecureChannelApplet.class);

        simulator.selectApplet(appletAID);

        CommandAPDU commandAPDU = new CommandAPDU(CLA_SIMPLEAPPLET, INS_DH_INIT, 0x00, 0x00, publicKeyWRaw);
        ResponseAPDU response = simulator.transmitCommand(commandAPDU);
        System.out.println(response);

        printBytes(response.getData());
        System.out.println(response.getData().length);
        System.out.println("Length: " + response.getData().length);

        if (response.getData().length != (1 + publicKeyX.length * 2) || response.getData()[0] != 0x04) {
            throw new IllegalArgumentException("Wrong public key from card.");
        }

        byte[] cardPublicKeyX = new byte[publicKeyX.length];
        byte[] cardPublicKeyY = new byte[publicKeyX.length];

        System.arraycopy(response.getData(), 1, cardPublicKeyX, 0, publicKeyX.length);
        System.arraycopy(response.getData(), 1 + publicKeyX.length, cardPublicKeyY, 0, publicKeyX.length);

        ECPoint ecPoint = new ECPoint(new BigInteger(cardPublicKeyX), new BigInteger(cardPublicKeyY));
        ECPublicKeySpec cardKeySpec = new ECPublicKeySpec(ecPoint, CurveSpecs.EC_P256K_PARAMS);

        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        PublicKey cardPublicKey = keyFactory.generatePublic(cardKeySpec);

        aliceKeyAgree.doPhase(cardPublicKey, true);

        byte[] aliceSharedSecret = aliceKeyAgree.generateSecret();

        MessageDigest crypt = MessageDigest.getInstance("SHA-1");
        crypt.reset();
        crypt.update(aliceSharedSecret);
        sharedSecret = crypt.digest();
    }

    private static void printBytes(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for(byte b: data)
            sb.append(String.format("%02x", b));
        System.out.println(sb.toString());
    }

    /*
     * Converts a byte to hex digit and writes to the supplied buffer
     */
    private static void byte2hex(byte b, StringBuffer buf) {
        char[] hexChars = { '0', '1', '2', '3', '4', '5', '6', '7', '8',
                '9', 'A', 'B', 'C', 'D', 'E', 'F' };
        int high = ((b & 0xf0) >> 4);
        int low = (b & 0x0f);
        buf.append(hexChars[high]);
        buf.append(hexChars[low]);
    }

    /*
     * Converts a byte array to hex string
     */
    private static String toHexString(byte[] block) {
        StringBuffer buf = new StringBuffer();
        int len = block.length;
        for (int i = 0; i < len; i++) {
            byte2hex(block[i], buf);
            if (i < len-1) {
                buf.append(":");
            }
        }
        return buf.toString();
    }
}
