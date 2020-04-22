package host;

import host_app.Config;
import src.main.java.applet.SecureChannelApplet;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;


import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

public class HostApp {
    private static final String APPLET_AID = "12345678912345678900";
    private static final byte INS_DH_INIT = (byte) 0x50;
    final static byte CLA_SECURECHANNEL = (byte) 0xB0;

    private static byte[] trimLeadingZero(byte[] bytes) {
        if (bytes[0] == 0) {  // trim the leading zero
            byte[] tmp = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, tmp, 0, tmp.length);
            return tmp;
        }
        return bytes;
    }

    private static byte[] publicKeyToRaw(ECPublicKey pubKey) {
        ECPoint publicKeyPoint = pubKey.getW();
        byte[] publicKeyX = trimLeadingZero(publicKeyPoint.getAffineX().toByteArray());
        byte[] publicKeyY = trimLeadingZero(publicKeyPoint.getAffineY().toByteArray());

        if (publicKeyX.length != Config.singleCoordLength || publicKeyY.length != Config.singleCoordLength) {
            throw new IllegalArgumentException("Different key length than configured.");
        }

        byte[] publicKeyWRaw = new byte[1 + publicKeyX.length * 2 + 31];
        publicKeyWRaw[0] = 0x04; // uncompressed form
        System.arraycopy(publicKeyX, 0, publicKeyWRaw, 1, publicKeyX.length);
        System.arraycopy(publicKeyY, 0, publicKeyWRaw, 1 + publicKeyX.length, publicKeyY.length);

        return publicKeyWRaw;
    }

    private static ECPublicKey publicKeyFromRaw(byte[] publicKeyWRaw) {
        byte[] cardPublicKeyX = new byte[Config.singleCoordLength];
        byte[] cardPublicKeyY = new byte[Config.singleCoordLength];

        System.arraycopy(publicKeyWRaw, 1, cardPublicKeyX, 0, Config.singleCoordLength);
        System.arraycopy(publicKeyWRaw, 1 + Config.singleCoordLength, cardPublicKeyY, 0, Config.singleCoordLength);

        ECPoint ecPoint = new ECPoint(new BigInteger(cardPublicKeyX), new BigInteger(cardPublicKeyY));
        ECPublicKeySpec cardKeySpec = new ECPublicKeySpec(ecPoint, CurveSpecs.EC_P256K_PARAMS);

        try {
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            return (ECPublicKey) keyFactory.generatePublic(cardKeySpec);
        } catch (NoSuchAlgorithmException| InvalidKeySpecException e) {
            return null;
        }
    }

    private static byte[] hashPin(byte[] pin) {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-1");
            byte[] hPin = sha.digest(pin);
            hPin = Arrays.copyOf(hPin, 16);
            return hPin;
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
    }

    private static byte[] negotiateSecret(CardSimulator simulator) {
        try {
            System.out.println("Generating ECDH keypair...");
            KeyPairGenerator ECKeyPairGen = KeyPairGenerator.getInstance("EC");
            ECKeyPairGen.initialize(CurveSpecs.EC_P256K_PARAMS);
            KeyPair ECKeyPair = ECKeyPairGen.generateKeyPair();

            System.out.println("Initializating key agreement...");
            KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
            keyAgreement.init(ECKeyPair.getPrivate());

            SecretKeySpec hPinAesKeySpec = new SecretKeySpec(hashPin(new byte[]{'1', '2', '3', '4'}), "AES");

            byte[] publicKeyWRaw = publicKeyToRaw((ECPublicKey) ECKeyPair.getPublic());

            Cipher cipher = Cipher.getInstance("AES/ECB/NOPADDING");
            cipher.init(Cipher.ENCRYPT_MODE, hPinAesKeySpec);
            printBytes(publicKeyWRaw);
            byte[] publicKeyWRawEncrypted = cipher.doFinal(publicKeyWRaw);
            printBytes(publicKeyWRawEncrypted);

            CommandAPDU commandAPDU = new CommandAPDU(CLA_SECURECHANNEL, INS_DH_INIT, 0x00, 0x00, publicKeyWRawEncrypted);
            ResponseAPDU response = simulator.transmitCommand(commandAPDU);
            System.out.println(response);
            printBytes(response.getData());
            System.out.println("Data length: " + response.getData().length);

            if (response.getData().length != Config.paddedKeySize) {
                throw new IllegalArgumentException("Wrong public key from card." + response.getData().length);
            }

            cipher.init(Cipher.DECRYPT_MODE, hPinAesKeySpec);
            byte[] responseDecrypted = cipher.doFinal(response.getData());

            PublicKey cardPublicKey = publicKeyFromRaw(responseDecrypted);
            keyAgreement.doPhase(cardPublicKey, true);

            byte[] sharedSecretRaw = keyAgreement.generateSecret();

            MessageDigest crypt = MessageDigest.getInstance("SHA-1");
            crypt.reset();
            crypt.update(sharedSecretRaw);
            return crypt.digest();
        } catch (NoSuchAlgorithmException| InvalidAlgorithmParameterException| InvalidKeyException|
                    NoSuchPaddingException| IllegalBlockSizeException| BadPaddingException e) {
            return null;
        }
    }

    /**
     * Main entry point.
     *
     * @param args
     */
    public static void main(String[] args) throws Exception {
        CardSimulator simulator = new CardSimulator();
        AID appletAID = AIDUtil.create(APPLET_AID);

        simulator.installApplet(appletAID, SecureChannelApplet.class);
        simulator.selectApplet(appletAID);

        byte[] sharedSecret = negotiateSecret(simulator);
        printBytes(sharedSecret);
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
