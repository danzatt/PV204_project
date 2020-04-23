package host;

import host_app.Config;
import host_app.Cryptogram;
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
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;

public class HostApp {
    private static CardSimulator simulator; 
    
    private static final String APPLET_AID = "12345678912345678900";

    private static final byte INS_DH_INIT = (byte) 0x50;
    private final static byte INS_CRYPTOGRAM = (byte) 0x51;
    private final static byte INS_DUMMY = (byte) 0x52;
    private final static byte CLA_SECURECHANNEL = (byte) 0xB0;
    
    private static final int IV_SIZE = 16;
    private static final short PIN_LENGTH = 4;
    
    final static byte[] pin = {'1', '2', '3', '4'};

    private static SecretKeySpec sessionKeySpec;
    private static Cipher sessionEncrypt;
    private static Cipher sessionDecrypt;
    private static byte[] sharedSecret;
    private static IvParameterSpec ivParameterSpec;

    private byte[] publicKeyToRaw(ECPublicKey pubKey) {
        ECPoint publicKeyPoint = pubKey.getW();
        byte[] publicKeyXWhole = publicKeyPoint.getAffineX().toByteArray();
        byte[] publicKeyYWhole = publicKeyPoint.getAffineY().toByteArray();

        byte[] publicKeyX = new byte[Config.singleCoordLength];
        byte[] publicKeyY = new byte[Config.singleCoordLength];

        System.arraycopy(publicKeyXWhole, publicKeyXWhole.length - Config.singleCoordLength, publicKeyX, 0, Config.singleCoordLength);
        System.arraycopy(publicKeyYWhole, publicKeyYWhole.length - Config.singleCoordLength, publicKeyY, 0, Config.singleCoordLength);

        if (publicKeyX.length != Config.singleCoordLength || publicKeyY.length != Config.singleCoordLength) {
            throw new IllegalArgumentException("Different key length than configured.");
        }

        byte[] publicKeyWRaw = new byte[1 + publicKeyX.length * 2 + 31];
        publicKeyWRaw[0] = 0x04; // uncompressed form
        System.arraycopy(publicKeyX, 0, publicKeyWRaw, 1, publicKeyX.length);
        System.arraycopy(publicKeyY, 0, publicKeyWRaw, 1 + publicKeyX.length, publicKeyY.length);

        return publicKeyWRaw;
    }

    private ECPublicKey publicKeyFromRaw(byte[] publicKeyWRaw) {
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

    private byte[] hashPin(byte[] pin) {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-1");
            byte[] hPin = sha.digest(pin);
            hPin = Arrays.copyOf(hPin, 16);
            return hPin;
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
    }

    private byte[] negotiateSecret(CardSimulator simulator, byte[] userPin) throws Exception {
        try {
            System.out.println("Generating ECDH keypair...");
            KeyPairGenerator ECKeyPairGen = KeyPairGenerator.getInstance("EC");
            ECKeyPairGen.initialize(CurveSpecs.EC_P256K_PARAMS);
            KeyPair ECKeyPair = ECKeyPairGen.generateKeyPair();

            System.out.println("Initializating key agreement...");
            KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
            keyAgreement.init(ECKeyPair.getPrivate());

            SecretKeySpec hPinAesKeySpec = new SecretKeySpec(hashPin(userPin), "AES");

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
            
            if (response.getSW() == 0x6900) {
                throw new Exception("Wrong pin");
            }
            
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

    private void initSessionKey() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
        //byte[] short_Key = Arrays.copyOf(sharedSecret, 16);
        sessionKeySpec = new SecretKeySpec(sharedSecret, 0, 16, "AES");
        
        //byte[] iv = new byte[IV_SIZE];
        byte[] iv = Arrays.copyOf(sharedSecret, 16);
        SecureRandom random = new SecureRandom();
        //random.nextBytes(iv);
        ivParameterSpec = new IvParameterSpec(iv);
        
        sessionEncrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
        sessionDecrypt = Cipher.getInstance("AES/CBC/NOPADDING");
        
        sessionEncrypt.init(Cipher.ENCRYPT_MODE, sessionKeySpec, ivParameterSpec);
        sessionDecrypt.init(Cipher.DECRYPT_MODE, sessionKeySpec, ivParameterSpec);
        
    }

    private void runECDH(byte[] userPin) throws Exception {
        if (userPin.length != PIN_LENGTH) {
            throw new Exception("Wrong entered pin length!");
        }
        
        try{
            sharedSecret = negotiateSecret(simulator, userPin);
        } catch (Exception e) {
            System.out.println(e);
        }
        printBytes(sharedSecret);
        initSessionKey();
    }
    
    private void Run() {
        simulator = new CardSimulator();
        AID appletAID = AIDUtil.create(APPLET_AID);

        simulator.installApplet(appletAID, SecureChannelApplet.class, pin, (short) 4, (byte) pin.length);
        simulator.selectApplet(appletAID);
    }

    private void sendCryptogram(Cryptogram cryptogram) throws Exception {
        byte[] encryptedCryptogram = Encrypt(cryptogram.getBytes());
        CommandAPDU commandAPDU = new CommandAPDU(CLA_SECURECHANNEL, INS_CRYPTOGRAM, 0x00, 0x00, encryptedCryptogram);

        ResponseAPDU response = simulator.transmitCommand(commandAPDU);

        System.out.println("Cryptogram response" + response);
        printBytes(response.getData());
        System.out.println("Data length: " + response.getData().length);

        Cryptogram responseCryptogram = new Cryptogram(Decrypt(response.getData()));

        printBytes(responseCryptogram.payload);
    }

    /**
     * Main entry point.
     *
     * @param args
     */
    public static void main(String[] args) throws Exception {
        HostApp hostApp = new HostApp();
        byte[] userPin = new byte[]{'1', '2', '3', '4'};
        
        hostApp.Run();
        
        try {
            hostApp.runECDH(userPin);
        } catch (Exception e) {
            System.err.println(e);
        }
        
        for(int i = 0; i < 10; i++) {
            Cryptogram cryptogram = new Cryptogram(INS_DUMMY, (byte) 0, new byte[]{3, 1, 4});
            hostApp.sendCryptogram(cryptogram);
        }
        
    }

    private byte[] Encrypt(byte[] data) 
            throws ShortBufferException, IllegalBlockSizeException, 
            BadPaddingException {
        
        return sessionEncrypt.doFinal(data);
    }

    private byte[] Decrypt(byte[] data) 
            throws ShortBufferException, IllegalBlockSizeException, 
            BadPaddingException {
        return sessionDecrypt.doFinal(data);
    }
    
    public static void printBytes(byte[] data) {
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
