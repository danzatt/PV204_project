package host;

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
import javax.security.auth.DestroyFailedException;

/*
* Host application class
* @author Michael Klunko, Daniel Zatovic, Vojtech Snajdr
*/
public class HostApp {
    
    private CardSimulator simulator; 
    
    private static final String APPLET_AID = "12345678912345678900";
    
    private static final byte CLA_SECURECHANNEL = (byte) 0xB0;
    
    private static final byte INS_DH_INIT = (byte) 0x50;
    private static final byte INS_CRYPTOGRAM = (byte) 0x51;
    private static final byte INS_DUMMY = (byte) 0x52;
    private static final byte INS_END_SESSION = (byte) 0xE0;
    
    
    private static final int IV_SIZE = 16;
    private static final short PIN_LENGTH = 4;
    
    private byte[] userPin;
    // Pin to be installed
    final static byte[] pin = {'1', '2', '3', '4'}; 

    private SecretKeySpec sessionKeySpec;
    private Cipher sessionEncrypt;
    private Cipher sessionDecrypt;
    private byte[] sharedSecret;
    private IvParameterSpec ivParameterSpec;

    private byte currentSeqNum = 0;

    /*
    * @brief Increases message sequence number
    */
    private void increaseSeqNum() {
        if (currentSeqNum == 255)
            currentSeqNum = 0;
        else
            currentSeqNum++;
    }

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
        if (publicKeyWRaw[0] != 0x04) {
            throw new IllegalArgumentException("Only uncompressed form supported");
        }
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

    /*
    * @brief Hash PIN for PAKE
    */
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

    /*
    * @brief Transmit apdu with trace
    */
    private ResponseAPDU transmitAPDU(CommandAPDU commandAPDU) {
        System.out.print("--> ");
        printBytes(commandAPDU.getBytes());

        ResponseAPDU response = simulator.transmitCommand(commandAPDU);
        System.out.print("<-- ");
        printBytes(response.getBytes());
        System.out.println(response);

        return response;
    }

    /*
    * @brief ECDH + PAKE negotiation
    */
    private byte[] negotiateSecret(byte[] userPin) throws Exception {
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
            ResponseAPDU response = transmitAPDU(commandAPDU);

            if (response.getSW() == 0x6900) {
                throw new Exception("Wrong pin");
            } else if (response.getSW() == 0x6901) {
                throw new Exception("Card is locked.");
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

    /*
    * @brief Initialize session keys
    */
    private void initSessionKey() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
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

    private void runECDH() throws Exception {
        try{
            sharedSecret = negotiateSecret(userPin);
        } catch (Exception e) {
            System.out.println(e);
        }

//        only for debug
//        System.out.print("Shared secret is: ");
//        printBytes(sharedSecret);

        initSessionKey();
    }
    
    private void EndSession() throws DestroyFailedException {
        CommandAPDU commandAPDU = new CommandAPDU(CLA_SECURECHANNEL, INS_END_SESSION, 0x00, 0x00);
        ResponseAPDU responseAPDU = transmitAPDU(commandAPDU);
        if (responseAPDU.getSW() == 0x8001) {
            System.out.println("--- Session ended ---");
            currentSeqNum = 0;
            Arrays.fill(sharedSecret, (byte) 0);
            sessionEncrypt = null;
            sessionDecrypt = null;
        } 
    }
    
    /*
    * @brief Prepare simulator and install applet
    */
    private void Run() {
        simulator = new CardSimulator();
        AID appletAID = AIDUtil.create(APPLET_AID);

        simulator.installApplet(appletAID, SecureChannelApplet.class, pin, (short) 4, (byte) pin.length);
        simulator.selectApplet(appletAID);
    }

    /*
    * @brief Send encrypted message to the card
    */
    private Cryptogram sendCryptogram(Cryptogram cryptogram) throws Exception {
        checkAndEstablishSession();
        byte[] encryptedCryptogram = Encrypt(cryptogram.getBytes());
        CommandAPDU commandAPDU = new CommandAPDU(CLA_SECURECHANNEL, INS_CRYPTOGRAM, 0x00, 0x00, encryptedCryptogram);

        ResponseAPDU responseAPDU = transmitAPDU(commandAPDU);
        increaseSeqNum();

        Cryptogram response = new Cryptogram(Decrypt(responseAPDU.getData()));

        if (response.seqnum != currentSeqNum) {
            throw new IllegalAccessException("Wrong sequence number from card");
        }

        increaseSeqNum();

        return response;
    }

    /*
    * @brief Communication testing function
    */
    private void tryDummyINS() throws Exception {
        byte expected = 5;
        byte[] data = new byte[]{3, 1, 4};
        for(int i = 0; i < 270; i++) {
            System.out.println("Trying dummy INS attempt n. " + i);
            Cryptogram cryptogram = new Cryptogram(INS_DUMMY, (byte) currentSeqNum , data);
            Cryptogram response = sendCryptogram(cryptogram);
            if (response.payload[0] != expected) {
                throw new IllegalArgumentException("Dummy instruction failed. Expected " + expected + " got " + response.payload[0]);
            }

            byte tmp = data[0];
            data[0] = expected;
            expected = tmp;
        }
    }

    /*
    * @brief Enter your pin. Should be done before ECDH.
    */
    private void setUserPin(byte[] userPin) {
        if (userPin.length != PIN_LENGTH) {
            System.err.println("> Wrong pin length. Pin must have 4 digits");
            System.exit(0);
        }
        this.userPin = userPin;
    }
    
    /**
     * Main entry point.
     *
     * @param args
     */
    public static void main(String[] args) throws Exception {
        HostApp hostApp = new HostApp();
        hostApp.setUserPin(new byte[]{'1', '2', '3', '4'});
        
        hostApp.Run();
        
        try {
            hostApp.runECDH();
        } catch (Exception e) {
            System.err.println(e);
        }

        hostApp.tryDummyINS();
        hostApp.EndSession();
        hostApp.tryDummyINS();
    }

    /*
    * @brief Encrypt data with AES session key
    * @param data data to encrypt
    */
    private byte[] Encrypt(byte[] data) 
            throws ShortBufferException, IllegalBlockSizeException, 
            BadPaddingException {
        
        return sessionEncrypt.doFinal(data);
    }

    /*
    * @brief Decrypt data with AES session key. Data should be padded by 
    * 16-byte blocks.
    * @param data data to decrypt
    */
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

    /*
    * @brief Check if session is active. If not, then try to establish a new one.
    */
    private void checkAndEstablishSession() {
        if (sessionDecrypt == null || sessionEncrypt == null) {
            System.out.println("> Sesssion is not active");
            System.out.println("> Establishing new session");
            try {
                runECDH();
            } catch (Exception e) {
                System.err.println("> Session cannot be established. Exiting...");
                System.exit(0);
            }
        }
    }
}
