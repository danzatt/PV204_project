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

//    public static void main2(String[] args) {
//        try {
//            run_main(args);
//        } catch (Exception e) {
//            System.out.println(e.getMessage());
//            e.printStackTrace();
//            if (e.getCause() != null)
//                System.out.println("cause: " + e.getCause().getMessage());
//        }
//    }

//    public static void run_main(String[] args) throws Exception {
//        /*
//         * Alice creates her own DH key pair with 2048-bit key size
//         */
//        System.out.println("ALICE: Generate DH keypair ...");
//        KeyPairGenerator aliceKpairGen = KeyPairGenerator.getInstance("EC");
//
//        aliceKpairGen.initialize(CurveSpecs.EC_P256K_PARAMS);
//        KeyPair aliceKpair = aliceKpairGen.generateKeyPair();
//
//        // Alice creates and initializes her ECDH KeyAgreement object
//        System.out.println("ALICE: Initialization ...");
//        KeyAgreement aliceKeyAgree = KeyAgreement.getInstance("ECDH");
//        aliceKeyAgree.init(aliceKpair.getPrivate());
//
////        byte[] alicePubKeyRaw = ((ECPublicKey) aliceKpair.getPublic()).getW();
//
//        /*
//         * Let's turn over to Bob. Bob has received Alice's public key
//         * in encoded format.
//         * He instantiates a ECDH public key from the encoded key material.
//         */
//        KeyFactory bobKeyFac = KeyFactory.getInstance("EC");
//        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(alicePubKeyEnc);
//
//        PublicKey alicePubKey = bobKeyFac.generatePublic(x509KeySpec);
//
//        /*
//         * Bob gets the ECDH parameters associated with Alice's public key.
//         * He must use the same parameters when he generates his own key
//         * pair.
//         */
//        ECParameterSpec ecParamFromAlicePubKey = ((ECPublicKey) alicePubKey).getParams();
//
//        // Bob creates his own ECDH key pair
//        System.out.println("BOB: Generate ECDH keypair ...");
//        KeyPairGenerator bobKpairGen = KeyPairGenerator.getInstance("EC");
//        bobKpairGen.initialize(ecParamFromAlicePubKey);
//        KeyPair bobKpair = bobKpairGen.generateKeyPair();
//
//        // Bob creates and initializes his ECDH KeyAgreement object
//        System.out.println("BOB: Initialization ...");
//        KeyAgreement bobKeyAgree = KeyAgreement.getInstance("ECDH");
//        bobKeyAgree.init(bobKpair.getPrivate());
//
//        // Bob encodes his public key, and sends it over to Alice.
//        byte[] bobPubKeyEnc = bobKpair.getPublic().getEncoded();
//
//        /*
//         * Alice uses Bob's public key for the first (and only) phase
//         * of her version of the ECDH
//         * protocol.
//         * Before she can do so, she has to instantiate a ECDH public key
//         * from Bob's encoded key material.
//         */
//        KeyFactory aliceKeyFac = KeyFactory.getInstance("EC");
//        x509KeySpec = new X509EncodedKeySpec(bobPubKeyEnc);
//        PublicKey bobPubKey = aliceKeyFac.generatePublic(x509KeySpec);
//        System.out.println("ALICE: Execute PHASE1 ...");
//        aliceKeyAgree.doPhase(bobPubKey, true);
//
//        /*
//         * Bob uses Alice's public key for the first (and only) phase
//         * of his version of the ECDH
//         * protocol.
//         */
//        System.out.println("BOB: Execute PHASE1 ...");
//        bobKeyAgree.doPhase(alicePubKey, true);
//
//        /*
//         * At this stage, both Alice and Bob have completed the ECDH key
//         * agreement protocol.
//         * Both generate the (same) shared secret.
//         */
//        byte[] aliceSharedSecret;
//        byte[] bobSharedSecret;
//        aliceSharedSecret = aliceKeyAgree.generateSecret();
//        bobSharedSecret = new byte[aliceSharedSecret.length];
//        int bobLen = bobKeyAgree.generateSecret(bobSharedSecret, 0);
//        System.out.println("Alice secret: " +
//                toHexString(aliceSharedSecret));
//        System.out.println("Bob secret: " +
//                toHexString(bobSharedSecret));
//        if (!java.util.Arrays.equals(aliceSharedSecret, bobSharedSecret))
//            throw new Exception("Shared secrets differ");
//        System.out.println("Shared secrets are the same");
//
//        /*
//         * Now let's create a SecretKey object using the shared secret
//         * and use it for encryption. First, we generate SecretKeys for the
//         * "AES" algorithm (based on the raw shared secret data) and
//         * Then we use AES in CBC mode, which requires an initialization
//         * vector (IV) parameter. Note that you have to use the same IV
//         * for encryption and decryption: If you use a different IV for
//         * decryption than you used for encryption, decryption will fail.
//         *
//         * If you do not specify an IV when you initialize the Cipher
//         * object for encryption, the underlying implementation will generate
//         * a random one, which you have to retrieve using the
//         * javax.crypto.Cipher.getParameters() method, which returns an
//         * instance of java.security.AlgorithmParameters. You need to transfer
//         * the contents of that object (e.g., in encoded format, obtained via
//         * the AlgorithmParameters.getEncoded() method) to the party who will
//         * do the decryption. When initializing the Cipher for decryption,
//         * the (reinstantiated) AlgorithmParameters object must be explicitly
//         * passed to the Cipher.init() method.
//         */
//        System.out.println("Use shared secret as SecretKey object ...");
//        SecretKeySpec bobAesKey = new SecretKeySpec(bobSharedSecret, 0, 16, "AES");
//        SecretKeySpec aliceAesKey = new SecretKeySpec(aliceSharedSecret, 0, 16, "AES");
//
//        /*
//         * Bob encrypts, using AES in CBC mode
//         */
//        Cipher bobCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
//        bobCipher.init(Cipher.ENCRYPT_MODE, bobAesKey);
//        byte[] cleartext = "This is just an example".getBytes();
//        byte[] ciphertext = bobCipher.doFinal(cleartext);
//
//        // Retrieve the parameter that was used, and transfer it to Alice in
//        // encoded format
//        byte[] encodedParams = bobCipher.getParameters().getEncoded();
//
//        /*
//         * Alice decrypts, using AES in CBC mode
//         */
//
//        // Instantiate AlgorithmParameters object from parameter encoding
//        // obtained from Bob
//        AlgorithmParameters aesParams = AlgorithmParameters.getInstance("AES");
//        aesParams.init(encodedParams);
//        Cipher aliceCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
//        aliceCipher.init(Cipher.DECRYPT_MODE, aliceAesKey, aesParams);
//        byte[] recovered = aliceCipher.doFinal(ciphertext);
//        if (!java.util.Arrays.equals(cleartext, recovered))
//            throw new Exception("AES in CBC mode recovered text is " +
//                    "different from cleartext");
//        System.out.println("AES in CBC mode recovered text is same as cleartext");
//    }

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
