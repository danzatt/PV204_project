package host;

import applet.SecureChannelApplet;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.*;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.X509EncodedKeySpec;

public class HostApp {
    private static String APPLET_AID = "12345678912345678900";
    /**
     * Main entry point.
     *
     * @param args
     */
//    public static void main(String[] args) {
//        CardSimulator simulator = new CardSimulator();
//
//        AID appletAID = AIDUtil.create(APPLET_AID);
//        simulator.installApplet(appletAID, SecureChannelApplet.class);
//
//        simulator.selectApplet(appletAID);
//
//        CommandAPDU commandAPDU = new CommandAPDU(0x00, 0x01, 0x00, 0x00);
//        ResponseAPDU response = simulator.transmitCommand(commandAPDU);
//
//        //assertEquals(0x9000, response.getSW());
//    }


    public static void main(String[] args) throws Exception {
        /*
         * Alice creates her own DH key pair with 2048-bit key size
         */
        System.out.println("ALICE: Generate DH keypair ...");
        KeyPairGenerator aliceKpairGen = KeyPairGenerator.getInstance("EC");
        // TODO: determine EC key length
        aliceKpairGen.initialize(256);
        KeyPair aliceKpair = aliceKpairGen.generateKeyPair();

        // Alice creates and initializes her ECDH KeyAgreement object
        System.out.println("ALICE: Initialization ...");
        KeyAgreement aliceKeyAgree = KeyAgreement.getInstance("ECDH");
        aliceKeyAgree.init(aliceKpair.getPrivate());

        // Alice encodes her public key, and sends it over to Bob.
        byte[] alicePubKeyEnc = aliceKpair.getPublic().getEncoded();

        /*
         * Let's turn over to Bob. Bob has received Alice's public key
         * in encoded format.
         * He instantiates a ECDH public key from the encoded key material.
         */
        KeyFactory bobKeyFac = KeyFactory.getInstance("EC");
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(alicePubKeyEnc);

        PublicKey alicePubKey = bobKeyFac.generatePublic(x509KeySpec);

        /*
         * Bob gets the ECDH parameters associated with Alice's public key.
         * He must use the same parameters when he generates his own key
         * pair.
         */
        ECParameterSpec ecParamFromAlicePubKey = ((ECPublicKey) alicePubKey).getParams();

        // Bob creates his own ECDH key pair
        System.out.println("BOB: Generate ECDH keypair ...");
        KeyPairGenerator bobKpairGen = KeyPairGenerator.getInstance("EC");
        bobKpairGen.initialize(ecParamFromAlicePubKey);
        KeyPair bobKpair = bobKpairGen.generateKeyPair();

        // Bob creates and initializes his ECDH KeyAgreement object
        System.out.println("BOB: Initialization ...");
        KeyAgreement bobKeyAgree = KeyAgreement.getInstance("ECDH");
        bobKeyAgree.init(bobKpair.getPrivate());

        // Bob encodes his public key, and sends it over to Alice.
        byte[] bobPubKeyEnc = bobKpair.getPublic().getEncoded();

        /*
         * Alice uses Bob's public key for the first (and only) phase
         * of her version of the ECDH
         * protocol.
         * Before she can do so, she has to instantiate a ECDH public key
         * from Bob's encoded key material.
         */
        KeyFactory aliceKeyFac = KeyFactory.getInstance("EC");
        x509KeySpec = new X509EncodedKeySpec(bobPubKeyEnc);
        PublicKey bobPubKey = aliceKeyFac.generatePublic(x509KeySpec);
        System.out.println("ALICE: Execute PHASE1 ...");
        aliceKeyAgree.doPhase(bobPubKey, true);

        /*
         * Bob uses Alice's public key for the first (and only) phase
         * of his version of the ECDH
         * protocol.
         */
        System.out.println("BOB: Execute PHASE1 ...");
        bobKeyAgree.doPhase(alicePubKey, true);

        /*
         * At this stage, both Alice and Bob have completed the ECDH key
         * agreement protocol.
         * Both generate the (same) shared secret.
         */
        byte[] aliceSharedSecret;
        byte[] bobSharedSecret;
        aliceSharedSecret = aliceKeyAgree.generateSecret();
        bobSharedSecret = new byte[aliceSharedSecret.length];
        int bobLen = bobKeyAgree.generateSecret(bobSharedSecret, 0);
        System.out.println("Alice secret: " +
                toHexString(aliceSharedSecret));
        System.out.println("Bob secret: " +
                toHexString(bobSharedSecret));
        if (!java.util.Arrays.equals(aliceSharedSecret, bobSharedSecret))
            throw new Exception("Shared secrets differ");
        System.out.println("Shared secrets are the same");

        /*
         * Now let's create a SecretKey object using the shared secret
         * and use it for encryption. First, we generate SecretKeys for the
         * "AES" algorithm (based on the raw shared secret data) and
         * Then we use AES in CBC mode, which requires an initialization
         * vector (IV) parameter. Note that you have to use the same IV
         * for encryption and decryption: If you use a different IV for
         * decryption than you used for encryption, decryption will fail.
         *
         * If you do not specify an IV when you initialize the Cipher
         * object for encryption, the underlying implementation will generate
         * a random one, which you have to retrieve using the
         * javax.crypto.Cipher.getParameters() method, which returns an
         * instance of java.security.AlgorithmParameters. You need to transfer
         * the contents of that object (e.g., in encoded format, obtained via
         * the AlgorithmParameters.getEncoded() method) to the party who will
         * do the decryption. When initializing the Cipher for decryption,
         * the (reinstantiated) AlgorithmParameters object must be explicitly
         * passed to the Cipher.init() method.
         */
        System.out.println("Use shared secret as SecretKey object ...");
        SecretKeySpec bobAesKey = new SecretKeySpec(bobSharedSecret, 0, 16, "AES");
        SecretKeySpec aliceAesKey = new SecretKeySpec(aliceSharedSecret, 0, 16, "AES");

        /*
         * Bob encrypts, using AES in CBC mode
         */
        Cipher bobCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        bobCipher.init(Cipher.ENCRYPT_MODE, bobAesKey);
        byte[] cleartext = "This is just an example".getBytes();
        byte[] ciphertext = bobCipher.doFinal(cleartext);

        // Retrieve the parameter that was used, and transfer it to Alice in
        // encoded format
        byte[] encodedParams = bobCipher.getParameters().getEncoded();

        /*
         * Alice decrypts, using AES in CBC mode
         */

        // Instantiate AlgorithmParameters object from parameter encoding
        // obtained from Bob
        AlgorithmParameters aesParams = AlgorithmParameters.getInstance("AES");
        aesParams.init(encodedParams);
        Cipher aliceCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aliceCipher.init(Cipher.DECRYPT_MODE, aliceAesKey, aesParams);
        byte[] recovered = aliceCipher.doFinal(ciphertext);
        if (!java.util.Arrays.equals(cleartext, recovered))
            throw new Exception("AES in CBC mode recovered text is " +
                    "different from cleartext");
        System.out.println("AES in CBC mode recovered text is same as cleartext");
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

    public static void DHTest() throws Exception {
            final CardManager cardManager = new CardManager(true, APPLET_AID_BYTE);
            final RunConfig runCfg = RunConfig.getDefaultConfig();
            final byte[] pin = {'1', '2', '3', '4'};
            runCfg.setInstallData(pin);
            runCfg.setAppletToSimulate(SecureChannelApplet.class);
            runCfg.setTestCardType(RunConfig.CARD_TYPE.JCARDSIMLOCAL);

            System.out.print("Connecting to card...");
            if (!cardManager.Connect(runCfg)) {
                System.out.println(" Failed.");
            }
            System.out.println(" Done.");

            final byte[] pin2 = {'1', '2', '3', '4'};
            final ResponseAPDU responcePin = cardManager.transmit(new CommandAPDU(0xB0, 0x20, 0x00, 0x00, pin2));

            //Start DH
            KeyPairGenerator hostKeyGen = KeyPairGenerator.getInstance("DH");
            KeyAgreement dhAlgorithm = KeyAgreement.getInstance("DH");
            DHParameterSpec dhKeySpecs = new DHParameterSpec(DH_GRP_14_P, DH_GRP_14_G);
            hostKeyGen.initialize(dhKeySpecs);
            //Private Key
            KeyPair hostKey = hostKeyGen.generateKeyPair();
            DHPublicKey hostPublicKey = (DHPublicKey) hostKey.getPublic();

            //Init card
            System.out.println("Init Smart Card DH Algo...");
            ResponseAPDU resp1 = cardManager.transmit(new CommandAPDU((byte) 0xB0, (byte) 0xDC, (byte) 0x00, (byte) 0x00, (byte) 0x00));

            System.out.println("Get card Y value...");
            ResponseAPDU yValResp = cardManager.transmit(new CommandAPDU((byte) 0xB0, (byte) 0xDD, (byte) 0x10, (byte) 0x00, (byte) 0x00));
            byte[] hexBytes = new byte[257];
            System.arraycopy(yValResp.getData(), 0, hexBytes, 1, yValResp.getData().length);

            BigInteger DH_Y = new BigInteger(hexBytes);
            DHPublicKey cardPublicKey = (DHPublicKey) KeyFactory.getInstance("DH").generatePublic(new DHPublicKeySpec(DH_Y, DH_GRP_14_P, DH_GRP_14_G));
            dhAlgorithm.init(hostKey.getPrivate());
            dhAlgorithm.doPhase(cardPublicKey, true);

            //Send host Y to the card
            hexBytes = new byte[256];
            int offset;
            if(hostPublicKey.getY().toByteArray().length > 256) {
                offset = 1;
            }
            else {
                offset = 0;
            }

            //System.arraycopy(setCardYApdu, 0, hexBytes, 0, setCardYApdu.length);
            System.arraycopy(hostPublicKey.getY().toByteArray(), offset, hexBytes, 0, 256);
            CommandAPDU setY = new CommandAPDU((byte) 0xB0, (byte) 0xDE, (byte) 0x10, (byte) 0x00, hexBytes);

            //Problem with sending 256 bytes of data
            ResponseAPDU resp3 = cardManager.transmit(setY);
            //Finish
            System.out.println("Finalize DH on card side...");
            //ResponseAPDU resp3 = cardManager.transmit(new CommandAPDU((byte) 0xB0, (byte) 0xDF, (byte) 0x00, (byte) 0x00, (byte) 0x00));
        }
    }
}
