package src.main.java.applet;

import javacard.framework.*;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.MessageDigest;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.RandomData;
import javacardx.crypto.Cipher;
import org.omg.CORBA.DATA_CONVERSION;

import java.util.Arrays;

public class SecureChannelApplet extends Applet implements MultiSelectable
{
    
    // Main instruction class
    
    final static byte CLA_SIMPLEAPPLET = (byte) 0xB0;
    
    // Instructions
    final static byte INS_INIT_ECDH = (byte) 0x50;
    // Error codes
    
    final static short SW_BAD_TEST_DATA_LEN = (short) 0x6680;
    final static short SW_KEY_LENGTH_BAD = (short) 0x6715;
    final static short SW_CIPHER_DATA_LENGTH_BAD = (short) 0x6710;
    final static short SW_OBJECT_NOT_AVAILABLE = (short) 0x6711;
    final static short SW_BAD_PIN = (short) 0x6900;

    final static short SW_Exception = (short) 0xff01;
    final static short SW_ArrayIndexOutOfBoundsException = (short) 0xff02;
    final static short SW_ArithmeticException = (short) 0xff03;
    final static short SW_ArrayStoreException = (short) 0xff04;
    final static short SW_NullPointerException = (short) 0xff05;
    final static short SW_NegativeArraySizeException = (short) 0xff06;
    final static short SW_CryptoException_prefix = (short) 0xf100;
    final static short SW_SystemException_prefix = (short) 0xf200;
    final static short SW_PINException_prefix = (short) 0xf300;
    final static short SW_TransactionException_prefix = (short) 0xf400;
    final static short SW_CardRuntimeException_prefix = (short) 0xf500;
    
    private static final short BUFFER_SIZE = 32;

    private byte[] tmpBuffer = JCSystem.makeTransientByteArray(BUFFER_SIZE, JCSystem.CLEAR_ON_DESELECT);
    byte[] baTemp;
    private RandomData random;
    private MessageDigest hash;

    KeyPair kpU;
    ECPrivateKey privKeyU;
    ECPublicKey pubKeyU;
    private byte[] sharedSecret;
        
    public static void install(byte[] bArray, short bOffset, byte bLength) 
    {
        new SecureChannelApplet(bArray, bOffset, bLength);
    }

    public SecureChannelApplet(byte[] buffer, short offset, byte length)
    {
        baTemp = JCSystem.makeTransientByteArray((short) 512, JCSystem.CLEAR_ON_DESELECT);
        sharedSecret = JCSystem.makeTransientByteArray(SecureChannelConfig.secretLen, JCSystem.CLEAR_ON_DESELECT);
        // Init hashing
        hash = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
        register();
    }

    @Override
    public void process(APDU apdu) throws ISOException {
        // get the buffer with incoming APDU
        byte[] apduBuffer = apdu.getBuffer();
        short receivedLen = apdu.setIncomingAndReceive();
        byte cla = apduBuffer[ISO7816.OFFSET_CLA];
        byte ins = apduBuffer[ISO7816.OFFSET_INS];
        short lc = (short)apduBuffer[ISO7816.OFFSET_LC];
        short p1 = (short)apduBuffer[ISO7816.OFFSET_P1];
        short p2 = (short)apduBuffer[ISO7816.OFFSET_P2];

        // ignore the applet select command dispached to the process
        if (selectingApplet()) {
            return;
        }

        try {
            // APDU instruction parser
            if (apduBuffer[ISO7816.OFFSET_CLA] == CLA_SIMPLEAPPLET) {
                switch (apduBuffer[ISO7816.OFFSET_INS]) {
                    case INS_INIT_ECDH:
                        initECDH(apdu, receivedLen);
                        break;
                    default:
                        // The INS code is not supported by the dispatcher
                        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                        break;
                }
            } else {
                ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
            }

            // Capture all reasonable exceptions and change into readable ones (instead of 0x6f00) 
        } catch (ISOException e) {
            throw e; // Our exception from code, just re-emit
        } catch (ArrayIndexOutOfBoundsException e) {
            ISOException.throwIt(SW_ArrayIndexOutOfBoundsException);
        } catch (ArithmeticException e) {
            ISOException.throwIt(SW_ArithmeticException);
        } catch (ArrayStoreException e) {
            ISOException.throwIt(SW_ArrayStoreException);
        } catch (NullPointerException e) {
            ISOException.throwIt(SW_NullPointerException);
        } catch (NegativeArraySizeException e) {
            ISOException.throwIt(SW_NegativeArraySizeException);
        } catch (CryptoException e) {
            ISOException.throwIt((short) (SW_CryptoException_prefix | e.getReason()));
        } catch (SystemException e) {
            ISOException.throwIt((short) (SW_SystemException_prefix | e.getReason()));
        } catch (PINException e) {
            ISOException.throwIt((short) (SW_PINException_prefix | e.getReason()));
        } catch (TransactionException e) {
            ISOException.throwIt((short) (SW_TransactionException_prefix | e.getReason()));
        } catch (CardRuntimeException e) {
            ISOException.throwIt((short) (SW_CardRuntimeException_prefix | e.getReason()));
        } catch (Exception e) {
            ISOException.throwIt(SW_Exception);
        }
    }
    
    @Override
    public boolean select(boolean b) {
        clearSessionData();
        return true;
    }

    @Override
    public void deselect(boolean b) {
        clearSessionData();
    }

    void clearSessionData() {
        //TODO: add data clening
    }

    void Encrypt(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();

        // CHECK EXPECTED LENGTH (MULTIPLY OF AES BLOCK LENGTH)
        if ((dataLen % 16) != 0) {
            ISOException.throwIt(SW_CIPHER_DATA_LENGTH_BAD);
        }

        // ENCRYPT INCOMING BUFFER
        // TODO: add buffer encryption
        // NOTE: In-place encryption directly with apdubuf as output can be performed. m_ramArray used to demonstrate Util.arrayCopyNonAtomic

        // COPY ENCRYPTED DATA INTO OUTGOING BUFFER
        //Util.arrayCopyNonAtomic(m_ramArray, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, dataLen);

        // SEND OUTGOING BUFFER
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, dataLen);
    }
    
    void Decrypt(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();

        // CHECK EXPECTED LENGTH (MULTIPLY OF AES BLOCK LENGTH)
        if ((dataLen % 16) != 0) {
            ISOException.throwIt(SW_CIPHER_DATA_LENGTH_BAD);
        }

        // ENCRYPT INCOMING BUFFER
        // TODO: add decryption

        // COPY ENCRYPTED DATA INTO OUTGOING BUFFER
        //Util.arrayCopyNonAtomic(m_ramArray, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, dataLen);

        // SEND OUTGOING BUFFER
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, dataLen);
    }
    
    void HashPIN(byte[] pin, byte[] hashedPin) {
        hash.doFinal(pin, (short) 0, (short) pin.length, hashedPin, (short) 0);
    }
    
    // HASH INCOMING BUFFER
    void Hash(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();

        // TODO: Implement hashing
        /*if (m_hash != null) {
            m_hash.doFinal(apdubuf, ISO7816.OFFSET_CDATA, dataLen, m_ramArray, (short) 0);
        } else {
            ISOException.throwIt(SW_OBJECT_NOT_AVAILABLE);
        }

        // COPY ENCRYPTED DATA INTO OUTGOING BUFFER
        Util.arrayCopyNonAtomic(m_ramArray, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, m_hash.getLength());

        // SEND OUTGOING BUFFER
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, m_hash.getLength());*/
    }

    private void initECDH(APDU apdu, short receivedLength) {
        if (receivedLength != (SecureChannelConfig.publicKeyBytes + 31))
        {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        kpU = SecP256k1.newKeyPair();
        kpU.genKeyPair();
        privKeyU = (ECPrivateKey) kpU.getPrivate();
        pubKeyU = (ECPublicKey) kpU.getPublic();

        byte[] hashedPinFull = new byte[20];
        HashPIN(new byte[]{'1', '2', '3', '4'}, hashedPinFull);

        byte[] hashedPin = new byte[16];
        Util.arrayCopyNonAtomic(hashedPinFull, (short) 0, hashedPin, (short) 0, (short) 16);

        byte[] cryptBuffer = new byte[receivedLength];

        KeyAgreement keyAgreement= KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH, false);
        keyAgreement.init(privKeyU);

        if (cryptPublicKey(hashedPin, apdu.getBuffer(), receivedLength, ISO7816.OFFSET_CDATA, cryptBuffer, (short) 0, Cipher.MODE_DECRYPT) != receivedLength) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        short secret_len = keyAgreement.generateSecret(cryptBuffer, (short) 0, SecureChannelConfig.publicKeyBytes, sharedSecret, (short) 0);
        short len = pubKeyU.getW(baTemp,(short) 0);
        short length = cryptPublicKey(hashedPin, baTemp, (short)cryptBuffer.length, (short) 0, cryptBuffer, (short) 0, Cipher.MODE_ENCRYPT);

        apdu.setOutgoing();
        apdu.setOutgoingLength((short) cryptBuffer.length);
        apdu.sendBytesLong(cryptBuffer,(short) 0, (short) cryptBuffer.length);
    }

    private short cryptPublicKey(byte[] key, byte[] dataToCrypt, short cryptLength, short decryptOffset, byte[] out, short offset, byte mode) {
        AESKey aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        Cipher aesCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);

        aesKey.setKey(key, (short) 0);
        aesCipher.init(aesKey, mode);

        return aesCipher.doFinal(dataToCrypt, (short) decryptOffset, cryptLength, out, offset);
    }
}
