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
import javacard.security.AESKey;
import javacard.security.RandomData;
import javacardx.crypto.Cipher;

import java.util.Arrays;

public class SecureChannelApplet extends Applet implements MultiSelectable
{
    
    // Main instruction class
    
    final static byte CLA_SIMPLEAPPLET = (byte) 0xB0;

    // Cryptogram offsets
    final static byte CRYPTOGRAM_MAGIC = 0x31;
    final static byte OFFSET_CRYPTOGRAM_MAGIC = ISO7816.OFFSET_CDATA;
    final static byte OFFSET_CRYPTOGRAM_LENGTH = ISO7816.OFFSET_CDATA + 1;
    final static byte OFFSET_CRYPTOGRAM_SEQNUM = ISO7816.OFFSET_CDATA + 2;
    final static byte OFFSET_CRYPTOGRAM_INS = ISO7816.OFFSET_CDATA + 3;
    final static byte OFFSET_CRYPTOGRAM_DATA = ISO7816.OFFSET_CDATA + 4;

    // Instructions
    final static byte INS_INIT_ECDH = (byte) 0x50;
    final static byte INS_CRYPTOGRAM = (byte) 0x51;
    final static byte INS_END_SESSION = (byte) 0xE0;

    final static byte INS_DUMMY = (byte) 0x52;
    
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
    
    // Session code
    final static short SW_SESSION_ENDED = (short) 0x8001;
    
    private static final short BUFFER_SIZE = 32;
    private static final short PIN_LENGTH = 4;
    
    private byte[] dummyPin = new byte[]{'0', '0', '0', '0'};
    private byte[] wrongPin = new byte[]{'1', '1', '1', '1'};
    private static final byte PIN_TRIES = (byte) 0x03;
    
    private byte[] mRamArray;
    private RandomData random;
    private MessageDigest hash;

    KeyPair kpU;
    ECPrivateKey privKeyU;
    ECPublicKey pubKeyU;
    private AESKey pinKey;
    private AESKey dataKey;
    private Cipher dataEncryptCipher;
    private Cipher dataDecryptCipher;
    private byte[] sharedSecret;
    private byte[] hashed_pin;
    
    private OwnerPIN pinCheck;
        
    public static void install(byte[] bArray, short bOffset, byte bLength) 
    {
        new SecureChannelApplet(bArray, bOffset, bLength);
    }

    public SecureChannelApplet(byte[] buffer, short offset, byte length)
    {   
        mRamArray = JCSystem.makeTransientByteArray((short) 512, JCSystem.CLEAR_ON_DESELECT);
  
        hash = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
        hash.doFinal(buffer, (short) 0, (short) 4, mRamArray, (short) 0);
        
        pinKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        pinKey.setKey(mRamArray, (short) 0);
        
        //Set dummy pin to count tries
        pinCheck = new OwnerPIN(PIN_TRIES, (byte) 4);
        pinCheck.update(dummyPin, (short) 0, (byte) dummyPin.length);
        
        dataKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        dataEncryptCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        dataDecryptCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        
        sharedSecret = JCSystem.makeTransientByteArray(SecureChannelConfig.secretLen, JCSystem.CLEAR_ON_RESET);

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
                    case INS_CRYPTOGRAM:
                        processCryptogram(apdu, receivedLen);
                        break;
                    case INS_END_SESSION:
                        endSession();
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

    private void endSession() {
        clearSessionData();
        ISOException.throwIt(SW_SESSION_ENDED);
    }
    
    void clearSessionData() {
        //TODO: add data clening
    }

    void Encrypt(APDU apdu, short dataLen) {
        byte[] apdubuf = apdu.getBuffer();
        

        // CHECK EXPECTED LENGTH (MULTIPLY OF AES BLOCK LENGTH)
        if ((dataLen % 16) != 0) {
            ISOException.throwIt(SW_CIPHER_DATA_LENGTH_BAD);
        }

        // ENCRYPT INCOMING BUFFER

        dataEncryptCipher.doFinal(apdubuf, ISO7816.OFFSET_CDATA, dataLen, mRamArray, (short) 0);
        // NOTE: In-place encryption directly with apdubuf as output can be performed. m_ramArray used to demonstrate Util.arrayCopyNonAtomic

        // COPY ENCRYPTED DATA INTO OUTGOING BUFFER
        Util.arrayCopyNonAtomic(mRamArray, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, dataLen);

        // SEND OUTGOING BUFFER
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, dataLen);
    }
    
    void Decrypt(APDU apdu, short dataLen) {
        byte[] apdubuf = apdu.getBuffer();

        // CHECK EXPECTED LENGTH (MULTIPLY OF AES BLOCK LENGTH)
        if ((dataLen % 16) != 0) {
            ISOException.throwIt(SW_CIPHER_DATA_LENGTH_BAD);
        }

        // ENCRYPT INCOMING BUFFER
        dataDecryptCipher.doFinal(apdubuf, ISO7816.OFFSET_CDATA, dataLen, mRamArray, (short) 0);

        // COPY ENCRYPTED DATA INTO OUTGOING BUFFER

        Util.arrayCopyNonAtomic(mRamArray, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, dataLen);
    }
    
    void HashPIN(byte[] pin, byte[] hashedPin) {
        hash.doFinal(pin, (short) 0, PIN_LENGTH, hashedPin, (short) 0);
    }
    
    // HASH INCOMING BUFFER
    void Hash(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();

        // TODO: Implement hashing
        /*if (m_hash != null) {
            m_hash.doFinal(apdubuf, ISO7816.OFFSET_CDATA, dataLen, mRamArrayArray, (short) 0);
        } else {
            ISOException.throwIt(SW_OBJECT_NOT_AVAILABLE);
        }

        // COPY ENCRYPTED DATA INTO OUTGOING BUFFER
        Util.arrayCopyNonAtomic(mRamArrayArray, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, m_hash.getLength());

        // SEND OUTGOING BUFFER
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, m_hash.getLength());*/
    }

    private void processCryptogram(APDU apdu, short receivedLength) {
        Decrypt(apdu, receivedLength);
        byte[] apduBuffer = apdu.getBuffer();
        if (apduBuffer[OFFSET_CRYPTOGRAM_MAGIC] != CRYPTOGRAM_MAGIC) {
            // TODO: failed PIN attempt
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        // TODO: check SEQNUM

        switch (apduBuffer[OFFSET_CRYPTOGRAM_INS]) {
            case INS_DUMMY:
                handleDummy(apduBuffer, OFFSET_CRYPTOGRAM_DATA, apduBuffer[OFFSET_CRYPTOGRAM_LENGTH]);
        }
    }

    private void handleDummy(byte[] data, short dataOffset, short dataLen) {
        short three = data[dataOffset];
//        short one = data[dataOffset + (short) 1];
//        short four = data[dataOffset + (short) 2];
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


        byte[] cryptBuffer = new byte[receivedLength];

        KeyAgreement keyAgreement= KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH, false);
        keyAgreement.init(privKeyU);

        if (cryptPublicKey(apdu.getBuffer(), receivedLength, ISO7816.OFFSET_CDATA, cryptBuffer, (short) 0, Cipher.MODE_DECRYPT) != receivedLength) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        short secret_len = keyAgreement.generateSecret(cryptBuffer, (short) 0, SecureChannelConfig.publicKeyBytes, sharedSecret, (short) 0);
        short len = pubKeyU.getW(mRamArray,(short) 0);
        short length = cryptPublicKey(mRamArray, (short)cryptBuffer.length, (short) 0, cryptBuffer, (short) 0, Cipher.MODE_ENCRYPT);

        apdu.setOutgoing();
        apdu.setOutgoingLength((short) cryptBuffer.length);
        apdu.sendBytesLong(cryptBuffer,(short) 0, (short) cryptBuffer.length);
        
        initSessionKey();
    }

    private short cryptPublicKey(byte[] dataToCrypt, short cryptLength, short decryptOffset, byte[] out, short offset, byte mode) {
        Cipher aesCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);

        aesCipher.init(pinKey, mode);

        return aesCipher.doFinal(dataToCrypt, (short) decryptOffset, cryptLength, out, offset);
    }
    
    private void initSessionKey() {
        
        byte[] shortened_key = new byte[16];
        Util.arrayCopyNonAtomic(sharedSecret, (short) 0, shortened_key, (short) 0, (short) 16);
        
        dataKey.setKey(shortened_key, (short) 0);
        
        dataEncryptCipher.init(dataKey, Cipher.MODE_ENCRYPT, shortened_key, (short) 0, (short) 16);
        dataDecryptCipher.init(dataKey, Cipher.MODE_DECRYPT, shortened_key, (short) 0, (short) 16);
    }
    
    
}
