/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package src.main.java.applet;

import javacard.framework.JCSystem;
import javacard.framework.TransactionException;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.RSAPrivateKey;
import javacardx.crypto.Cipher;
import javacardx.framework.util.ArrayLogic;
import javacardx.framework.util.UtilException;

/**
 *
 * @author Michael Klunko
 */
public class DH {
    
    private RSAPrivateKey dhKey;
    private Cipher dhCipher;
    
    //256 byte p for DH
    private byte[] p = {
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xC9, (byte) 0x0F,
        (byte) 0xDA, (byte) 0xA2, (byte) 0x21, (byte) 0x68, (byte) 0xC2,
        (byte) 0x34, (byte) 0xC4, (byte) 0xC6, (byte) 0x62, (byte) 0x8B,
        (byte) 0x80, (byte) 0xDC, (byte) 0x1C, (byte) 0xD1, (byte) 0x29,
        (byte) 0x02, (byte) 0x4E, (byte) 0x08, (byte) 0x8A, (byte) 0x67,
        (byte) 0xCC, (byte) 0x74, (byte) 0x02, (byte) 0x0B, (byte) 0xBE,
        (byte) 0xA6, (byte) 0x3B, (byte) 0x13, (byte) 0x9B, (byte) 0x22,
        (byte) 0x51, (byte) 0x4A, (byte) 0x08, (byte) 0x79, (byte) 0x8E,
        (byte) 0x34, (byte) 0x04, (byte) 0xDD, (byte) 0xEF, (byte) 0x95,
        (byte) 0x19, (byte) 0xB3, (byte) 0xCD, (byte) 0x3A, (byte) 0x43,
        (byte) 0x1B, (byte) 0x30, (byte) 0x2B, (byte) 0x0A, (byte) 0x6D,
        (byte) 0xF2, (byte) 0x5F, (byte) 0x14, (byte) 0x37, (byte) 0x4F,
        (byte) 0xE1, (byte) 0x35, (byte) 0x6D, (byte) 0x6D, (byte) 0x51,
        (byte) 0xC2, (byte) 0x45, (byte) 0xE4, (byte) 0x85, (byte) 0xB5,
        (byte) 0x76, (byte) 0x62, (byte) 0x5E, (byte) 0x7E, (byte) 0xC6,
        (byte) 0xF4, (byte) 0x4C, (byte) 0x42, (byte) 0xE9, (byte) 0xA6,
        (byte) 0x37, (byte) 0xED, (byte) 0x6B, (byte) 0x0B, (byte) 0xFF,
        (byte) 0x5C, (byte) 0xB6, (byte) 0xF4, (byte) 0x06, (byte) 0xB7,
        (byte) 0xED, (byte) 0xEE, (byte) 0x38, (byte) 0x6B, (byte) 0xFB,
        (byte) 0x5A, (byte) 0x89, (byte) 0x9F, (byte) 0xA5, (byte) 0xAE,
        (byte) 0x9F, (byte) 0x24, (byte) 0x11, (byte) 0x7C, (byte) 0x4B,
        (byte) 0x1F, (byte) 0xE6, (byte) 0x49, (byte) 0x28, (byte) 0x66,
        (byte) 0x51, (byte) 0xEC, (byte) 0xE4, (byte) 0x5B, (byte) 0x3D,
        (byte) 0xC2, (byte) 0x00, (byte) 0x7C, (byte) 0xB8, (byte) 0xA1,
        (byte) 0x63, (byte) 0xBF, (byte) 0x05, (byte) 0x98, (byte) 0xDA,
        (byte) 0x48, (byte) 0x36, (byte) 0x1C, (byte) 0x55, (byte) 0xD3,
        (byte) 0x9A, (byte) 0x69, (byte) 0x16, (byte) 0x3F, (byte) 0xA8,
        (byte) 0xFD, (byte) 0x24, (byte) 0xCF, (byte) 0x5F, (byte) 0x83,
        (byte) 0x65, (byte) 0x5D, (byte) 0x23, (byte) 0xDC, (byte) 0xA3,
        (byte) 0xAD, (byte) 0x96, (byte) 0x1C, (byte) 0x62, (byte) 0xF3,
        (byte) 0x56, (byte) 0x20, (byte) 0x85, (byte) 0x52, (byte) 0xBB,
        (byte) 0x9E, (byte) 0xD5, (byte) 0x29, (byte) 0x07, (byte) 0x70,
        (byte) 0x96, (byte) 0x96, (byte) 0x6D, (byte) 0x67, (byte) 0x0C,
        (byte) 0x35, (byte) 0x4E, (byte) 0x4A, (byte) 0xBC, (byte) 0x98,
        (byte) 0x04, (byte) 0xF1, (byte) 0x74, (byte) 0x6C, (byte) 0x08,
        (byte) 0xCA, (byte) 0x18, (byte) 0x21, (byte) 0x7C, (byte) 0x32,
        (byte) 0x90, (byte) 0x5E, (byte) 0x46, (byte) 0x2E, (byte) 0x36,
        (byte) 0xCE, (byte) 0x3B, (byte) 0xE3, (byte) 0x9E, (byte) 0x77,
        (byte) 0x2C, (byte) 0x18, (byte) 0x0E, (byte) 0x86, (byte) 0x03,
        (byte) 0x9B, (byte) 0x27, (byte) 0x83, (byte) 0xA2, (byte) 0xEC,
        (byte) 0x07, (byte) 0xA2, (byte) 0x8F, (byte) 0xB5, (byte) 0xC5,
        (byte) 0x5D, (byte) 0xF0, (byte) 0x6F, (byte) 0x4C, (byte) 0x52,
        (byte) 0xC9, (byte) 0xDE, (byte) 0x2B, (byte) 0xCB, (byte) 0xF6,
        (byte) 0x95, (byte) 0x58, (byte) 0x17, (byte) 0x18, (byte) 0x39,
        (byte) 0x95, (byte) 0x49, (byte) 0x7C, (byte) 0xEA, (byte) 0x95,
        (byte) 0x6A, (byte) 0xE5, (byte) 0x15, (byte) 0xD2, (byte) 0x26,
        (byte) 0x18, (byte) 0x98, (byte) 0xFA, (byte) 0x05, (byte) 0x10,
        (byte) 0x15, (byte) 0x72, (byte) 0x8E, (byte) 0x5A, (byte) 0x8A,
        (byte) 0xAC, (byte) 0xAA, (byte) 0x68, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF
    };
    
    public static final short maxLength = 256;
    private byte[] G; 
    private byte[] Y;
    private byte[] S;
    
    public DH() {
        
        //init values
        G = new byte[maxLength];
        Y = JCSystem.makeTransientByteArray(maxLength, JCSystem.CLEAR_ON_DESELECT);
        S = JCSystem.makeTransientByteArray(maxLength, JCSystem.CLEAR_ON_DESELECT);
        
        dhKey = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, KeyBuilder.LENGTH_RSA_2048, false);
        
        dhCipher = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
        
        G[(short) (maxLength - 1)] = (byte) 0x02;
    }
    
    public void init() {
        KeyPair dhKeyPair = new KeyPair(KeyPair.ALG_RSA, (short) dhKey.getSize());
        
        dhKeyPair.genKeyPair();
        dhKey = (RSAPrivateKey) dhKeyPair.getPrivate();
        
        dhKey.setModulus(p, (short) 0, (short) 256);
        
        dhCipher.init(dhKey, Cipher.MODE_DECRYPT);
        
        dhCipher.doFinal(G, (short) 0, (short) 256, Y, (short) 0);
    }
    
    public void getG(byte[] output, short offset) {
        ArrayLogic.arrayCopyRepackNonAtomic(G, (short) 0, maxLength, output, offset);
    }

    public void getP(byte[] output, short offset) {
        ArrayLogic.arrayCopyRepackNonAtomic(p, (short) 0, maxLength, output, offset);
    }

    public void getY(byte[] output, short offset) {
        //ArrayLogic.arrayCopyRepackNonAtomic(Y, (short) 0, maxLength, output, offset);
        Util.arrayCopyNonAtomic(Y, (short) 0, output, offset, maxLength);
    }
    
    public void setY(byte[] data, short offset, short length, short yOffset) throws ArrayIndexOutOfBoundsException, NullPointerException, TransactionException, UtilException {
        ArrayLogic.arrayCopyRepack(data, offset, length, Y, yOffset);
    }

    public void setP(byte[] data, short offset, short length, short pOffset) throws ArrayIndexOutOfBoundsException, NullPointerException, TransactionException, UtilException {
        ArrayLogic.arrayCopyRepack(data, offset, length, p, pOffset);
    }

    public void setG(byte[] data, short offset, short length, short gOffset) throws ArrayIndexOutOfBoundsException, NullPointerException, TransactionException, UtilException {
        ArrayLogic.arrayCopyRepack(data, offset, length, G, gOffset);
    }

    /**
     * Destroys DH private key.
     */
    public void clearKey() {
        dhKey.clearKey();
    }

    public void doFinal(AESKey encKey) {
        // Set private key into cipher
        dhCipher.init(dhKey, Cipher.MODE_DECRYPT);

        // Execute S = Y^a mod p via RSA's decrypt
        dhCipher.doFinal(Y, (short) 0, maxLength, S, (short) 0);

        // Set session Encryption key
        encKey.setKey(S, (short) 0);

        // Clear DH Private Key
        dhKey.clearKey();

        // Zeroize temporary S bytes.
        ArrayLogic.arrayFillGenericNonAtomic(S, (short) 0, (short) S.length, S, (short) 0);

        // Zeroize temporary Y bytes.
        ArrayLogic.arrayFillGenericNonAtomic(Y, (short) 0, (short) Y.length, Y, (short) 0);
    }
}
