package src.main.java.applet;

import javacard.framework.*;
import javacard.security.RandomData;

public class SecureChannelApplet extends Applet implements MultiSelectable
{
    private static final short BUFFER_SIZE = 32;

    //CLA
    private static final byte CLA = (byte)0xB0;

    //INS
    private static final byte INS_SELECT = (byte)0xA4;
    private static final byte INS_GENERATE_KEYPAIR = (byte)0xDB;
    
    private static final byte INS_DH_INIT = (byte) 0xDC;
    private static final byte INS_GET = (byte) 0xDD;
    private static final byte INS_SET = (byte) 0xDE;
    private static final byte INS_DH_FINALIZE = (byte) 0xDF;
    
    private static final byte INS_VERIFY = (byte)0x20;
    
    private static final byte P1_Y = (byte) 0x10;
    private static final byte P1_P = (byte) 0x11;
    private static final byte P1_G = (byte) 0x12;
    
    //Security
    private static final byte PIN_RETRIES = (byte) 0x03;
    private static final byte PIN_MAX_LENGTH = (byte) 0x04;

    final static short SW_PINVERIFY_FAILED = (short)0x6900;

    private byte[] tmpBuffer = JCSystem.makeTransientByteArray(BUFFER_SIZE, JCSystem.CLEAR_ON_DESELECT);
    private RandomData random;

    private DH dh;
    private OwnerPIN cardPIN;

    public static void install(byte[] bArray, short bOffset, byte bLength) 
    {
        new SecureChannelApplet(bArray, bOffset, bLength);
    }

    public SecureChannelApplet(byte[] buffer, short offset, byte length)
    {
        cardPIN = new OwnerPIN(PIN_RETRIES, PIN_MAX_LENGTH);
        cardPIN.update(buffer, offset, length);
        //random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        register();
        
        dh = new DH();
        
    }

    public void process(APDU apdu)
    {
        byte[] apduBuffer = apdu.getBuffer();
        byte cla = apduBuffer[ISO7816.OFFSET_CLA];
        byte ins = apduBuffer[ISO7816.OFFSET_INS];
        short lc = (short)apduBuffer[ISO7816.OFFSET_LC];
        short p1 = (short)apduBuffer[ISO7816.OFFSET_P1];
        short p2 = (short)apduBuffer[ISO7816.OFFSET_P2];


        // check SELECT APDU command
        if ((cla == 0) &&
           (ins == (byte)(0xA4)) ) {
            return;
        }

        // verify the reset of commands have the
        // correct CLA byte, which specifies the
        // command structure
        if (apduBuffer[ISO7816.OFFSET_CLA] != CLA)
           ISOException.throwIt
        (ISO7816.SW_CLA_NOT_SUPPORTED);

        switch(ins) {
            case INS_SELECT:
                select();
                break;
            case INS_DH_INIT:
                dh.init();
                break;
            case INS_GET:
                if(p1 == P1_Y) {
                    apdu.setOutgoing();
                    apdu.setOutgoingLength(DH.maxLength);
                    dh.getY(apduBuffer, (short) 0);
                    apdu.sendBytesLong(apduBuffer, (short) 0, DH.maxLength);
                } else {
                    ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
                }
                return;
            case INS_SET:
                if(p1 == P1_Y) {
                    dh.setY(apduBuffer, ISO7816.OFFSET_CDATA, DH.maxLength, (short) 0);
                } else {
                    ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
                }
                return;
            case INS_DH_FINALIZE:
                //dh.doFinal(null);
                break;
            case INS_VERIFY:
                verify(apdu);
                break;
            case INS_GENERATE_KEYPAIR:
                break;
            default:
                ISOException.throwIt
        (ISO7816.SW_INS_NOT_SUPPORTED);
        }

        //random.generateData(tmpBuffer, (short) 0, BUFFER_SIZE);

        Util.arrayCopyNonAtomic(tmpBuffer, (short)0, apduBuffer, (short)0, BUFFER_SIZE);
        apdu.setOutgoingAndSend((short)0, BUFFER_SIZE);
    }

	@Override
	public boolean select(boolean b) {
            if(cardPIN.getTriesRemaining() == 0) {
                return false;
            }
		return true;
	}

	@Override
	public void deselect(boolean b) {
            cardPIN.reset();
	}
        
        private void verify(APDU apdu) {
            byte[] buffer = apdu.getBuffer();
            
            byte bytesRead = (byte)apdu.setIncomingAndReceive();
            if (cardPIN.check(buffer, ISO7816.OFFSET_CDATA, bytesRead) == false) {
                ISOException.throwIt(SW_PINVERIFY_FAILED);
            }
        }
}
