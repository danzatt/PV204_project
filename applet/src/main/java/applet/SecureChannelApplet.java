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
    private static final byte INS_VERIFY = (byte)0x20;

    //Security
    private static final byte PIN_RETRIES = (byte) 0x03;
    private static final byte PIN_MAX_LENGTH = (byte) 0x04;

    final static short SW_PINVERIFY_FAILED = (short)0x6900;

    private byte[] tmpBuffer = JCSystem.makeTransientByteArray(BUFFER_SIZE, JCSystem.CLEAR_ON_DESELECT);
    private RandomData random;

    OwnerPIN cardPIN;

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
