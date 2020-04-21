package src.main.java.applet;

/**
 * @author Daniel Zatovic
 */

public class SecureChannelConfig {
    public final static short keySize = 256;
    public final static short publicKeyBytes = ((keySize/8) * 2) + 1;
}
