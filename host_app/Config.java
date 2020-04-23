package host_app;

/**
 * @author Daniel Zatovic
 */
public class Config {
    public final static int singleCoordLength = 32;
    public final static int wholeKeySize = 1 + (singleCoordLength * 2);
    public final static int paddedKeySize = wholeKeySize + 31;
}
