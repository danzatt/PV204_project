package host;

import applet.MainApplet;

public class HostApp {
    private static String APPLET_AID = "12345678912345678900";
    private static byte APPLET_AID_BYTE[] = Util.hexStringToByteArray(APPLET_AID);

    /**
     * Main entry point.
     *
     * @param args
     */
    public static void main(String[] args) {
        try {
            demoSingleCommand();
        } catch (Exception ex) {
            System.out.println("Exception : " + ex);
        }
    }

    public static ResponseAPDU demoSingleCommand() throws Exception {
    }
}
