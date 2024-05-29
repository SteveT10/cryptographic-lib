import java.io.UnsupportedEncodingException;

public class Util {

    /**
     * Performs exclusive or bit operation on the two input bytes.
     * Normal ^ operations will not work on byte types without casting.
     * 
     * @param x is the first input byte.
     * @param y is the second input byte.
     * @return is the XOR result of the two input bytes.
     */
    public static byte byteXor(byte x, byte y) {
        return (byte) (((int) x ^ (int) y) & 0xFF);
    }

    /**
     * Converts a string into a byte array using ISO-8859-1 charset.
     * 
     * @param S is the string to convert to bytes.
     * @return byte array representing S in ISO-8859-1 charset.
     */
    public static byte[] strToByteArr(String S) {
        byte[] ret;
        try {
            ret = S.getBytes("ISO-8859-1");
        } catch (UnsupportedEncodingException err) {
            System.out.println("Error with strToByteArr!");
            ret = new byte[1];
        }
        return ret;
    }

    /**
     * Converts a byte array into a string using ISO-8859-1 charset.
     * 
     * @param b bytes to convert to a string.
     * @return string representing b in ISO-8859-1 charset.
     */
    public static String byteArrToStr(byte[] b) {
        String ret;
        try {
            ret = new String(b, "ISO-8859-1");
        } catch (UnsupportedEncodingException err) {
            ret = "Error with byteArrToString!";
            System.out.println(ret);
        }
        return ret;
    }

    public static byte[] byteArrXor(byte[] arr1, byte[] arr2) {
        byte[] ret;
        if(arr1.length != arr2.length) {
            System.out.println("Exclusive ORing two byte arrays of different length!");
            ret = new byte[Math.min(arr1.length, arr2.length)];
        } else {
            ret = new byte[arr1.length];
        }

        for(int i = 0; i < ret.length; i++) {
            ret[i] = byteXor(arr1[i], arr2[i]);
        }

        return ret;
    }

}
