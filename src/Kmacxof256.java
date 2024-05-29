import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;

public class Kmacxof256 {

    /**
     * Computes an hash function for a given message using
     * Kmacxof256. 
     * 
     * Follows the notation in the NIST Publication 800-185
     * except for parameter m which is converted to a
     * byte array in KMACX. 
     * 
     * @param message is the message to compute the hash for.
     * @return the hash as bytes.
     */
    public static byte[] computeHash(String message) {
        return KMACXOF256("", message, 512, "D");
    }

    /**
     * Computes an authentication tag for a given message using
     * Kmacxof256 and a pass phrase.
     * 
     * Follows the notation in the NIST Publication 800-185
     * except for parameter m which is converted to a
     * byte array in KMACX. 
     * 
     * @param message is the message to create a authentication tag for.
     * @param pw is the pass phrases used to create the authentication tag.
     * @return the authentication tag in bytes.
     */
    public static byte[] computeAuthTag(String message, String pw) {
        return KMACXOF256(pw, message, 512, "T");
    }

    /**
     * Symmetrically encrypts an given message usign a pass phrase and Kmacxof256.
     * 
     * Follows the notation in the NIST Publication 800-185
     * except for parameter m which is converted to a
     * byte array KMACX. 
     * 
     * @param message is the message to encrypt.
     * @param pw is the pass phrase to use during ecryption.
     * @return cryptogram(z, c, t). See decrypt() function for description of z, c, t.
     */
    public static byte[][] encrypt(String message, String pw) {
        byte[][] cryptogram = new byte[3][];
        SecureRandom rand = new SecureRandom();
        byte[] z = new byte[64]; //64 * 8 = 512
        rand.nextBytes(z);

        byte[] keka = KMACXOF256(byteArrToStr(z) + pw, "", 1024, "S");
        byte[] ke = new byte[keka.length / 2];
        System.arraycopy(keka, 0, ke, 0, keka.length / 2);
        byte[] ka = new byte[keka.length / 2];
        System.arraycopy(keka, 0, ka, 0, keka.length / 2);

        byte[] m = strToByteArr(message);
        byte[] c = KMACXOF256(byteArrToStr(ke), "", m.length, "SKE");
        for(int i = 0; i < Math.min(c.length, m.length); i++) {
            c[i] = byteXor(c[i], m[i]);
        }
        byte[] t = KMACXOF256(byteArrToStr(ka), message, 512, "SKA");
        cryptogram[0] = z;
        cryptogram[1] = c;
        cryptogram[2] = t;
        return cryptogram;
    }

    /**
     * Symmetrically decrypts a given cryptogram using the given pass phrase.
     * 
     * @param cryptogram is the symmetric cryptogram(z, c, t).
     *      z is the randomly selected number from 0 to (2^512) - 1 during encryption.
     *      c is the ciphertext.
     *      t is the authentication tag.
     * @param pw is the pass phrase used for decrypting the cryptogram.
     * @return the decrypted plaintext.
     */
    public static String decrypt(byte[][] cryptogram, String pw) {
        String ret = "Mismatching Tags, rejecting message... Please check your passphrase input";
        byte[] keka = KMACXOF256(byteArrToStr(cryptogram[0]) + pw, "", 1024, "S");
        byte[] ke = new byte[keka.length / 2];
        System.arraycopy(keka, 0, ke, 0, keka.length / 2);
        byte[] ka = new byte[keka.length / 2];
        System.arraycopy(keka, 0, ka, 0, keka.length / 2); 

        byte[] m = KMACXOF256(byteArrToStr(ke), "", cryptogram[1].length, "SKE");
        for(int i = 0; i < Math.min(m.length, cryptogram[1].length); i++) {
            m[i] = byteXor(m[i], cryptogram[1][i]);
        }
        byte[] t = KMACXOF256(byteArrToStr(ka), byteArrToStr(m), 512, "SKA");

        //String mStr = byteArrToStr(m);
        //System.out.println("\nMessage was " + mStr);
        if(Arrays.compare(cryptogram[2], t) == 0) {
            ret = byteArrToStr(m);
        }
        return ret;
    }

    /**
     * KMACXOF256 primitive according to NIST Special Publication 800-185, the only 
     * exception being that L is the byte width rather than bit width.
     * Additional support function used to convert between bytes and Strings in Java.
     * 
     * @param K is the key string of any length between zero and 2^2040. 
     * @param X is the main input string, the message.
     * @param L is the length of final output in bytes.
     * @param S is an optional customization string.
     * @return output of Kmacof256 as bytes.
     */
    public static byte[] KMACXOF256(String K, String X, int L, String S) {
        byte[] newX = concateByteArr(bytePad(encodeString(K), 136), strToByteArr(X));
        newX = concateByteArr(newX, rightEncode(0));
        return cShake256(newX, L, "KMAC", S);
    }

    /**
     * Performs cShake256 function. Inspired by Github user mjosaarinen's
     * Sha-3 implementation in C at 
     * https://github.com/mjosaarinen/tiny_sha3/tree/master
     * 
     * Due to the requirements of the project, this function only calls
     * Keccak() unlike the NIST specification in SP 800-185. Specifically, only 
     * "KECCAK[512](bytepad(encode_string(N) || encode_string(S), 136) || X || 00, L)" is
     * done here.
     * 
     * @param X is the main input string, the message.
     * @param L is the length of final output in bytes.
     * @param N is the NIST function-name input Only values defined by NIST should be used here.
     * @param S is an optional customization string.
     * @return the output of cShake function.
     */
    public static byte[] cShake256(byte[] X, int L, String N, String S) {
        int rsize = 136;
        int ptr = 0;
        byte[] output = new byte[L];
        
        //First absorb
        byte[] temp = bytePad(concateByteArr(encodeString(N), encodeString(S)), 136);
        byte[] state = new byte[200];
        System.arraycopy(temp, 0, state, 0, temp.length);
        Arrays.fill(state, temp.length - 1, state.length - 1, (byte) 0);
        state = keccakf(state);

        //Sponge ABSORB or sha3 update
        int j = ptr;
        for(int i = 0; i < X.length; i++) {
            j++;
            state[j] = byteXor(state[j], X[i]);
            if(j >= rsize) {
                state = keccakf(state);
                j = 0;
            }
        }
        ptr = j;

        //xof
        state[ptr] = byteXor(state[ptr], (byte) 0x1F);
        state[rsize - 1] = byteXor(state[rsize - 1], (byte) 0x04);
        state = keccakf(state);
        ptr = 0;
        
        //Out
        j = ptr;
        for(int i = 0; i < L; i++) {
            if(j >= rsize) {
                keccakf(state);
                j = 0;
            }
            output[i] = state[j];
            j++;
        }
        return output;
    }

    /**
     * Encode Strings into byte arrays that may be 
     * parsed unambiguously from the beginning of the string. 
     * 
     * @param S is the String to encode.
     * @return encoded byte array of S.
     */
    public static byte[] encodeString(String S) {
        byte[] sBytes = strToByteArr(S);        
        byte[] bitWidthNum = leftEncode(sBytes.length * 8); //byte = 8 bits
        //byte[] ret = new byte[sBytes.length + bitWidthNum.length];
        //System.arraycopy(bitWidthNum, 0, ret, 0, bitWidthNum.length);
        //System.arraycopy(sBytes, 0, ret, bitWidthNum.length, sBytes.length);
        return concateByteArr(bitWidthNum, sBytes);
    }

    /**
     * Encodes integer x as a byte array and inserts 
     * the length of the byte array in the first indices.
     * @param x is the integer to encode.
     * @return encoded x as a byte array, length inserted at start.
     */
    public static byte[] leftEncode(int x) {
        assert x > 0;
        int n = getByteSize(x);
        byte[] ret = new byte[n + 1];
        for(int i = n; i > 0; i--) { //Currently Big endian.
            ret[i] = (byte) (x % 256);
            x = x / 256; 
        }
        ret[0] = (byte) n;
        return ret;
    }
    
    /**
     * Encodes integer x as a byte array and inserts 
     * the length of the byte array in the last indices.
     * 
     * @param x is the integer to encode.
     * @return encoded x as a byte array, length inserted at end.
     */
    public static byte[] rightEncode(int x) {
        assert x > 0;
        int n = getByteSize(x);
        byte[] ret = new byte[n + 1];
        for(int i = n - 1; i >= 0; i--) { //Currently Big endian.
            ret[i] = (byte) (x % 256);
            x = x / 256; 
        }
        ret[n] = (byte) n;
        return ret;
    }

    /**
     * Detects how many bytes are needed to represent integer x.
     * 
     * @param x is the integer to represent.
     * @return how many bytes needed to represent x.
     */
    private static int getByteSize(int x) {
        int n = 1;
        //Find Minimumm amount of bytes needed for representation.
        while(Math.pow(2, 8 * n) <= x) { 
            n++;
        }
        return n;
    }

    /**
     * Prepends an encoding of integer w to an input byte array X then
     * pads the result with zeros until its length in bytes is a multiple of w.
     * Used on encoded strings.
     * 
     * This implementation is provided by Professor Paulo Barreto, who
     * is teaching the course for this project.
     * 
     * @param X is the encoded string, encoded from encodeString().
     * @param w is the output length multiple.
     * @return padded version of byte array X.
     */
    public static byte[] bytePad(byte[] X, int w) {
        assert w > 0;
        byte[] wenc = leftEncode(w); 

        byte[] z = new byte[w * ((wenc.length + X.length + w - 1) / w)]; //W *  and / W gets smallest multiple of w.
        System.arraycopy(wenc, 0, z, 0, wenc.length); //Z = W.
        System.arraycopy(X, 0, z, wenc.length, X.length); //Z = Z || X
        for(int i = wenc.length + X.length; i < z.length; i++) {
            z[i] = (byte) 0;
        }
        return z;
    }

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
     * Converts an array of bytes (8-bit) to an equivalent array of longs (64-bit).
     * Used at beginnning of keccakf() function.
     * 
     * @param input is the byte array to convert to a long array.
     * @return long array equivalent of input.
     */
    public static long[] byteArrToLongArr(byte[] input) {
        ByteBuffer buf = ByteBuffer.allocate(input.length);
        buf.put(input);
        long[] ret = new long[input.length / 8];
        for(int i = 0; i < ret.length; i++) {
            ret[i] = buf.getLong(i * 8);
        }
        return ret;
    }  

    /**
     * Converts an array of longs (64-bit) to an equivalent array of bytes (8-bit).
     * Used at ending of keccakf() function.
     * 
     * @param input is the byte array to convert to a long array.
     * @return long array equivalent of input.
     */
    public static byte[] longArrToByteArr(long[] input) {
        ByteBuffer buf = ByteBuffer.allocate(64 * input.length); //8 bytes = long
        for(int i = 0; i < input.length; i++) {
            buf.putLong(i * 8, input[i]);
        }
        return buf.array();
    }

    /**
     * Performs keccakf permutation, directly translated from Github user mjosaarinen's
     * Sha-3 implementation in C at https://github.com/mjosaarinen/tiny_sha3/tree/master.
     * 
     * @param state is the sponge state.
     * @return state after permutation.
     */
    public static byte[] keccakf(byte[] state) {
        Kmacxof256.swapWordEndian(state);
        long[] st = Kmacxof256.byteArrToLongArr(state);
        final long[] keccakf_rndc = {
            0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL,
            0x8000000080008000L, 0x000000000000808bL, 0x0000000080000001L,
            0x8000000080008081L, 0x8000000000008009L, 0x000000000000008aL,
            0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
            0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L,
            0x8000000000008003L, 0x8000000000008002L, 0x8000000000000080L,
            0x000000000000800aL, 0x800000008000000aL, 0x8000000080008081L,
            0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
        };

        final int[] keccakf_rotc = {
            1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
            27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44
        };

        final int[] keccakf_piln = {
            10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
            15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1
        };

        int i, j;
        long t;
        long[] bc = new long[5];

        for(int r = 0; r < 24; r++) {
            
            // Theta: Linearly combines bits from certain two distinct columns
            for(i = 0; i < 5; i++) {
                bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
            }
    
            for(i = 0; i < 5; i++) {
                t = bc[(i + 4) % 5] ^ rotateLeft(bc[(i + 1) % 5], 1);
                for (j = 0; j < 25; j += 5) {
                    st[j + i] ^= t;
                }
            }

            //Rho: Cyclically shifts bits within individual lanes 
            //Pi: Permutes bits within slices.
            t = st[1];
            for (i = 0; i < 24; i++) {
                j = keccakf_piln[i];
                bc[0] = st[j];
                st[j] = rotateLeft(t, keccakf_rotc[i]);
                t = bc[0];
            }
            //Chi: Mixes highly nonlinearly the bits within each row.
            for (j = 0; j < 25; j += 5) {
                for (i = 0; i < 5; i++) {
                    bc[i] = st[j + i];
                }
                for (i = 0; i < 5; i++) {
                    st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
                }
            }
            //  Iota: Adds asymmetric, round-specific constants to (0, 0) lane.
            st[0] ^= keccakf_rndc[r]; 
        }

        byte[] ret = Kmacxof256.longArrToByteArr(st);
        Kmacxof256.swapWordEndian(ret);
        return ret;
    }

    /**
     * Performs rotate left bit operation.
     * 
     * @param num is the number to rotate left.
     * @param shiftAmount is how bits to rotate by.
     * @return num shifted left by {shiftAmount} bits.
     */
    private static long rotateLeft(long num, int shiftAmount) {
        long ret = num << shiftAmount;
        ret |= num >>> (64 - shiftAmount); //64 bits in long, 'unsigned shift' to prevent leading 1s.
        return ret;
    }

    /**
     * Swaps the 64-bit word or long endianness in the byte array state. 
     * Ensure that the state array can be exactly divided into 64-bit word chunks.
     * 
     * @param state is the state array to swap endianness in.
     */
    public static void swapWordEndian(byte[] state) {
        int bytesInWord = 8;
        byte temp = 0;
        for(int i = 0; i <  (state.length / 8); i++) {
            for(int j = 0; j < (bytesInWord / 2); j++) {
                temp = state[(i * 8) + j];
                state[(i * 8) + j] = state[((i + 1) * 8) - j - 1];
                state[((i + 1) * 8) - j - 1] = temp;
            }
        }
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

    /**
     * Concatenates two byte arrays together.
     * 
     * @param left is the left byte array.
     * @param right is the right byte array.
     * @return left byte array concatenated with the right array.
     */
    public static byte[] concateByteArr(byte[] left, byte[] right) {
        byte[] ret = new byte[left.length + right.length];
        System.arraycopy(left, 0, ret, 0, left.length);
        System.arraycopy(right, 0, ret, left.length, right.length);
        return ret;
    }
}

