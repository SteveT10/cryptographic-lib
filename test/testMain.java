import java.math.BigInteger;

public class testMain {
    public static void main(String[] args) {
        
        //byte[][] gram = testEncrypt();
        //testDecrypt(gram);
        //testEncodeStr();
        //testRightEncode();
        //testBytePad();
        //testLeftEncode();
        //testKeccek();
        //testByteFuncs();
        //testBigIntConvert();


        //testScalarMultiply(BigInteger.ZERO);
        //testScalarMultiply(BigInteger.ONE);
        //testScalarMultiply(new BigInteger("2"));
        //testScalarMultiply(new BigInteger("4"));
        //testScalarMultiply(r);
        Ed448pt pt1 = new Ed448pt(BigInteger.ONE.negate(), BigInteger.ZERO);
        Ed448pt pt2 = pt1.getOpposite();
        testAdd(pt1, pt2);
    }

    public static void testAdd(Ed448pt pt1, Ed448pt pt2) {
        BigInteger p = (((new BigInteger("2")).pow(448)).subtract((new BigInteger("2")).pow(224))).subtract(new BigInteger("1"));

        //Curve Equation Factor
        BigInteger d = new BigInteger("-39081");
        System.out.println(pt1.add(pt2, d, p));
    } 

    public static void testScalarMultiply(BigInteger scalar) {
        BigInteger p = (((new BigInteger("2")).pow(448)).subtract((new BigInteger("2")).pow(224))).subtract(new BigInteger("1"));

        //Curve Equation Factor
        BigInteger d = new BigInteger("-39081");
        Ed448pt G = new Ed448pt(BigInteger.ZERO, BigInteger.ONE.negate());
        Ed448pt neutral = G.multiply(scalar, d, p);
        System.out.println(neutral);
    }

    public static void testBigIntConvert() {
        byte[] test = {(byte) 0x08};
        BigInteger test2 = new BigInteger(test);
        System.out.println(test2);
        byte[] test3 = (test2.multiply(new BigInteger("4"))).toByteArray();
        for(int i = 0; i < test3.length; i++) {
            System.out.print("Byte " + i + ": " + test3[i]);
        }
        System.out.println();
    }

    public static byte[][] testEncrypt(App app) {
        byte[][] ret = app.encrypt("Hello World! Testing 123 blah blah blah blah", "Password"); 
        for(int i = 0; i < 3; i++) {
            System.out.print("Variable " + i + ": ");
            for(int j = 0; j < ret[i].length; j++) {
                System.out.print(Integer.toHexString(ret[i][j] & 0xFF));
            }
            System.out.println();
        }
        return ret;
    }

    public static void testShake() {

    }

    public static String testDecrypt(byte[][] cryptogram, App app) {
        String ret = app.decrypt(cryptogram, "Password");
        System.out.println(ret);
        return ret;
    }

    public static void testEncodeStr() {
        String in = "70617373776f7264";;
        byte[] encoded;
        encoded = Kmac256.encodeString(in);
        for(int i = 0; i < encoded.length; i++) {
            System.out.println(Integer.toHexString(encoded[i]));
        }   //Due to different state type, I can't confirm this works, I just hope it does.
    }

    public static void testLeftEncode() {
        int X = 0x88;
        byte[] encoded = Kmac256.leftEncode(X);
        for(int i = 0; i < encoded.length; i++) {
            System.out.println(Integer.toHexString(encoded[i]));
        }    
        //Should be encoded[0] = 1, encoded[1] = 0x88;
    }

    public static void testRightEncode() { 
        int X = 0x0; //This is only value rightEncode will encountered.
        byte[] encoded = Kmac256.rightEncode(X);
        for(int i = 0; i < encoded.length; i++) {
            System.out.println(Integer.toHexString(encoded[i]));
        }    
        //Should be encoded[0] = 0x00, encoded[1] = 01;
    }

    public static void testBytePad() {
        byte[] bitStr = {0x04, 0x04};
        int w = 136;
        byte[] result = Kmac256.bytePad(bitStr, w);
        System.out.println(result.length); //Should be = w
        //View array in debug mode.
    }

    public static void testKeccek() {
        byte[] testState = { //20x00,* 8 = 1600
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        };

        byte[] dataState = {
            0x01 ,(byte) 0x88 ,0x01 ,0x20 ,0x4B ,0x4D ,0x41 ,0x43 ,0x01 ,(byte) 0xA8 ,0x4D ,0x79 ,0x20 ,0x54 ,0x61 ,0x67,
            (byte) 0x67 ,0x65 ,0x64 ,0x20 ,0x41 ,0x70 ,0x70 ,0x6C, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        };

        byte[] xorState = new byte[dataState.length];

        for(int i = 0; i < dataState.length; i++) {
            xorState[i] = Util.byteXor(testState[i], dataState[i]);
        }
        //long[] keccakState = Kmac256.byteArrToLongArr(xorState);
        byte[] afterKeccak = Kmac256.keccakf(xorState);
        for(int i = 0; i < 8; i++) {
            System.out.println(Integer.toHexString(afterKeccak[i]));
        }
    }

    public static void testByteFuncs() {
        byte[] dataState = {
            0x01 ,(byte) 0x88 ,0x01 ,0x20 ,0x4B ,0x4D ,0x41 ,0x43 ,0x01 ,(byte) 0xA8 ,0x4D ,0x79 ,0x20 ,0x54 ,0x61 ,0x67,
            (byte) 0x67 ,0x65 ,0x64 ,0x20 ,0x41 ,0x70 ,0x70 ,0x6C, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        };
        byte test1 = (byte) 0x55;
        byte test2 = (byte) 0xff;
        byte test4 = Util.byteXor(test1, test2);
        System.out.println(Integer.toHexString(test4));
        long[] test5 = Kmac256.byteArrToLongArr(dataState);
        System.out.println(Long.toHexString(test5[0]));
        byte[] test6 = Kmac256.longArrToByteArr(test5);
        for(int i = 0; i < 8; i++) {
            System.out.println(Integer.toHexString(test6[i]));
        }
    }
}