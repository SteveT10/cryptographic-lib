import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

public class App {

    //p = 2^448 - 2^224 - 1
    private static BigInteger p = (((new BigInteger("2")).pow(448)).subtract((new BigInteger("2")).pow(224))).subtract(new BigInteger("1"));

    //Curve Equation Factor: d = -39081
    private static BigInteger d = new BigInteger("-39081");

    //Project specifies even number, only even when x lsb is 0.
    private static Ed448pt G = new Ed448pt(false, new BigInteger("-3").mod(p), d, p);

    //r = 2^446 - 13818066809895115352007386748515426880336692474882178609894547503885
    private static BigInteger r = ((new BigInteger("2")).pow(446)).subtract(new BigInteger("13818066809895115352007386748515426880336692474882178609894547503885"));

    private byte[][] privateKey;

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
    public byte[] computeHash(String message) {
        return Kmac256.kmac("", message, 512, "D");
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
    public byte[] computeAuthTag(String message, String pw) {
        return Kmac256.kmac(pw, message, 512, "T");
    }

    public Ed448pt generateKeyPair(String pw) {
        BigInteger s = new BigInteger(Kmac256.kmac(pw, "", 448, "SK"));
        s = s.multiply(new BigInteger("4"));
        s = s.mod(r);

        //return (s, V)
        this.privateKey = encrypt(s.toString(10), pw);
        return G.multiply(s, d, p);
    }

    public EccGram encrypt(String message, Ed448pt V) {
        EccGram ret;

        SecureRandom rand = new SecureRandom();
        byte[] k_bytes = new byte[448]; //64 * 8 = 512
        rand.nextBytes(k_bytes);

        BigInteger k = new BigInteger(k_bytes);
        Ed448pt W = V.multiply(k, d, p);

        byte[] keka = Kmac256.kmac(Util.byteArrToStr(W.getX().toByteArray()), "", 2 * 448, "PK");
        byte[][] split = splitKeka(keka);
        byte[] ke = split[0];
        byte[] ka = split[1];

        byte[] m = Util.strToByteArr(message);
        ret = new EccGram(
            G.multiply(k, d, p), //Z
            Util.byteArrXor(Kmac256.kmac(Util.byteArrToStr(ke), "",  m.length, "PKE"), m), //c
            Kmac256.kmac(Util.byteArrToStr(ka), message, 448, "PKA") //t
        );
        return ret;
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
    public byte[][] encrypt(String message, String pw) {
        //cryptogram = {z, c, t}
        byte[][] cryptogram = new byte[3][];

        SecureRandom rand = new SecureRandom();
        cryptogram[0] = new byte[64]; //64 * 8 = 512
        rand.nextBytes(cryptogram[0]);

        byte[] keka = Kmac256.kmac(Util.byteArrToStr(cryptogram[0]) + pw, "", 1024, "S");
        byte[][] split = splitKeka(keka);
        byte[] ke = split[0];
        byte[] ka = split[1];

        byte[] m = Util.strToByteArr(message);
        cryptogram[1] = Kmac256.kmac(Util.byteArrToStr(ke), "", m.length, "SKE");
        cryptogram[1] = Util.byteArrXor(cryptogram[1], m);

        cryptogram[2] = Kmac256.kmac(Util.byteArrToStr(ka), message, 512, "SKA");

        return cryptogram;
    }


    public String decrypt(String pw, EccGram gram) {
        String ret = "Mismatching Tags, rejecting message... Please check your passphrase input";
        BigInteger s = new BigInteger(Kmac256.kmac(pw, "", 448, "SK"));
        s = s.multiply(new BigInteger("4"));
        s = s.mod(r);
        Ed448pt W = gram.getZ().multiply(s, d, p);

        byte[] keka = Kmac256.kmac(Util.byteArrToStr(W.getX().toByteArray()), "", 2 * 448, "PK");
        byte[][] split = splitKeka(keka);
        byte[] ke = split[0];
        byte[] ka = split[1];

        byte[] m = Util.byteArrXor(Kmac256.kmac(Util.byteArrToStr(ke), "", gram.getC().length, "PKE"), gram.getC());
    
        byte[] tslash = Kmac256.kmac(Util.byteArrToStr(ka), Util.byteArrToStr(m), 448, "PKA");
        if(Arrays.compare(tslash, gram.getT()) == 0) {
            ret = Util.byteArrToStr(m);
        }

        return ret;
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
    public String decrypt(byte[][] cryptogram, String pw) {
        String ret = "Mismatching Tags, rejecting message... Please check your passphrase input";

        byte[] keka = Kmac256.kmac(Util.byteArrToStr(cryptogram[0]) + pw, "", 1024, "S");
        byte[][] split = splitKeka(keka);
        byte[] ke = split[0];
        byte[] ka = split[1];

        byte[] m = Util.byteArrXor(Kmac256.kmac(Util.byteArrToStr(ke), "", cryptogram[1].length, "SKE"), cryptogram[1]);
        byte[] t = Kmac256.kmac(Util.byteArrToStr(ka), Util.byteArrToStr(m), 512, "SKA");

        if(Arrays.compare(cryptogram[2], t) == 0) {
            ret = Util.byteArrToStr(m);
        }
        return ret;
    }

    public BigInteger[] generateSignature(String m, String pw) {
        BigInteger[] signature = new BigInteger[2];

        BigInteger s = new BigInteger(Kmac256.kmac(pw, "", 448, "SK"));
        s = s.multiply(new BigInteger("4"));
        s = s.mod(r);
        BigInteger k = new BigInteger(Kmac256.kmac(Util.byteArrToStr(s.toByteArray()), m, 448, "N"));
        k = k.multiply(new BigInteger("4"));
        k = k.mod(r);
        Ed448pt U = G.multiply(k, d, p);
        signature[0] = new BigInteger(Kmac256.kmac(Util.byteArrToStr(U.getX().toByteArray()), m, 448, "T"));
        signature[1] = k.subtract(signature[0].multiply(s)).mod(r);

        return signature;
    }

    public String verifySignature(String m, BigInteger[] signature, Ed448pt publicKey) {
        String ret = "Mismatching, rejecting message...";
        Ed448pt U = (G.multiply(signature[0], d, p)).add(publicKey.multiply(signature[0], d, p), d, p);
        if(Arrays.compare(signature[1].toByteArray(), Kmac256.kmac(Util.byteArrToStr(U.getX().toByteArray()), m, 448, "T")) == 0) {
            ret = "Successful Verification of Signature!";
        }
        return ret;
    }

    private byte[][] splitKeka(byte[] keka) {
        byte[][] ret = new byte[2][keka.length / 2];
        System.arraycopy(keka, 0, ret[0], 0, keka.length / 2);
        System.arraycopy(keka, 0, ret[1], 0, keka.length / 2);
        return ret;
    }

    public String getEncryptedPrivateKey() {
        StringBuilder sb = new StringBuilder();
        for(int i = 0; i < privateKey.length; i++) {
            sb.append(Util.byteArrToStr(privateKey[0]) + "\n");
        }
        return sb.toString();
    }
}
