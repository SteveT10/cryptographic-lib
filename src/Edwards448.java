import java.security.SecureRandom;
import java.util.Arrays;
import java.math.BigInteger;

public class Edwards448 {
    //private static int d = -39081;

    //p = 2^448 - 2^224 - 1
    private static BigInteger p = (((new BigInteger("2")).pow(448)).subtract((new BigInteger("2")).pow(224))).subtract(new BigInteger("1"));

    //Curve Equation Factor
    private static BigInteger d = new BigInteger("-39081");

    //Project specifies even number, only even when x lsb is 0.
    private static Edwards448Point G = new Edwards448Point(false, new BigInteger("-3").mod(p), d, p);

    //r = 2^446 - 13818066809895115352007386748515426880336692474882178609894547503885
    private static BigInteger r = ((new BigInteger("2")).pow(446)).subtract(new BigInteger("13818066809895115352007386748515426880336692474882178609894547503885"));

    //private BigInteger privateKey;
    private Edwards448Point publicKey;

    private Edwards448Point Z;
    private byte[] c;
    private byte[] t;

    private BigInteger z;
    private BigInteger h;
    
    public Edwards448() {

    }

    public void generateKeyPair(String pw) {
        BigInteger s = new BigInteger(Kmacxof256.KMACXOF256(pw, "", 448, "SK"));
        s = s.multiply(new BigInteger("4"));
        s = s.mod(r);
        Edwards448Point V = G.multiply(s, d, p);
        //return (s, V)
        //this.privateKey = s;
        this.publicKey = V;
        System.out.println("Key pairs cached!");
    }

    public void encrypt(String m /*,Public key V */) {
        if(this.publicKey != null) {
            SecureRandom rand = new SecureRandom();
            byte[] k_bytes = new byte[448]; //64 * 8 = 512
            rand.nextBytes(k_bytes);
            BigInteger k = new BigInteger(k_bytes);
            Edwards448Point W = publicKey.multiply(k, d, p);
            Z = G.multiply(k, d, p);
    
            byte[] keka = Kmacxof256.KMACXOF256(Kmacxof256.byteArrToStr(W.getX().toByteArray()), "", 2 * 448, "PK");
            byte[] ke = new byte[keka.length / 2];
            System.arraycopy(keka, 0, ke, 0, keka.length / 2);
            byte[] ka = new byte[keka.length / 2];
            System.arraycopy(keka, 0, ka, 0, keka.length / 2);
    
            byte[] m_bytes = Kmacxof256.strToByteArr(m);
            c = Kmacxof256.KMACXOF256(Kmacxof256.byteArrToStr(ke), "",  m_bytes.length, "PKE");
            for(int i = 0; i < c.length; i++) {
                c[i] = Kmacxof256.byteXor(c[i], m_bytes[i]);
            }
            t = Kmacxof256.KMACXOF256(Kmacxof256.byteArrToStr(ka), m, 448, "PKA");
    
            System.out.println("Elliptic Cryptogram cached!");
        } else {
            System.out.println("No cached key pair detected! Please generate a key pair first.");
        }
    }

    public String decrypt(String pw) {
        String ret = "Mismatching Tags, rejecting message... Please check your passphrase input";
        if(this.Z != null && this.c != null && this.t != null) {
            BigInteger s = new BigInteger(Kmacxof256.KMACXOF256(pw, "", 448, "SK"));
            s = s.multiply(new BigInteger("4"));
            s = s.mod(r);
            Edwards448Point W = Z.multiply(s, d, p);
    
            byte[] keka = Kmacxof256.KMACXOF256(Kmacxof256.byteArrToStr(W.getX().toByteArray()), "", 2 * 448, "PK");
            byte[] ke = new byte[keka.length / 2];
            System.arraycopy(keka, 0, ke, 0, keka.length / 2);
            byte[] ka = new byte[keka.length / 2];
            System.arraycopy(keka, 0, ka, 0, keka.length / 2);
    
            byte[] m = Kmacxof256.KMACXOF256(Kmacxof256.byteArrToStr(ke), "", c.length, "PKE");
            for(int i = 0; i < c.length; i++) {
                m[i] = Kmacxof256.byteXor(c[i], m[i]);
            }
    
            byte[] tslash = Kmacxof256.KMACXOF256(Kmacxof256.byteArrToStr(ka), Kmacxof256.byteArrToStr(m), 448, "PKA");
            if(Arrays.compare(tslash, t) == 0) {
                ret = Kmacxof256.byteArrToStr(m);
            }
        } else {
            ret = "No cached elliptic cryptogram detected! Please generate a cryptogram first.";
        }
        return ret;
    }

    public void generateSignature(String m, String pw) {
        BigInteger s = new BigInteger(Kmacxof256.KMACXOF256(pw, "", 448, "SK"));
        s = s.multiply(new BigInteger("4"));
        s = s.mod(r);
        BigInteger k = new BigInteger(Kmacxof256.KMACXOF256(Kmacxof256.byteArrToStr(s.toByteArray()), m, 448, "N"));
        k = k.multiply(new BigInteger("4"));
        k = k.mod(r);
        Edwards448Point U = G.multiply(k, d, p);
        h = new BigInteger(Kmacxof256.KMACXOF256(Kmacxof256.byteArrToStr(U.getX().toByteArray()), m, 448, "T"));
        z = k.subtract(h.multiply(s)).mod(r);

        System.out.println("Signature cached!");
    }

    public String verifySignature(String m) {
        String ret = "Mismatching, rejecting message...";
        if(this.z != null && this.h != null) {
            Edwards448Point U = (G.multiply(z, d, p)).add(publicKey.multiply(z, d, p), d, p);
            if(Arrays.compare(h.toByteArray(), Kmacxof256.KMACXOF256(Kmacxof256.byteArrToStr(U.getX().toByteArray()), m, 448, "T")) == 0) {
                ret = "Successful Verification of Signature!";
            }
        } else {
            ret = "No signature was detected on message. Please generate a signature for this message";
        }
        return ret;
    }

}
